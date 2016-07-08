#include <pin.H>
#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <cstring>

extern "C" {
#include <xed-interface.h>
}

// BEGIN: class instruction_t
struct instruction_t
{
  ADDRINT address;
  ADDRINT next_address;
  USIZE opcode_size;
  UINT8* opcode_buffer;
  std::string memonic_string;

  std::map<REG, PIN_REGISTER> src_registers;
  std::map<REG, PIN_REGISTER> dst_registers;

  BOOL is_memory_read;
  BOOL is_memory_write;
  BOOL has_memory_read2;
  BOOL has_known_memory_size;

  BOOL has_fall_through;

  instruction_t(const INS& ins);
  virtual ~instruction_t();
};

instruction_t::instruction_t(const INS& ins)
{
  this->address = INS_Address(ins);
  this->next_address = INS_NextAddress(ins);

  this->opcode_size = INS_Size(ins);
  this->opcode_buffer = new UINT8[this->opcode_size];
  PIN_SafeCopy(this->opcode_buffer, reinterpret_cast<VOID*>(this->address), this->opcode_size);

  this->memonic_string = INS_Disassemble(ins);

  // accessed registers can be obtained statically
  PIN_REGISTER default_reg_value;
  UINT32 rreg_num = INS_MaxNumRRegs(ins);
  for (UINT32 reg_id = 0; reg_id < rreg_num; ++reg_id) {
    this->src_registers[INS_RegR(ins, reg_id)] = default_reg_value;
  }

  UINT32 wreg_num = INS_MaxNumWRegs(ins);
  for (UINT32 reg_id = 0; reg_id < wreg_num; ++reg_id) {
    this->dst_registers[INS_RegW(ins, reg_id)] = default_reg_value;
  }

  this->is_memory_read = INS_IsMemoryRead(ins);
  this->is_memory_write = INS_IsMemoryWrite(ins);
  this->has_memory_read2 = INS_HasMemoryRead2(ins);
  this->has_known_memory_size = INS_hasKnownMemorySize(ins);

  this->has_fall_through = INS_HasFallThrough(ins);
}

instruction_t::~instruction_t()
{
  delete[] opcode_buffer;
}
// END: class instruction_t

// START: class runtime_instruction_t
struct rt_instruction_t : public instruction_t
{
  std::map<ADDRINT, UINT8> load_mem_addresses;
  std::map<ADDRINT, UINT8> store_mem_addresses;
  THREADID thread_id;

  rt_instruction_t(const instruction_t& static_ins);
  std::size_t serialized_length();
  std::size_t serialize(UINT8* buffer);
};

rt_instruction_t::rt_instruction_t(const instruction_t &static_ins) :
  instruction_t(static_ins) {}

static std::size_t length_of_register_map(const std::map<REG, PIN_REGISTER>& reg_map)
{
  std::size_t length = 0;
  std::map<REG, PIN_REGISTER>::const_iterator reg_iter = reg_map.begin();
  for (; reg_iter != reg_map.end(); ++reg_iter) {
    REG reg = (*reg_iter).first;
    std::string reg_name = REG_StringShort(reg);
    length += sizeof(ADDRINT);      // for length of register's name
    length += reg_name.length();    // for register's name
    length += sizeof(PIN_REGISTER); // for PIN_REGISTER
  }

  return length;
}

static std::size_t length_of_memory_map(const std::map<ADDRINT, UINT8>& mem_map)
{
  std::size_t length = 0;
  std::map<ADDRINT, UINT8>::const_iterator mem_iter = mem_map.begin();
  for (; mem_iter != mem_map.end(); ++mem_iter) {
    length += sizeof(ADDRINT); // for address;
    length += sizeof(UINT8);   // for value
  }

  return length;
}

std::size_t rt_instruction_t::serialized_length()
{
  std::size_t group0_length =
    sizeof(ADDRINT) +              // for address
    sizeof(ADDRINT) +              // for next address
    sizeof(ADDRINT) +              // for opcode buffer length
    this->opcode_size +            // for opcode buffer
    sizeof(ADDRINT) +              // for memonic string length
    this->memonic_string.length(); // for memonic string

  std::size_t group1_length = length_of_register_map(this->src_registers) + // for read registers
                              length_of_register_map(this->dst_registers);  // for written registers

//  std::size_t group2_length = 5 * sizeof(bool); // not serialized

  std::size_t group2_length = length_of_memory_map(this->load_mem_addresses) +
                              length_of_memory_map(this->store_mem_addresses);

  std::size_t group3_length = sizeof(THREADID);

  return group0_length + group1_length + group2_length + group3_length;
}

static std::size_t serialize_register_map(UINT8* buffer, const std::map<REG, PIN_REGISTER>& reg_map)
{
  UINT8 *original_buffer_address = buffer;
  std::size_t serialized_length = 0;
  ADDRINT *p_reg_name_length;
  UINT8 *p_reg_name;
  PIN_REGISTER *p_reg_value;

  std::map<REG, PIN_REGISTER>::const_iterator reg_iter = reg_map.begin();
  for (; reg_iter != reg_map.end(); ++reg_iter) {
    REG reg = (*reg_iter).first;
    std::string reg_name = REG_StringShort(reg);
    PIN_REGISTER reg_value = (*reg_iter).second;

    p_reg_name_length = reinterpret_cast<ADDRINT*>(buffer);
    *p_reg_name_length = reg_name.length(); serialized_length += sizeof(ADDRINT);

    p_reg_name = reinterpret_cast<UINT8*>(p_reg_name_length + 1);
    std::memcpy(p_reg_name, reg_name.c_str(), reg_name.length()); serialized_length += reg_name.length();

    p_reg_value = reinterpret_cast<PIN_REGISTER*>(p_reg_name + reg_name.length());
    *p_reg_value = reg_value; serialized_length += sizeof(PIN_REGISTER);

    buffer = original_buffer_address + serialized_length;
  }

  return serialized_length;
}

static std::size_t serialize_memory_map(UINT8* buffer, const std::map<ADDRINT, UINT8>& mem_map)
{
  UINT8 *original_buffer_address = buffer;
  ADDRINT *p_mem_addr = 0;
  UINT8 *p_mem_value = 0;
  std::size_t serialized_length = 0;

  std::map<ADDRINT, UINT8>::const_iterator mem_iter = mem_map.begin();
  for (; mem_iter != mem_map.end(); ++mem_iter) {
    p_mem_addr = reinterpret_cast<ADDRINT*>(buffer);
    *p_mem_addr = (*mem_iter).first; serialized_length += sizeof(ADDRINT);

    p_mem_value = reinterpret_cast<UINT8*>(p_mem_addr + 1);
    *p_mem_value = (*mem_iter).second; serialized_length += sizeof(UINT8);

    buffer = original_buffer_address + serialized_length;
  }

  return serialized_length;
}

std::size_t rt_instruction_t::serialize(UINT8 *buffer)
{
  UINT8 *original_buffer_addr = buffer;
  std::size_t serialized_length = 0;

  // group 0
  buffer = original_buffer_addr + serialized_length;
  ADDRINT *p_address = reinterpret_cast<ADDRINT*>(buffer);
  *p_address = this->address;
  serialized_length += sizeof(ADDRINT);

  ADDRINT *p_next_address = p_address + 1;
  *p_next_address = this->next_address;
  serialized_length += sizeof(ADDRINT);

  ADDRINT *p_opcode_size = p_next_address + 1;
  *p_opcode_size = this->opcode_size;
  serialized_length += sizeof(ADDRINT);

  UINT8 *p_opcode = reinterpret_cast<UINT8*>(p_opcode_size + 1);
  std::memcpy(p_opcode, this->opcode_buffer, this->opcode_size);
  serialized_length += this->opcode_size;

  ADDRINT *p_mnemonic_size = reinterpret_cast<ADDRINT*>(p_opcode + this->opcode_size);
  *p_mnemonic_size = this->memonic_string.length();
  serialized_length += sizeof(ADDRINT);

  UINT8 *p_mnemonic = reinterpret_cast<UINT8*>(p_mnemonic_size + 1);
  std::memcpy(p_mnemonic, this->memonic_string.c_str(), this->memonic_string.length());
  serialized_length += this->memonic_string.length();

  // group 1
  buffer = original_buffer_addr + serialized_length;
  serialized_length += serialize_register_map(buffer, this->src_registers);
  buffer = original_buffer_addr + serialized_length;
  serialized_length += serialize_register_map(buffer, this->dst_registers);

  // group 2
  buffer = original_buffer_addr + serialized_length;
  serialized_length += serialize_memory_map(buffer, this->load_mem_addresses);
  buffer = original_buffer_addr + serialized_length;
  serialized_length += serialize_memory_map(buffer, this->store_mem_addresses);

  // group 3
  buffer = original_buffer_addr + serialized_length;
  THREADID *p_thread_id = reinterpret_cast<THREADID*>(buffer);
  *p_thread_id = this->thread_id;
  serialized_length += sizeof(THREADID);

  return serialized_length;
}
// END: class runtime_instruction_t

// BEGIN: static variables
static KNOB<string> output_file_knob      (KNOB_MODE_WRITEONCE, "pintool", "out", "output.trace", "output trace file");
static KNOB<UINT32> trace_max_length_knob (KNOB_MODE_WRITEONCE, "pintool", "length", "0", "limit length of trace (0 = no limit)");

static UINT32 max_trace_length = 0;
static UINT32 current_trace_length = 0;

static std::ofstream output_file;

static std::map<THREADID, rt_instruction_t*> current_instruction_at_thread;
static std::map<ADDRINT, instruction_t*> cached_instruction_at_address;

// END: static variables

/*
 * extract the name of the traced binary from the command line
 */
std::string get_binary_name(int argc, char* argv[])
{
  static_cast<void>(argc);

  unsigned int i = 0;
  while(std::string(argv[i]) != "--") { i++; };
  return std::string(argv[i + 1]);
}

// declare callback functions
static VOID initialize_cached_instruction_callback(ADDRINT ins_addr, const CONTEXT *p_context, THREADID thread_id);

static VOID save_read_registers_callback(const CONTEXT *p_context, THREADID thread_id);

static VOID save_written_registers_callback(const CONTEXT *p_context, THREADID thread_id);

static VOID save_loaded_memory_callback(ADDRINT load_addr, UINT32 load_size, THREADID thread_id);

static VOID save_stored_memory_callback(ADDRINT stored_addr, UINT32 stored_size, THREADID thread_id);

static VOID serialize_threaded_instruction_callback(THREADID thread_id);

// implement callback functions
static VOID initialize_cached_instruction_callback(ADDRINT ins_addr, const CONTEXT *p_context, THREADID thread_id)
{
  if (current_instruction_at_thread[thread_id] != 0) {
    // this instruction is not reset yet (because it has no "fall through") then
    // we need some extract information and serialize it
    save_written_registers_callback(p_context, thread_id);

    std::map<ADDRINT, UINT8>::iterator mem_iter = current_instruction_at_thread[thread_id]->store_mem_addresses.begin();
    for (; mem_iter != current_instruction_at_thread[thread_id]->store_mem_addresses.end(); ++mem_iter) {
      static UINT8 byte_value;
      PIN_SafeCopy(&byte_value, reinterpret_cast<VOID*>(mem_iter->first), sizeof(UINT8));
      mem_iter->second = byte_value;
    }

    serialize_threaded_instruction_callback(thread_id); // the instruction will be reset after serialized
  }

  current_instruction_at_thread[thread_id] = new rt_instruction_t(*cached_instruction_at_address[ins_addr]);
  current_instruction_at_thread[thread_id]->thread_id = thread_id;
  return;
}

static VOID save_read_registers_callback(const CONTEXT *p_context, THREADID thread_id)
{
  rt_instruction_t* runtime_ins = current_instruction_at_thread[thread_id];
  for (std::map<REG, PIN_REGISTER>::iterator reg_iter = runtime_ins->src_registers.begin();
       reg_iter != runtime_ins->src_registers.end(); ++reg_iter) {
    static PIN_REGISTER reg_value;
    PIN_GetContextRegval(p_context, (*reg_iter).first, reinterpret_cast<UINT8*>(&reg_value));
    runtime_ins->src_registers[(*reg_iter).first] = reg_value;
  }

  return;
}

static VOID save_written_registers_callback(const CONTEXT *p_context, THREADID thread_id)
{
  rt_instruction_t* runtime_ins = current_instruction_at_thread[thread_id];

  std::map<REG, PIN_REGISTER>::const_iterator reg_iter = runtime_ins->dst_registers.begin();
  for (; reg_iter != runtime_ins->dst_registers.end(); ++reg_iter) {
    static PIN_REGISTER reg_value;
    PIN_GetContextRegval(p_context, (*reg_iter).first, reinterpret_cast<UINT8*>(&reg_value));
    runtime_ins->dst_registers[(*reg_iter).first] = reg_value;
  }

  return;
}

static VOID save_loaded_memory_callback(ADDRINT load_addr, UINT32 load_size, THREADID thread_id)
{
  rt_instruction_t* runtime_ins = current_instruction_at_thread[thread_id];
  ADDRINT upper_addr = load_addr + load_size;
  for (ADDRINT mem_addr = load_addr; mem_addr < upper_addr; ++mem_addr) {
    static UINT8 byte_value;
    PIN_SafeCopy(&byte_value, reinterpret_cast<VOID*>(mem_addr), 1);
    runtime_ins->load_mem_addresses[mem_addr] = byte_value;
  }

  return;
}

static VOID save_stored_memory_callback(ADDRINT stored_addr, UINT32 stored_size, THREADID thread_id)
{
  rt_instruction_t *runtime_ins = current_instruction_at_thread[thread_id];
  ADDRINT upper_addr = stored_addr + stored_size;
  for (ADDRINT mem_addr = stored_addr; mem_addr < upper_addr; ++mem_addr) {
    static UINT8 byte_value;
    PIN_SafeCopy(&byte_value, reinterpret_cast<VOID*>(mem_addr), sizeof(UINT8));
    runtime_ins->store_mem_addresses[mem_addr] = byte_value;
  }

  return;
}

static VOID serialize_threaded_instruction_callback(THREADID thread_id)
{
  std::size_t serialized_length = current_instruction_at_thread[thread_id]->serialized_length();
  UINT8 *buffer = new UINT8[serialized_length];
  current_instruction_at_thread[thread_id]->serialize(buffer);
  output_file.write(reinterpret_cast<char*>(buffer), serialized_length);
  current_trace_length++;
  delete [] buffer;

  // reset serialized instruction
  current_instruction_at_thread[thread_id] = 0;

  return;
}

static VOID inject_callbacks(const INS& ins)
{
  // add instruction statically into a map, so we do not need to re-examine it
  ADDRINT ins_addr = INS_Address(ins);
  if (cached_instruction_at_address.find(ins_addr) == cached_instruction_at_address.end()) {
    cached_instruction_at_address[ins_addr] = new instruction_t(ins);
  }
  static instruction_t *instrumented_instruction = cached_instruction_at_address[ins_addr];

  // insert callback functions for this instruction
  INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(initialize_cached_instruction_callback),
                 IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);

  // these callbacks are inserted "before"
  if (!instrumented_instruction->src_registers.empty()) {
    INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(save_read_registers_callback),
                   IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
  }

  if (instrumented_instruction->is_memory_read) {
    INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(save_loaded_memory_callback),
                   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_THREAD_ID, IARG_END);
  }

  if (instrumented_instruction->has_memory_read2) {
    INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(save_loaded_memory_callback),
                   IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_THREAD_ID, IARG_END);
  }

  // if the instruction has fall through then we can insert an "after execution" callback
  if (instrumented_instruction->has_fall_through) {
    if (instrumented_instruction->dst_registers.empty()) {
        INS_InsertCall(ins, IPOINT_AFTER, reinterpret_cast<AFUNPTR>(save_written_registers_callback),
                       IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
    }

    if (instrumented_instruction->is_memory_write) {
      INS_InsertCall(ins, IPOINT_AFTER, reinterpret_cast<AFUNPTR>(save_stored_memory_callback),
                     IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_THREAD_ID, IARG_END);
    }

    // so we can save it into trace when all needed information has been captured
    INS_InsertCall(ins, IPOINT_AFTER, reinterpret_cast<AFUNPTR>(serialize_threaded_instruction_callback),
                   IARG_THREAD_ID, IARG_END);
  }
  else {
    // we cannot use IPOINT_AFTER for instructions having no "fall through", so use IPOINT_BEFORE just to
    // specify which data should be captured
    if (instrumented_instruction->is_memory_write) {
      INS_InsertCall(ins, IPOINT_AFTER, reinterpret_cast<AFUNPTR>(save_stored_memory_callback),
                     IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_THREAD_ID, IARG_END);
    }
  }

  return;
}

static VOID instrument_trace(TRACE trace, VOID *data)
{
  static_cast<VOID>(data);

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      inject_callbacks(ins);
    }
  }
  return;
}

static VOID finalize(INT32 code, VOID *data)
{
  static_cast<void>(code); static_cast<void>(data);

  // clean cached instructions
  std::map<ADDRINT, instruction_t*>::iterator addr_ins_iter = cached_instruction_at_address.begin();
  for (; addr_ins_iter != cached_instruction_at_address.end(); ++addr_ins_iter) {
    delete (*addr_ins_iter).second;
  }
  cached_instruction_at_address.clear();

  output_file.close();

  return;
}

int main(int argc, char *argv[])
{
  if (PIN_Init(argc, argv)) {
    std::cout << KNOB_BASE::StringKnobSummary() << std::endl;
    PIN_ExitProcess(0);
  }

  max_trace_length = trace_max_length_knob.Value();

  std::cout << "start tracing program: " << get_binary_name(argc, argv) << std::endl
            << "limit length: " << max_trace_length;
  if (max_trace_length == 0) std::cout << " (nolimit)";
  std::cout << std::endl
            << "output file: " << output_file_knob.Value() << std::endl;

  output_file.open(output_file_knob.Value().c_str(),
                   std::ofstream::trunc | std::ofstream::binary);
  if (!output_file) {
    std::cout << "cannot open output file, stop tracing." << std::endl;
    return 1;
  }
  // specify size of ADDRINT, BOOL and THREADID
  UINT8 basic_size = sizeof(ADDRINT);
  output_file.write(reinterpret_cast<char*>(&basic_size), sizeof(UINT8));
  basic_size = sizeof(BOOL);
  output_file.write(reinterpret_cast<char*>(&basic_size), sizeof(UINT8));
  basic_size = sizeof(THREADID);
  output_file.write(reinterpret_cast<char*>(basic_size), sizeof(UINT8));

  TRACE_AddInstrumentFunction(instrument_trace, 0);
  PIN_AddFiniFunction(finalize, 0);

  // start tracing
  PIN_StartProgram();

  // never reached
  return 0;
}
