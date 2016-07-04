#include <pin.H>
#include <string>
#include <iostream>
#include <map>
#include <vector>
#include "picojson.h"

extern "C" {
#include <xed-interface.h>
}

// BEGIN: class instruction_t
struct instruction_t
{
  ADDRINT address;
  ADDRINT next_addres;
  unsigned int opcode_size;
  unsigned char* opcode_buffer;
  std::string memonic_string;

  std::map<REG, PIN_REGISTER> src_registers;
  std::map<REG, PIN_REGISTER> dst_registers;

  bool is_memory_read;
  bool is_memory_write;
  bool has_memory_read2;
  bool has_known_memory_size;
  
  bool has_fall_through;

  instruction_t(const INS& ins);
  virtual ~instruction_t();
};

instruction_t::instruction_t(const INS& ins)
{
  this->address = INS_Address(ins);
  this->next_addres = INS_NextAddress(ins);

  this->opcode_size = INS_Size(ins);
  this->opcode_buffer = new unsigned char[this->opcode_size];
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
};

rt_instruction_t::rt_instruction_t(const instruction_t &static_ins) : instruction_t(static_ins) {}
// END: class runtime_instruction_t

// BEGIN: static variables
static KNOB<string> output_file_knob      (KNOB_MODE_WRITEONCE, "pintool", "out", "output.trace", "output trace file");
static KNOB<UINT32> trace_max_length_knob (KNOB_MODE_WRITEONCE, "pintool", "length", "0", "limit length of trace (0 = no limit)");

UINT32 max_trace_length = 0;
UINT32 current_trace_length = 0;

std::map<THREADID, rt_instruction_t*> current_instruction_at_thread;
std::map<ADDRINT, instruction_t*> cached_instruction_at_address;

// END: static variables

/*
 * extract the name of the traced binary from the command line
 */
std::string get_binary_name(int argc, char* argv[])
{
  unsigned int i = 0;
  while(std::string(argv[i]) != "--") { i++; };
  return std::string(argv[i + 1]);
}


static VOID initialize_cached_instruction(ADDRINT ins_addr, THREADID thread_id)
{
  if (current_instruction_at_thread[thread_id] != 0) {
    // save instruction
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
  for (std::map<REG, PIN_REGISTER>::iterator reg_iter = runtime_ins->dst_registers.begin();
       reg_iter != runtime_ins->dst_registers.end(); ++reg_iter) {
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
    PIN_SafeCopy(&byte_value, reinterpret_cast<VOID*>(mem_addr), 1);
    runtime_ins->store_mem_addresses[mem_addr] = byte_value;
  }

  return;
}


//static VOID serialize_instruction(rt_instruction_t *runtime_ins)
//{
//  return;
//}

static VOID serialize_threaded_instruction(THREADID thread_id)
{

  return;
}


static VOID inject_callbacks(const INS& ins)
{
  ADDRINT ins_addr = INS_Address(ins);
  if (cached_instruction_at_address.find(ins_addr) == cached_instruction_at_address.end()) {
    cached_instruction_at_address[ins_addr] = new instruction_t(ins);
  }
  static instruction_t *instrumented_instruction = cached_instruction_at_address[ins_addr];

  INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(initialize_cached_instruction),
                 IARG_INST_PTR, IARG_THREAD_ID, IARG_END);

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
    INS_InsertCall(ins, IPOINT_AFTER, reinterpret_cast<AFUNPTR>(serialize_threaded_instruction),
                   IARG_THREAD_ID, IARG_END);
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
  for (std::map<ADDRINT, instruction_t*>::iterator addr_ins_iter = cached_instruction_at_address.begin();
       addr_ins_iter != cached_instruction_at_address.end(); ++addr_ins_iter) {
    delete (*addr_ins_iter).second;
  }
  cached_instruction_at_address.clear();

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

  TRACE_AddInstrumentFunction(instrument_trace, 0);
  PIN_AddFiniFunction(finalize, 0);

  // start tracing
  PIN_StartProgram();

  // never reached
  return 0;
}
