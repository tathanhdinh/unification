#include <pin.H>
#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <cstring>
#include <ctime>
#include <cassert>
#include <climits>
//#include <memory>

#define CAPTURED_INS_MAX_SIZE 1000
#define MAX_OPCODE_SIZE 15

extern "C" {
#include <xed-interface.h>
}

// static bool instruction_is_disabled = false;

// BEGIN: class instruction_t
struct instruction_t
{
  ADDRINT address;
  ADDRINT next_address;
  USIZE opcode_size;
  UINT8* opcode_buffer;
  // std::string mnemonic_string;

  std::map<REG, PIN_REGISTER> src_registers;
  std::map<REG, PIN_REGISTER> dst_registers;

  BOOL is_fp;

  BOOL is_memory_read;
  BOOL is_memory_write;
  BOOL has_memory_read2;
//  BOOL has_known_memory_size;

  BOOL has_fall_through;

  bool operator==(const INS& ins);

  instruction_t(const INS& ins);
  instruction_t(const instruction_t& ins);
  virtual ~instruction_t();
};


bool instruction_t::operator==(const INS& ins) 
{
  unsigned int ins_size = INS_Size(ins);
  if (this->opcode_size != ins_size) return false;

  static UINT8 other_opcode_buffer[MAX_OPCODE_SIZE];
  PIN_SafeCopy(other_opcode_buffer, reinterpret_cast<VOID*>(INS_Address(ins)), ins_size);
  if (memcmp(this->opcode_buffer, other_opcode_buffer, ins_size) != 0) return false;

  return true;
}

instruction_t::instruction_t(const INS& ins)
{
  this->address = INS_Address(ins);
  this->next_address = INS_NextAddress(ins);

  this->opcode_size = INS_Size(ins);
  this->opcode_buffer = new UINT8[this->opcode_size];
  PIN_SafeCopy(this->opcode_buffer, reinterpret_cast<VOID*>(this->address), this->opcode_size);

  // this->mnemonic_string = INS_Disassemble(ins);

//  std::cout << "create: " << StringFromAddrint(this->address) << " " << this->mnemonic_string << std::endl;

  INT32 ins_cat = INS_Category(ins);
  this->is_fp = (ins_cat == XED_CATEGORY_X87_ALU || ins_cat == XED_CATEGORY_MMX);

  if (this->is_fp) {} // do not capture register/memory accesses of X87 instructions
  else {
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
  }

  this->is_memory_read = INS_IsMemoryRead(ins);
  this->is_memory_write = INS_IsMemoryWrite(ins);
  this->has_memory_read2 = INS_HasMemoryRead2(ins);
//  this->has_known_memory_size = INS_hasKnownMemorySize(ins);

  this->has_fall_through = INS_HasFallThrough(ins);
}

instruction_t::instruction_t(const instruction_t &ins) : address(ins.address),
                                                         next_address(ins.next_address),
                                                         opcode_size(ins.opcode_size),
                                                         // mnemonic_string(ins.mnemonic_string),
                                                         src_registers(ins.src_registers),
                                                         dst_registers(ins.dst_registers),
                                                         is_fp(ins.is_fp),
                                                         is_memory_read(ins.is_memory_read),
                                                         is_memory_write(ins.is_memory_write),
                                                         has_memory_read2(ins.has_memory_read2),
                                                         has_fall_through(ins.has_fall_through)
{
  this->opcode_buffer = new UINT8[this->opcode_size];
  memcpy(this->opcode_buffer, ins.opcode_buffer, this->opcode_size);
//  PIN_SafeCopy(this->opcode_buffer, reinterpret_cast<VOID*>(this->address), this->opcode_size);
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

rt_instruction_t::rt_instruction_t(const instruction_t &static_ins) : instruction_t(static_ins)
{
//  std::cout << "run: " << StringFromAddrint(this->address) << " " << this->mnemonic_string << std::endl;
}

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
//  std::cout << "in length: " << length << std::endl;

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
    sizeof(ADDRINT);              // for memonic string length
    // this->mnemonic_string.length(); // for mnemonic string

  std::size_t group1_length = sizeof(ADDRINT) + length_of_register_map(this->src_registers) + // for read registers
                              sizeof(ADDRINT) + length_of_register_map(this->dst_registers);  // for written registers

//  std::size_t group2_length = 5 * sizeof(bool); // not serialized

  std::size_t group2_length = sizeof(ADDRINT) + length_of_memory_map(this->load_mem_addresses) + // for load memory addresses
                              sizeof(ADDRINT) + length_of_memory_map(this->store_mem_addresses); // for stored memory addreses

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

//  std::cout << this->mnemonic_string << std::endl;

  // group 0
  buffer = original_buffer_addr + serialized_length;
  ADDRINT *p_address = reinterpret_cast<ADDRINT*>(buffer); // address
  *p_address = this->address;
  serialized_length += sizeof(ADDRINT);

  ADDRINT *p_next_address = p_address + 1; // next address
  *p_next_address = this->next_address;
  serialized_length += sizeof(ADDRINT);

  ADDRINT *p_opcode_size = p_next_address + 1; // opcode size
  *p_opcode_size = this->opcode_size;
  serialized_length += sizeof(ADDRINT);

  UINT8 *p_opcode = reinterpret_cast<UINT8*>(p_opcode_size + 1); // opcode buffer
  std::memcpy(p_opcode, this->opcode_buffer, this->opcode_size);
  serialized_length += this->opcode_size;

  // ADDRINT *p_mnemonic_size = reinterpret_cast<ADDRINT*>(p_opcode + this->opcode_size); // mnemonic size
  // *p_mnemonic_size = this->mnemonic_string.length();
  // serialized_length += sizeof(ADDRINT);

  // UINT8 *p_mnemonic = reinterpret_cast<UINT8*>(p_mnemonic_size + 1); // mnemonic buffer
  // std::memcpy(p_mnemonic, this->mnemonic_string.c_str(), this->mnemonic_string.length());
  // serialized_length += this->mnemonic_string.length();

  // group 1
  buffer = original_buffer_addr + serialized_length;
  ADDRINT *p_src_reg_map_length = reinterpret_cast<ADDRINT*>(buffer); // read register map length
  *p_src_reg_map_length = length_of_register_map(this->src_registers);
//  std::cout << "read register map length (before): " << *p_src_reg_map_length << std::endl;
  serialized_length += sizeof(ADDRINT);

  UINT8 *p_src_reg_map = reinterpret_cast<UINT8*>(p_src_reg_map_length + 1); // read register map
  serialize_register_map(p_src_reg_map, this->src_registers);
  serialized_length += *p_src_reg_map_length;
//  std::cout << "read register map length (after): " << *p_src_reg_map_length << std::endl;

  buffer = original_buffer_addr + serialized_length;
  ADDRINT *p_dst_reg_map_length = reinterpret_cast<ADDRINT*>(buffer); // written register map length
  *p_dst_reg_map_length = length_of_register_map(this->dst_registers);
//  std::cout << "written register map length: " << *p_dst_reg_map_length << std::endl;
  serialized_length += sizeof(ADDRINT);

  UINT8 *p_dst_reg_map = reinterpret_cast<UINT8*>(p_dst_reg_map_length + 1); // written register map
  serialize_register_map(p_dst_reg_map, this->dst_registers);
  serialized_length += *p_dst_reg_map_length;


  // group 2
  buffer = original_buffer_addr + serialized_length;
  ADDRINT *p_load_mem_map_length = reinterpret_cast<ADDRINT*>(buffer); // loaded memory map length
  *p_load_mem_map_length = length_of_memory_map(this->load_mem_addresses);
//  std::cout << "load mem length: " << *p_load_mem_map_length << std::endl;
  serialized_length += sizeof(ADDRINT);

  UINT8 *p_load_mem_map = reinterpret_cast<UINT8*>(p_load_mem_map_length + 1); // loaded memory map
  serialize_memory_map(p_load_mem_map, this->load_mem_addresses);
  serialized_length += *p_load_mem_map_length;
//  std::cout << "load mem length: " << *p_load_mem_map_length << std::endl;

  buffer = original_buffer_addr + serialized_length;
  ADDRINT *p_store_mem_map_length = reinterpret_cast<ADDRINT*>(buffer); // stored memory map length
  *p_store_mem_map_length = length_of_memory_map(this->store_mem_addresses);
//  std::cout << "stored mem length: " << *p_store_mem_map_length << std::endl;
  serialized_length += sizeof(ADDRINT);

  UINT8 *p_store_mem_map = reinterpret_cast<UINT8*>(p_store_mem_map_length + 1); // stored memory map length
  serialize_memory_map(p_store_mem_map, this->store_mem_addresses);
  serialized_length += *p_store_mem_map_length;
//  std::cout << "stored mem length: " << *p_store_mem_map_length << std::endl;

  // group 3
  buffer = original_buffer_addr + serialized_length;
  THREADID *p_thread_id = reinterpret_cast<THREADID*>(buffer);
  *p_thread_id = this->thread_id;
  serialized_length += sizeof(THREADID);

//  std::cout << serialized_length << " " << this->serialized_length() << std::endl;
  assert(serialized_length == this->serialized_length());
  return serialized_length;
}
// END: class runtime_instruction_t

// BEGIN: static variables
static KNOB<string> output_file_knob      (KNOB_MODE_WRITEONCE, "pintool", "out", "output.trace", "output trace file");
static KNOB<UINT32> trace_max_length_knob (KNOB_MODE_WRITEONCE, "pintool", "length", "0", "limit length of trace (0 = no limit)");
static KNOB<UINT32> cached_ins_count_knob (KNOB_MODE_WRITEONCE, "pintool", "cached", "0", "number of cached instruction (0 = no cached)");
static KNOB<ADDRINT> start_address_knob   (KNOB_MODE_WRITEONCE, "pintool", "start", "0", "start address (0 = from beginning)");
static KNOB<ADDRINT> stop_address_knob    (KNOB_MODE_WRITEONCE, "pintool", "stop", "0", "stop address (0 = until ending)");

static UINT32 max_trace_length = 0;
static UINT32 current_trace_length = 0;
static UINT32 cached_ins_count = 0;

static ADDRINT start_address;
static ADDRINT stop_address;

static std::ofstream output_file;

static std::map<THREADID, rt_instruction_t*> current_instruction_at_thread;
static std::map<ADDRINT, instruction_t*> cached_instruction_at_address;

static UINT8* cached_buffer = 0;
static UINT32 current_cached_length = 0;
static UINT32 current_cached_count = 0;

static std::time_t start_time;
static std::time_t stop_time;

enum TracingState 
{
  BeforeStart = 0,
  BetweenStartAndStop = 1,
  AfterStop = 2
};
static TracingState tracing_state = BeforeStart;
// END: static variables

// BEGIN: declare callback functions
static VOID initialize_cached_instruction_callback(ADDRINT ins_addr, const CONTEXT *p_context, THREADID thread_id);

static VOID save_read_registers_callback(const CONTEXT *p_context, THREADID thread_id);

static VOID save_written_registers_callback(const CONTEXT *p_context, THREADID thread_id);

static VOID save_loaded_memory_callback(ADDRINT load_addr, UINT32 load_size, THREADID thread_id);

static VOID save_stored_memory_callback(ADDRINT stored_addr, UINT32 stored_size, THREADID thread_id);

static VOID serialize_threaded_instruction_callback(THREADID thread_id);
// END: declare callback functions

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


static VOID save_previous_instruction_information(CONTEXT const *p_context, THREADID thread_id)
{
  if (tracing_state == BetweenStartAndStop && current_instruction_at_thread[thread_id] != 0) {
    // this instruction is not reset yet (because it has no "fall through") then
    // we need some extract information and serialize it
    if (!current_instruction_at_thread[thread_id]->dst_registers.empty()) {
      save_written_registers_callback(p_context, thread_id);
    }

    if (current_instruction_at_thread[thread_id]->is_memory_write) {
      std::map<ADDRINT, UINT8>::iterator mem_iter = current_instruction_at_thread[thread_id]->store_mem_addresses.begin();
      for (; mem_iter != current_instruction_at_thread[thread_id]->store_mem_addresses.end(); ++mem_iter) {
        UINT8 byte_value;
        PIN_SafeCopy(&byte_value, reinterpret_cast<VOID*>(mem_iter->first), sizeof(UINT8));
        mem_iter->second = byte_value;
      }
    }

    if (stop_address != 0 && current_instruction_at_thread[thread_id]->address == stop_address) tracing_state = AfterStop;

    serialize_threaded_instruction_callback(thread_id);

    // reset serialized instruction
    delete current_instruction_at_thread[thread_id];
    current_instruction_at_thread[thread_id] = 0;
  }

  return;
}

//static instruction_t *p_ins = 0;
// implement callback functions
static VOID initialize_cached_instruction_callback(ADDRINT ins_addr, const CONTEXT *p_context, THREADID thread_id)
{
  //instruction_is_disabled = (ins_addr >> (CHAR_BIT * 3)) >= 0x60;
  //if (instruction_is_disabled) return;

  if (tracing_state == AfterStop) PIN_ExitApplication(0);

  switch (tracing_state)
  {
  case BeforeStart:
    if (start_address == 0 || start_address == ins_addr) tracing_state = BetweenStartAndStop;
    break;
  case BetweenStartAndStop:
    break;
  case AfterStop:
    break;
  }

  if (tracing_state == BetweenStartAndStop) {
    //if (current_instruction_at_thread[thread_id] != 0) {
    //  // this instruction is not reset yet (because it has no "fall through") then
    //  // we need some extract information and serialize it
    //  if (!current_instruction_at_thread[thread_id]->dst_registers.empty()) {
    //    save_written_registers_callback(p_context, thread_id);
    //  }

    //  if (current_instruction_at_thread[thread_id]->is_memory_write) {
    //    std::map<ADDRINT, UINT8>::iterator mem_iter = current_instruction_at_thread[thread_id]->store_mem_addresses.begin();
    //    for (; mem_iter != current_instruction_at_thread[thread_id]->store_mem_addresses.end(); ++mem_iter) {
    //      UINT8 byte_value;
    //      PIN_SafeCopy(&byte_value, reinterpret_cast<VOID*>(mem_iter->first), sizeof(UINT8));
    //      mem_iter->second = byte_value;
    //    }
    //  }

    //  if (stop_address != 0 && current_instruction_at_thread[thread_id]->address == stop_address) tracing_state = AfterStop;

    //  serialize_threaded_instruction_callback(thread_id);

    //  // reset serialized instruction
    //  delete current_instruction_at_thread[thread_id];
    //  current_instruction_at_thread[thread_id] = 0;
    //}

    current_instruction_at_thread[thread_id] = new rt_instruction_t(*cached_instruction_at_address[ins_addr]);
    current_instruction_at_thread[thread_id]->thread_id = thread_id;
  }

  return;
}

static VOID save_read_registers_callback(const CONTEXT *p_context, THREADID thread_id)
{
  //if (instruction_is_disabled) return;
  if (tracing_state != BetweenStartAndStop) return;

  rt_instruction_t *runtime_ins = current_instruction_at_thread[thread_id];
  for (std::map<REG, PIN_REGISTER>::iterator reg_iter = runtime_ins->src_registers.begin();
       reg_iter != runtime_ins->src_registers.end(); ++reg_iter) {
    PIN_REGISTER reg_value;
    PIN_GetContextRegval(p_context, (*reg_iter).first, reinterpret_cast<UINT8*>(&reg_value));
    runtime_ins->src_registers[(*reg_iter).first] = reg_value;
  }

  return;
}

static VOID save_written_registers_callback(const CONTEXT *p_context, THREADID thread_id)
{
  //if (instruction_is_disabled) return;
  if (tracing_state != BetweenStartAndStop) return;

  rt_instruction_t *runtime_ins = current_instruction_at_thread[thread_id];

  std::map<REG, PIN_REGISTER>::const_iterator reg_iter = runtime_ins->dst_registers.begin();
  for (; reg_iter != runtime_ins->dst_registers.end(); ++reg_iter) {
    PIN_REGISTER reg_value;
    PIN_GetContextRegval(p_context, (*reg_iter).first, reinterpret_cast<UINT8*>(&reg_value));
    runtime_ins->dst_registers[(*reg_iter).first] = reg_value;
  }

  return;
}

static VOID save_loaded_memory_callback(ADDRINT load_addr, UINT32 load_size, THREADID thread_id)
{
  //if (instruction_is_disabled) return;
  if (tracing_state != BetweenStartAndStop) return;

  rt_instruction_t *runtime_ins = current_instruction_at_thread[thread_id];
  ADDRINT upper_addr = load_addr + load_size;
  for (ADDRINT mem_addr = load_addr; mem_addr < upper_addr; ++mem_addr) {
    UINT8 byte_value;
    PIN_SafeCopy(&byte_value, reinterpret_cast<VOID*>(mem_addr), 1);
    runtime_ins->load_mem_addresses[mem_addr] = byte_value;
  }

  return;
}

static VOID save_stored_memory_callback(ADDRINT stored_addr, UINT32 stored_size, THREADID thread_id)
{
  //if (instruction_is_disabled) return;
  if (tracing_state != BetweenStartAndStop) return;

  rt_instruction_t *runtime_ins = current_instruction_at_thread[thread_id];
  ADDRINT upper_addr = stored_addr + stored_size;
  for (ADDRINT mem_addr = stored_addr; mem_addr < upper_addr; ++mem_addr) {
    UINT8 byte_value;
    PIN_SafeCopy(&byte_value, reinterpret_cast<VOID*>(mem_addr), sizeof(UINT8));
    runtime_ins->store_mem_addresses[mem_addr] = byte_value;
  }

  return;
}

static VOID serialize_threaded_instruction_callback(THREADID thread_id)
{
  //if (instruction_is_disabled) return;
  if (tracing_state != BetweenStartAndStop) return;
  //if (!should_add_to_trace(current_instruction_at_thread[thread_id])) return;

  //printf("add 0x%x\n", current_instruction_at_thread[thread_id]->address);

  current_trace_length++;
  std::size_t serialized_length = current_instruction_at_thread[thread_id]->serialized_length();

  if (cached_ins_count == 0) {
    // serialize size of serialized instruction: allow random access on the serialized trace
    output_file.write(reinterpret_cast<char*>(&serialized_length), sizeof(ADDRINT));

    static UINT8 buffer[1000];
    // UINT8 *buffer = new UINT8[serialized_length];
    current_instruction_at_thread[thread_id]->serialize(buffer);
    output_file.write(reinterpret_cast<char*>(buffer), serialized_length);
  }
  else {
    // serialize size of serialized instruction: allow random access on the serialized trace
    reinterpret_cast<ADDRINT*>(cached_buffer + current_cached_length)[0] = serialized_length;
    current_cached_length += sizeof(ADDRINT);

    current_instruction_at_thread[thread_id]->serialize(cached_buffer + current_cached_length);
    current_cached_length += serialized_length;
    current_cached_count++;

    if (current_cached_count == cached_ins_count) {
      printf("flush %u instructions (%u bytes), current trace length: %u\n", 
             current_cached_count, current_cached_length, current_trace_length);

      output_file.write(reinterpret_cast<char*>(cached_buffer), current_cached_length);
      current_cached_length = 0;
      current_cached_count = 0;
    }
  }
  // delete [] buffer;

  // // reset serialized instruction
  // delete current_instruction_at_thread[thread_id];
  // current_instruction_at_thread[thread_id] = 0;

  // compare with maximal length (0 = no limit)
  
  //if (current_trace_length % 500000 == 0) std::cout << "traced instructions: " << current_trace_length 
  //                                                  << " (cached: " << cached_instruction_at_address.size() << ")"  << std::endl;
  //if (current_trace_length % 50000 == 0) std::cout << "traced instructions: " << current_trace_length << std::endl;

  //output_file.flush(); // just for safe
  if (current_trace_length >= max_trace_length && max_trace_length != 0) {
    PIN_ExitApplication(1);
  }

  return;
}

static VOID inject_callbacks(const INS& ins)
{
  // add instruction statically into a map, so we do not need to re-examine it
  /*ADDRINT ins_addr = INS_Address(ins);
  if (cached_instruction_at_address.find(ins_addr) == cached_instruction_at_address.end()) {
    cached_instruction_at_address[ins_addr] = new instruction_t(ins);
  }*/

  INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(save_previous_instruction_information), 
                 IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
  
  // instructions can be modified (e.g. self-modifying code), so we need 
  // reinitialize them in this analysis function
  ADDRINT ins_addr = INS_Address(ins);

  // omit instructions of Windows's APIs
  if (ins_addr >> (CHAR_BIT * 3 + 4) > 0x0) return;

  if (cached_instruction_at_address.find(ins_addr) == cached_instruction_at_address.end()) {
    cached_instruction_at_address[ins_addr] = new instruction_t(ins);
  }
  else if (!(*cached_instruction_at_address[ins_addr] == ins)) {
    delete cached_instruction_at_address[ins_addr];
    cached_instruction_at_address[ins_addr] = new instruction_t(ins);
  }

  /*if (cached_instruction_at_address.find(ins_addr) != cached_instruction_at_address.end() && 
      !(*cached_instruction_at_address[ins_addr] == ins)) {
    delete cached_instruction_at_address[ins_addr];
  }
  else cached_instruction_at_address[ins_addr] = new instruction_t(ins);*/

  instruction_t *instrumented_instruction = cached_instruction_at_address[ins_addr];

  // insert callback functions for this instruction
  INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(initialize_cached_instruction_callback),
                  IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);

  if (stop_address == ins_addr && stop_address != 0) tracing_state = AfterStop;

  if (instrumented_instruction->is_fp) {} // do not capture concrete information of X87 instructions
  else {
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

    if (instrumented_instruction->is_memory_write) {
      INS_InsertCall(ins, IPOINT_BEFORE, reinterpret_cast<AFUNPTR>(save_stored_memory_callback),
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

static VOID initialize(VOID *data)
{
  if (cached_ins_count != 0) {
    cached_buffer = new UINT8[CAPTURED_INS_MAX_SIZE * cached_ins_count];
  }
}

static VOID finalize(INT32 code, VOID *data)
{
  static_cast<void>(code); static_cast<void>(data);

  if (cached_ins_count != 0 && current_cached_count != 0) {
    output_file.write(reinterpret_cast<char*>(cached_buffer), current_cached_length);
  }

  // clean cached instructions
  std::map<ADDRINT, instruction_t*>::iterator addr_ins_iter = cached_instruction_at_address.begin();
  for (; addr_ins_iter != cached_instruction_at_address.end(); ++addr_ins_iter) {
    delete (*addr_ins_iter).second;
  }
  cached_instruction_at_address.clear();

  if (cached_ins_count != 0) {
    delete cached_buffer;
  }

  output_file.close();

  std::cout << std::endl << "stop tracing" << std::endl
            << current_trace_length << " instruction captured" << std::endl;

  time(&stop_time);
  std::cout << std::difftime(stop_time, start_time) << " seconds elapsed." << std::endl;

  return;
}

#if defined(_WIN32)
namespace windows
{
#include <Windows.h>
#include <Psapi.h>
#include <io.h>
#include <fcntl.h>

void reopen_console()
{
  // attach to the console of the current cmd process
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    int outDesc = _open_osfhandle(reinterpret_cast<intptr_t>(GetStdHandle(STD_OUTPUT_HANDLE)), _O_TEXT);
    *stdout = *_fdopen(outDesc, "w"); setvbuf(stdout, NULL, _IONBF, 0);

    int errDesc = _open_osfhandle(reinterpret_cast<intptr_t>(GetStdHandle(STD_ERROR_HANDLE)), _O_TEXT);
    *stderr = *_fdopen(errDesc, "w"); setvbuf(stderr, NULL, _IONBF, 0);
  }

  return;
}
}
#endif

int main(int argc, char *argv[])
{
#if defined(_WIN32)
  windows::reopen_console();
#endif

  if (PIN_Init(argc, argv)) {
    std::cout << KNOB_BASE::StringKnobSummary() << std::endl;
    PIN_ExitProcess(0);
  }

  max_trace_length = trace_max_length_knob.Value();
  start_address = start_address_knob.Value();
  stop_address = stop_address_knob.Value();
  cached_ins_count = cached_ins_count_knob.Value();

  std::cout << "start tracing program: " << get_binary_name(argc, argv) << std::endl
            << "limit length: " << max_trace_length;
  if (max_trace_length == 0) std::cout << " (no limit)";

  std::cout << std::endl 
            << "cached instruction count: " << cached_ins_count;
  if (cached_ins_count == 0) std::cout << " (no cached)";

  std::cout << std::endl
            << "start address: " << StringFromAddrint(start_address);
  if (start_address == 0) std::cout << " (from beginning)";
  std::cout << std::endl
	        << "stop address: " << StringFromAddrint(stop_address);
  if (stop_address == 0) std::cout << " (until ending)";
  std::cout << std::endl
            << "output file: " << output_file_knob.Value() << std::endl;

  output_file.open(output_file_knob.Value().c_str(),
                   std::ofstream::trunc | std::ofstream::binary);
  if (!output_file) {
    std::cout << "cannot open output file, stop tracing." << std::endl;
    return 1;
  }

  std::cout << "start tracing..." << std::endl;
  std::time(&start_time);

  // specify size of ADDRINT, BOOL and THREADID
  UINT8 basic_size = sizeof(ADDRINT);
  output_file.write(reinterpret_cast<char*>(&basic_size), sizeof(UINT8));
  basic_size = sizeof(BOOL);
  output_file.write(reinterpret_cast<char*>(&basic_size), sizeof(UINT8));
  basic_size = sizeof(THREADID);
  output_file.write(reinterpret_cast<char*>(&basic_size), sizeof(UINT8));

  TRACE_AddInstrumentFunction(instrument_trace, 0);
  PIN_AddApplicationStartFunction(initialize, 0);
  PIN_AddFiniFunction(finalize, 0);

  // start tracing
  PIN_StartProgram();

  // never reached
  return 0;
}
