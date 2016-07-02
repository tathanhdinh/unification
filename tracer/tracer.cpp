#include <pin.H>
#include <string>
//#include <xed-interface.h>

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

  std::vector<REG> src_registers;
  std::vector<REG> dst_registers;

  instruction_t(const INS& ins);
  ~instruction_t();
};

instruction_t::instruction_t(const INS& ins)
{
  this->address = INS_Address(ins);
  this->next_addres = INS_NextAddress(ins);
}

// END: class instruction_t


int main(int argc, char *argv[])
{  return 0;
}
