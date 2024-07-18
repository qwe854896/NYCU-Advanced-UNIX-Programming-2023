// file deepcode ignore PT
// file deepcode ignore IntegerOverflow
// file deepcode ignore CommandInjection
#include <capstone/capstone.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <vector>

#define errquit(msg)                                                           \
  {                                                                            \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  }

#define PEEKSIZE 8
#define LOG2_PEEKSIZE 3

struct instruction_t {
  unsigned char bytes[16];
  int32_t size;
  std::string opr, opnd;
};

class Disassembler {
public:
  Disassembler() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_cshandle) != CS_ERR_OK)
      errquit("cs_open");
  }

  ~Disassembler() { cs_close(&m_cshandle); }

  void print_instruction(int64_t addr, const instruction_t *in,
                         const char *module);

  const std::vector<instruction_t> disassemble(const unsigned char *buf,
                                               size_t len, uint64_t rip);

private:
  csh m_cshandle = 0;
};

void Disassembler::print_instruction(int64_t addr, const instruction_t *in,
                                     const char *module) {
  int32_t i;
  char bytes[128] = "";
  if (in == NULL) {
    fprintf(stderr, "%12lx:\t<cannot disassemble>\n", addr);
  } else {
    for (i = 0; i < in->size; i++) {
      snprintf(&bytes[i * 3], 4, "%2.2x ", in->bytes[i]);
    }
    fprintf(stderr, "%12lx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(),
            in->opnd.c_str());
  }
}

const std::vector<instruction_t>
Disassembler::disassemble(const unsigned char *buf, size_t len, uint64_t rip) {
  int32_t count;
  cs_insn *insn;
  std::vector<instruction_t> instructions;

  if ((count = cs_disasm(m_cshandle, (uint8_t *)buf, len, rip, 0, &insn)) > 0) {
    int32_t i;
    for (i = 0; i < count; i++) {
      instructions.emplace_back(instruction_t());
      auto &in = instructions.back();
      in.size = insn[i].size;
      in.opr = insn[i].mnemonic;
      in.opnd = insn[i].op_str;
      memcpy(in.bytes, insn[i].bytes, insn[i].size);
    }
    cs_free(insn, count);
  }

  return instructions;
}

struct breakpoint_t {
  uint32_t index;
  uint64_t address;
  uint64_t original_data;
};

class BreakpointManager {
public:
  BreakpointManager(pid_t child) : m_child(child) {}

  void set_breakpoint(uint64_t address);
  void remove_breakpoint(uint64_t address);
  void check_breakpoint(user_regs_struct &regs);

  const breakpoint_t *get_breakpoint(uint32_t index) const;
  const breakpoint_t *get_breakpoint(uint64_t address) const;
  const std::vector<breakpoint_t> get_breakpoints() const;

  void update_breakpoint(uint32_t index, uint64_t data);

private:
  pid_t m_child;

  uint32_t m_breakpoint_count = 0;
  std::map<uint32_t, breakpoint_t> m_breakpoints;
  std::map<uint64_t, uint32_t> m_address_to_index;
};

void BreakpointManager::set_breakpoint(uint64_t address) {
  breakpoint_t bp;
  bp.index = m_breakpoint_count++;
  bp.address = address;

  m_breakpoints[bp.index] = bp;
  m_address_to_index[address] = bp.index;
}

void BreakpointManager::remove_breakpoint(uint64_t address) {
  int32_t index = m_address_to_index[address];

  m_address_to_index.erase(address);
  m_breakpoints.erase(index);
}

void BreakpointManager::check_breakpoint(user_regs_struct &regs) {
  uint64_t rip = regs.rip;
  const breakpoint_t *bp = get_breakpoint(rip);

  if (bp == nullptr) {
    bp = get_breakpoint(--rip);

    if (bp == nullptr) {
      return;
    }
  }

  // Check if 0xCC is at the address
  uint64_t data = ptrace(PTRACE_PEEKTEXT, m_child, rip, NULL);
  if ((data & 0xFF) != 0xCC) {
    return;
  }

  fprintf(stderr, "** hit a breakpoint at 0x%lx.\n", rip);

  regs.rip = rip;
  if (ptrace(PTRACE_SETREGS, m_child, 0, &regs) != 0) {
    errquit("ptrace(SETREGS)");
  }
}

const breakpoint_t *BreakpointManager::get_breakpoint(uint32_t index) const {
  auto it = m_breakpoints.find(index);
  if (it == m_breakpoints.end()) {
    return nullptr;
  }
  return &it->second;
}

const breakpoint_t *BreakpointManager::get_breakpoint(uint64_t address) const {
  auto it = m_address_to_index.find(address);
  if (it == m_address_to_index.end()) {
    return nullptr;
  }
  return get_breakpoint(it->second);
}

const std::vector<breakpoint_t> BreakpointManager::get_breakpoints() const {
  std::vector<breakpoint_t> breakpoints;
  for (const auto &bp : m_breakpoints) {
    breakpoints.emplace_back(bp.second);
  }
  return breakpoints;
}

void BreakpointManager::update_breakpoint(uint32_t index, uint64_t data) {
  auto it = m_breakpoints.find(index);
  if (it == m_breakpoints.end()) {
    return;
  }
  it->second.original_data = data;
}

class Debugger {
public:
  Debugger() {}
  ~Debugger() {}

  void set_program(char *argv[]);
  void run();

private:
  bool m_program_loaded = false;
  pid_t m_child;
  int32_t m_status;

  /* Utils */
  void m_prompt() { std::cerr << "(sdb) "; }

  /* Commands */
  void m_singlestep();
  void m_continue();
  void m_syscall();
  void m_info_regs();
  void m_info_breakpoints();
  void m_setup_breakpoint(uint64_t address);
  void m_remove_breakpoint(uint32_t index);
  void m_patch(uint64_t address, uint64_t value, uint8_t len);

  /* Breakpoints */
  std::unique_ptr<BreakpointManager> m_breakpoint_manager = nullptr;

  /* Child Process */
  uint64_t m_program_text_section_end = 0x0;
  struct user_regs_struct m_regs;

  void m_update_regs();
  void m_terminate();
  void m_prepare_for_execution(bool is_continue = false);
  void m_return_from_execution();

  /* Disassembler */
  std::unique_ptr<Disassembler> m_disassembler = nullptr;

  const int32_t INSTRUCTION_COUNT = 5;
  void m_print_instructions(uint64_t rip, uint32_t count);
};

namespace {
int64_t get_text_section_end(const char *program_name) {
  // parse ELF to get the end of the text section
  FILE *fp = fopen(program_name, "rb");
  if (fp == nullptr) {
    errquit("fopen");
  }

  Elf64_Ehdr ehdr;
  fread(&ehdr, 1, sizeof(ehdr), fp);

  fseek(fp, ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shstrndx, SEEK_SET);

  Elf64_Shdr shdr;
  fread(&shdr, 1, sizeof(shdr), fp);

  int64_t text_section_end = 0;
  for (int32_t i = 0; i < ehdr.e_shnum; i++) {
    fseek(fp, ehdr.e_shoff + ehdr.e_shentsize * i, SEEK_SET);
    fread(&shdr, 1, sizeof(shdr), fp);

    if (shdr.sh_type == SHT_PROGBITS && shdr.sh_flags & SHF_EXECINSTR) {
      text_section_end = shdr.sh_addr + shdr.sh_size;
    }
  }

  fclose(fp);

  return text_section_end;
}
} // namespace

void Debugger::set_program(char *argv[]) {
  if (m_program_loaded) {
    std::cerr << "** program already loaded" << std::endl;
    return;
  }

  if ((m_child = fork()) < 0) {
    errquit("fork");
  }

  if (m_child == 0) {
    // Child process
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
      errquit("ptrace");
    }
    execvp(argv[0], argv);
    errquit("execvp");
  }

  if (waitpid(m_child, &m_status, 0) < 0) {
    errquit("waitpid");
  }

  assert(WIFSTOPPED(m_status));

  ptrace(PTRACE_SETOPTIONS, m_child, NULL,
         PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

  m_program_loaded = true;

  // open argv[0] and parse ELF to get the end of the text section
  m_program_text_section_end = get_text_section_end(argv[0]);

  m_update_regs();
  fprintf(stderr, "** program '%s' loaded. entry point 0x%llx.\n", argv[0],
          m_regs.rip);

  m_print_instructions(m_regs.rip, INSTRUCTION_COUNT);
}

void Debugger::run() {
  std::string command;
  for (; m_prompt(), std::cin >> command;) {
    if (command == "load") {
      if (m_program_loaded) {
        std::cerr << "** program already loaded" << std::endl;
        continue;
      }

      std::string program;
      std::cin >> program;

      char *argv[] = {&program[0], nullptr};
      set_program(argv);

      continue;
    } else if (command == "quit" || command == "exit") {
      break;
    } else if (!m_program_loaded) {
      std::cerr << "** please load a program first." << std::endl;
      continue;
    }

    if (command == "cont") {
      m_continue();
    } else if (command == "si") {
      m_singlestep();
    } else if (command == "info") {
      std::string subcommand;
      std::cin >> subcommand;

      if (subcommand == "reg") {
        m_info_regs();
      } else if (subcommand == "break") {
        m_info_breakpoints();
      } else {
        std::cerr << "** unknown subcommand" << std::endl;
      }
    } else if (command == "break") {
      std::string hex_address;
      std::cin >> hex_address;

      // if hex_address is not start with 0x, add 0x
      if (hex_address.substr(0, 2) != "0x") {
        hex_address = "0x" + hex_address;
      }

      int64_t address = std::stoll(hex_address, nullptr, 16);

      m_setup_breakpoint(address);
    } else if (command == "delete") {
      int32_t index;
      std::cin >> index;

      m_remove_breakpoint(index);
    } else if (command == "patch") {
      std::string hex_address, hex_value;
      uint8_t len;
      std::cin >> hex_address >> hex_value >> len;

      if (hex_address.substr(0, 2) != "0x") {
        hex_address = "0x" + hex_address;
      }
      if (hex_value.substr(0, 2) != "0x") {
        hex_value = "0x" + hex_value;
      }

      uint64_t address = std::stoll(hex_address, nullptr, 16);
      uint64_t value = std::stoll(hex_value, nullptr, 16);

      m_patch(address, value, len);
    } else if (command == "syscall") {
      m_syscall();
    } else {
      std::cerr << "** unknown command" << std::endl;
    }
  }
}

void Debugger::m_singlestep() {
  m_prepare_for_execution();
  ptrace(PTRACE_SINGLESTEP, m_child, NULL, NULL);
  waitpid(m_child, &m_status, 0);
  m_return_from_execution();
}

void Debugger::m_continue() {
  m_prepare_for_execution(true);
  ptrace(PTRACE_CONT, m_child, NULL, NULL);
  waitpid(m_child, &m_status, 0);
  m_return_from_execution();
}

void Debugger::m_syscall() {
  m_prepare_for_execution();
  ptrace(PTRACE_SYSCALL, m_child, NULL, NULL);
  waitpid(m_child, &m_status, 0);
  m_return_from_execution();
}

void Debugger::m_info_regs() {
  m_update_regs();
  printf("$rax 0x%016llx\t$rbx 0x%016llx\t$rcx 0x%016llx\n"
         "$rdx 0x%016llx\t$rsi 0x%016llx\t$rdi 0x%016llx\n"
         "$rbp 0x%016llx\t$rsp 0x%016llx\t$r8  0x%016llx\n"
         "$r9  0x%016llx\t$r10 0x%016llx\t$r11 0x%016llx\n"
         "$r12 0x%016llx\t$r13 0x%016llx\t$r14 0x%016llx\n"
         "$r15 0x%016llx\t$rip 0x%016llx\t$eflags 0x%016llx\n",
         m_regs.rax, m_regs.rbx, m_regs.rcx, m_regs.rdx, m_regs.rsi, m_regs.rdi,
         m_regs.rbp, m_regs.rsp, m_regs.r8, m_regs.r9, m_regs.r10, m_regs.r11,
         m_regs.r12, m_regs.r13, m_regs.r14, m_regs.r15, m_regs.rip,
         m_regs.eflags);
}

void Debugger::m_info_breakpoints() {
  const auto &breakpoints = m_breakpoint_manager->get_breakpoints();

  if (breakpoints.empty()) {
    std::cerr << "** no breakpoints." << std::endl;
    return;
  }

  printf("Num\tAddress\n");
  for (const auto &bp : breakpoints) {
    printf("%d\t0x%lx\n", bp.index, bp.address);
  }
}

void Debugger::m_setup_breakpoint(uint64_t address) {
  if (m_breakpoint_manager == nullptr) {
    m_breakpoint_manager = std::make_unique<BreakpointManager>(m_child);
  }

  m_breakpoint_manager->set_breakpoint(address);

  fprintf(stderr, "** set a breakpoint at 0x%lx.\n", address);
}

void Debugger::m_remove_breakpoint(uint32_t index) {
  if (m_breakpoint_manager == nullptr) {
    fprintf(stderr, "** breakpoint %d does not exist.\n", index);
    return;
  }

  const auto *bp = m_breakpoint_manager->get_breakpoint(index);
  if (bp == nullptr) {
    fprintf(stderr, "** breakpoint %d does not exist.\n", index);
    return;
  }

  m_breakpoint_manager->remove_breakpoint(bp->address);
  fprintf(stderr, "** delete breakpoint %d.\n", index);
}

void Debugger::m_patch(uint64_t address, uint64_t value, uint8_t len) {
  int64_t data = ptrace(PTRACE_PEEKTEXT, m_child, address, NULL);

  uint64_t mask = (1LL << (len << LOG2_PEEKSIZE)) - 1;
  uint64_t new_data = (data & ~mask) | (value & mask);

  ptrace(PTRACE_POKETEXT, m_child, address, new_data);
  fprintf(stderr, "** patch memory at address 0x%lx.\n", address);
}

void Debugger::m_update_regs() {
  if (ptrace(PTRACE_GETREGS, m_child, 0, &m_regs) == 0) {
    // pass
  }
}

void Debugger::m_terminate() {
  m_program_loaded = false;
  std::cerr << "** the target program terminated." << std::endl;
}

void Debugger::m_prepare_for_execution(bool is_continue) {
  if (m_breakpoint_manager == nullptr) {
    return;
  }

  const auto &breakpoints = m_breakpoint_manager->get_breakpoints();

  for (const auto &bp : breakpoints) {
    uint64_t address = bp.address;
    uint64_t data = ptrace(PTRACE_PEEKTEXT, m_child, address, NULL);

    if (is_continue && address == m_regs.rip) {
      const std::vector<instruction_t> instructions =
          m_disassembler->disassemble((unsigned char *)&data, PEEKSIZE,
                                      m_regs.rip);
      instruction_t in = instructions[0];

      uint64_t next_address = m_regs.rip + in.size;
      uint64_t next_data = ptrace(PTRACE_PEEKTEXT, m_child, next_address, NULL);
      uint64_t next_int3 = (next_data & 0xFFFFFFFFFFFFFF00) | 0xCC;

      ptrace(PTRACE_POKETEXT, m_child, next_address, next_int3);

      ptrace(PTRACE_SINGLESTEP, m_child, NULL, NULL);
      waitpid(m_child, &m_status, 0);

      ptrace(PTRACE_POKETEXT, m_child, next_address, next_data);
    } else if (address == m_regs.rip) {
      continue;
    }

    m_breakpoint_manager->update_breakpoint(bp.index, data);

    uint64_t int3 = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;

    ptrace(PTRACE_POKETEXT, m_child, address, int3);
  }
}

void Debugger::m_return_from_execution() {
  if (WIFEXITED(m_status)) {
    m_terminate();
    return;
  }

  if (!WIFSTOPPED(m_status)) {
    return;
  }

  m_update_regs();

  if (m_breakpoint_manager != nullptr) {
    m_breakpoint_manager->check_breakpoint(m_regs);

    const auto &breakpoints = m_breakpoint_manager->get_breakpoints();

    for (auto it = breakpoints.rbegin(); it != breakpoints.rend(); ++it) {
      const auto &bp = *it;
      uint64_t address = bp.address;
      uint64_t data = bp.original_data;

      ptrace(PTRACE_POKETEXT, m_child, address, data);
    }
  }

  bool is_syscall = WSTOPSIG(m_status) & 0x80;
  static bool syscall_enter = true;

  if (is_syscall) {
    if (syscall_enter) {
      fprintf(stderr, "** enter a syscall(%lld) at 0x%llx.\n", m_regs.orig_rax,
              m_regs.rip - 2);
    } else {
      fprintf(stderr, "** leave a syscall(%lld) = %lld at 0x%llx.\n",
              m_regs.orig_rax, m_regs.rax, m_regs.rip - 2);
    }
    syscall_enter = !syscall_enter;
  } else {
    syscall_enter = true;
  }

  uint64_t rip = m_regs.rip - (is_syscall ? 2 : 0);
  m_print_instructions(rip, INSTRUCTION_COUNT);
}

void Debugger::m_print_instructions(uint64_t rip, uint32_t count) {
  if (!m_disassembler) {
    m_disassembler = std::make_unique<Disassembler>();
  }

  unsigned char buf[64] = {0};
  uint64_t ptr = rip;

  for (ptr = rip; ptr < rip + sizeof(buf); ptr += PEEKSIZE) {
    int64_t peek;
    errno = 0;
    peek = ptrace(PTRACE_PEEKTEXT, m_child, ptr, NULL);
    if (errno != 0)
      break;

    memcpy(&buf[ptr - rip], &peek, PEEKSIZE);
  }

  if (ptr == rip) {
    fprintf(stderr,
            "** the address is out of the range of the text section.\n");
    return;
  }

  const std::vector<instruction_t> instructions =
      m_disassembler->disassemble(buf, ptr - rip, rip);

  for (uint32_t i = 0; i < count; ++i) {
    if (i >= instructions.size() || rip >= m_program_text_section_end) {
      fprintf(stderr,
              "** the address is out of the range of the text section.\n");
      break;
    }
    m_disassembler->print_instruction(rip, &instructions[i], "test");
    rip += instructions[i].size;
  }
}

int32_t main(int32_t argc, char *argv[]) {
  Debugger debugger;

  if (argc != 1) {
    debugger.set_program(argv + 1);
  }
  debugger.run();

  return 0;
}
