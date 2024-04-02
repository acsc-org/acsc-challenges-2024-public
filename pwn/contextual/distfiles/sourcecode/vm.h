#ifndef __VM_HEADER__
#define __VM_HEADER__

struct BasicBlockInfo;

#include "util.h"

#define MEMORY_START 0
#define CODE_SEG_ADDR 0x2000
#define CODE_SIZE 0x1000
#define STACK_SEG_ADDR 0x3000
#define STACK_SIZE 0x1000
#define MEMORY_SIZE 0x5000

#define PAGE_SIZE 0x1000

#define LEGAL_ADDR(addr, size) (((addr) >= MEMORY_START) && ((addr) <= MEMORY_SIZE) && ((size) <= MEMORY_SIZE) && ((addr) + (size) <= MEMORY_SIZE))

typedef enum Vmstatus {
  VM_NEXT,
  VM_EXIT,
  VM_ILLEGAL
} VMSTATUS;

typedef enum Reg {
  REG_R0 = 0,
  REG_R1 = 1,
  REG_R2 = 2,
  REG_R3 = 3,
  REG_R4 = 4,
  REG_PC = 4,
  REG_R5 = 5,
  REG_LR = 5,
  REG_R6 = 6,
  REG_R7 = 7,
  REG_R8 = 8,
  REG_R9 = 9,
  REG_R10 = 10,
  REG_R11 = 11,
  REG_R12 = 12,
  REG_R13 = 13,
  REG_FLAG = 13,
  REG_R14 = 14,
  REG_SP = 14,
  REG_R15 = 15,
  REG_BP = 15,
  REG_CNT = 16
} REG;

typedef struct Context {
  VMSTATUS status;
  uint8_t code[0x1000];
  uint8_t memory[0x5000];
  uint64_t regs[REG_CNT];
  VEC bb;
  struct BasicBlockInfo *prevBB;
} CONTEXT;

void setupVM(CONTEXT *context, uint8_t *code, uint64_t codeLen);
void clearVM(CONTEXT *context);
void runVM(CONTEXT *context);

#endif
