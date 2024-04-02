#ifndef __IR_HEADER__
#define __IR_HEADER__

#include "util.h"

#define IR_MEM_ACCESS(ir) ((ir) == IR_LOAD || (ir) == IR_STORE_IMM || (ir) == IR_STORE_REG)

#define SETUP_IR(_irS, _ir, _pc, _readRegCnt, _writeRegCnt) do { \
  (_irS).ir = (_ir); \
  (_irS).pc = (_pc); \
  (_irS).readRegCnt = (_readRegCnt); \
  (_irS).writeRegCnt = (_writeRegCnt); \
} while (0);

typedef enum Ir {
  IR_NOOP,
  IR_ILLEGAL,
  IR_LOAD,
  IR_STORE_IMM,
  IR_STORE_REG,
  IR_JCC,
  IR_ALU,
  IR_SYSCALL,
  IR_EXIT
} IR;

typedef enum Syscall {
  SYS_READ = 0,
  SYS_WRITE = 1
} SYSCALL;

typedef enum CmpFlag {
  CMP_MIN = 1,
  CMP_E = 1,
  CMP_A = 2,
  CMP_B = 4,
  CMP_MAX = 4
} CMPFLAG;

typedef enum Cond {
  COND_B = 1,
  COND_AE = 2,
  COND_E = 3,
  COND_NE = 4,
  COND_BE = 5,
  COND_A = 6
} COND;

typedef enum Alu {
  ALU_ADD = 0x0,
  ALU_SUB = 0x1,
  ALU_MUL = 0x2,
  ALU_DIV = 0x3,
  ALU_AND = 0x4,
  ALU_OR = 0x5,
  ALU_XOR = 0x6,
  ALU_SHR = 0x7,
  ALU_SHL = 0x8,
  ALU_MOV = 0x9,
  ALU_CMP = 0xa,
  ALU_MASK = 0xf,
  ALU_ADD_IMM = 0x80,
  ALU_SUB_IMM = 0x81,
  ALU_MUL_IMM = 0x82,
  ALU_DIV_IMM = 0x83,
  ALU_AND_IMM = 0x84,
  ALU_OR_IMM = 0x85,
  ALU_XOR_IMM = 0x86,
  ALU_SHR_IMM = 0x87,
  ALU_SHL_IMM = 0x88,
  ALU_MOV_IMM = 0x89,
  ALU_CMP_IMM = 0x8a
} ALU;

typedef struct IrInfo {
  IR ir;
  COND cond;
  ALU alu;
  bool check;
  bool concrete;
  uint8_t size;
  uint8_t readRegCnt;
  uint8_t writeRegCnt;
  uint8_t readReg[4];
  uint8_t writeReg[4];
  uint64_t imm;
  uint64_t addr;
  uint64_t pc;
} IRINFO;

#endif
