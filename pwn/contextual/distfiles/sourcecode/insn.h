#ifndef __INSN_HEADER__
#define __INSN_HEADER__

#include "util.h"
#include "ir.h"
#include "vm.h"

#define MAX_INSN_IR 7
#define GET_IMM_SIZE(opcode) (((opcode) & 0x7) + 1)
#define LEGAL_REG1(regs) ((((regs) & 0xf) != REG_PC) && (((regs) & 0xf) != REG_LR))
#define LEGAL_REG2(regs) ((((regs) >> 4) != REG_PC) && (((regs) >> 4) != REG_LR))

uint64_t parseInsn(CONTEXT *context, IRINFO *ir, uint64_t irCnt, uint64_t *pc, bool *endBlock);

#endif
