#ifndef __OP_HEADER__
#define __OP_HEADER__

#include "util.h"
#include "ir.h"
#include "vm.h"

typedef struct OpInfo {
  bool (*op)(CONTEXT *context, uint64_t *arg);
  uint64_t arg[5];
} OPINFO;

bool opIllegal(CONTEXT *context, uint64_t *arg);
bool opLoadConcrete(CONTEXT *context, uint64_t *arg);
bool opLoadRegNoCheck(CONTEXT *context, uint64_t *arg);
bool opLoadRegCheck(CONTEXT *context, uint64_t *arg);
bool opStoreImmConcrete(CONTEXT *context, uint64_t *arg);
bool opStoreImmRegNoCheck(CONTEXT *context, uint64_t *arg);
bool opStoreImmRegCheck(CONTEXT *context, uint64_t *arg);
bool opStoreRegConcrete(CONTEXT *context, uint64_t *arg);
bool opStoreRegRegNoCheck(CONTEXT *context, uint64_t *arg);
bool opStoreRegRegCheck(CONTEXT *context, uint64_t *arg);
bool opJmpA(CONTEXT *context, uint64_t *arg);
bool opJmpAE(CONTEXT *context, uint64_t *arg);
bool opJmpE(CONTEXT *context, uint64_t *arg);
bool opJmpNE(CONTEXT *context, uint64_t *arg);
bool opJmpB(CONTEXT *context, uint64_t *arg);
bool opJmpBE(CONTEXT *context, uint64_t *arg);
bool opAddImm(CONTEXT *context, uint64_t *arg);
bool opSubImm(CONTEXT *context, uint64_t *arg);
bool opMulImm(CONTEXT *context, uint64_t *arg);
bool opDivImm(CONTEXT *context, uint64_t *arg);
bool opAndImm(CONTEXT *context, uint64_t *arg);
bool opOrImm(CONTEXT *context, uint64_t *arg);
bool opXorImm(CONTEXT *context, uint64_t *arg);
bool opShrImm(CONTEXT *context, uint64_t *arg);
bool opShlImm(CONTEXT *context, uint64_t *arg);
bool opMovImm(CONTEXT *context, uint64_t *arg);
bool opCmpImm(CONTEXT *context, uint64_t *arg);
bool opAddReg(CONTEXT *context, uint64_t *arg);
bool opSubReg(CONTEXT *context, uint64_t *arg);
bool opMulReg(CONTEXT *context, uint64_t *arg);
bool opDivRegNoCheck(CONTEXT *context, uint64_t *arg);
bool opDivRegCheck(CONTEXT *context, uint64_t *arg);
bool opAndReg(CONTEXT *context, uint64_t *arg);
bool opOrReg(CONTEXT *context, uint64_t *arg);
bool opXorReg(CONTEXT *context, uint64_t *arg);
bool opShrReg(CONTEXT *context, uint64_t *arg);
bool opShlReg(CONTEXT *context, uint64_t *arg);
bool opMovReg(CONTEXT *context, uint64_t *arg);
bool opCmpReg(CONTEXT *context, uint64_t *arg);
bool opSyscall(CONTEXT *context, uint64_t *arg);
bool opExit(CONTEXT *context, uint64_t *arg);

#endif
