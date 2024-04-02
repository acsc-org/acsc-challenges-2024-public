#ifndef __BB_HEADER__
#define __BB_HEADER__

#include "util.h"
#include "ir.h"
#include "op.h"
#include "compile.h"
#include "vm.h"

#define BB_MAX_IR 0x200

typedef struct BasicBlockVersion {
  uint64_t pc;
  uint8_t version;
} BBVERSION;

typedef struct BasicBlockInfo {
  uint64_t pc;
  uint8_t version;
  uint8_t sRegRangeChangeCnt[REG_CNT];
  VEC prevVersion;
  VALRANGE sRegRange[REG_CNT];
  VALRANGE eRegRange[REG_CNT];
  uint64_t opCnt;
  OPINFO *op;
} BBINFO;

bool lookupBBCmpFunc(void *_bb, void *_pc);
BBINFO *lookupBB(CONTEXT *context, uint64_t pc);
BBINFO *getBB(CONTEXT *context, uint64_t idx);
void insertBB(CONTEXT *context, BBINFO *bb);
BBVERSION *createBBVersion(BBINFO *bb);
bool lookupBBVersionCmpFunc(void *_bbVersion, void *_pc);
BBVERSION *lookupBBVersion(BBINFO *bb, uint64_t pc);
void insertBBVersion(BBINFO *bb, BBINFO *prevBB);
BBINFO *createBB(CONTEXT *context);
void destructBB(BBINFO *bb);
void runBB(CONTEXT *context, BBINFO *thisBB);

#endif
