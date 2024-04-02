#ifndef __COMPILE_HEADER__
#define __COMPILE_HEADER__

struct BasicBlockInfo;

#include "util.h"
#include "ir.h"
#include "op.h"
#include "insn.h"
#include "vm.h"
#include "debug.h"

#define MAX_RELAX_TOLERANCE 20

#define VAL_CHECK_CONCRETE(regrange) ((regrange).l == (regrange).u)

#define VAL_SET_RANGE(regrange, _l, _u) do { \
  uint64_t rl = (_l); \
  uint64_t ru = (_u); \
  (regrange).l = rl; \
  (regrange).u = ru; \
} while (0);

#define VAL_SET_CONCRETE(regrange, val) do { \
  VAL_SET_RANGE(regrange, val, val); \
} while (0);

#define VAL_SET_FULL_RANGE(regrange, size) do { \
  VAL_SET_RANGE(regrange, 0, ((size) == 8 ? U64_MAX : (1ULL << ((size) * 8)) - 1)); \
} while (0);

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef struct ValRange {
  uint64_t l;
  uint64_t u;
} VALRANGE;

void rangeAnalysis(uint64_t irCnt, IRINFO *ir, struct BasicBlockInfo *thisBB);
void deadEliminate(uint64_t irCnt, IRINFO *ir, struct BasicBlockInfo *thisBB);
void optimizeBB(CONTEXT *context, uint64_t irCnt, IRINFO *ir, struct BasicBlockInfo *thisBB);
void emitBB(CONTEXT *context, uint64_t irCnt, IRINFO *ir, struct BasicBlockInfo *thisBB);
void compileBB(CONTEXT *context, struct BasicBlockInfo *thisBB);
bool mergeRegRange(CONTEXT *context, struct BasicBlockInfo *thisBB);
void runBB(CONTEXT *context, struct BasicBlockInfo *thisBB);


#endif
