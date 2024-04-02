#ifndef __DEBUG_HEADER__
#define __DEBUG_HEADER__

struct ValRange;

#include "util.h"
#include "ir.h"
#include "vm.h"

void debugRegState(uint64_t *reg);
void debugRegRange(struct ValRange* regRange);
void debugIr(IRINFO *ir, bool optimized);

#endif
