#include "bb.h"

bool lookupBBCmpFunc(void *_bb, void *_pc) {
  BBINFO *bb = *((BBINFO**)_bb);
  uint64_t pc = (uint64_t)_pc;
  return bb->pc == pc;
}

BBINFO *lookupBB(CONTEXT *context, uint64_t pc) {
  BBINFO **ptr = (BBINFO**)lookupVec(&context->bb, sizeof(BBINFO*), (void*)pc, lookupBBCmpFunc);
  if (ptr == NULL) return NULL;
  return *ptr;
}

BBINFO *getBB(CONTEXT *context, uint64_t idx) {
  BBINFO **ptr = (BBINFO**)getVec(&context->bb, sizeof(BBINFO*), idx);
  if (ptr == NULL) return NULL;
  return *ptr;
}

void insertBB(CONTEXT *context, BBINFO *bb) {
  insertVec(&context->bb, sizeof(BBINFO*), (void*)&bb);
  return;
}

BBVERSION *createBBVersion(BBINFO *bb) {
  BBVERSION *bbVersion = malloc(sizeof(BBVERSION));
  if (bbVersion == NULL) printError("createBBVersion::malloc failed");
  bbVersion->pc = bb->pc;
  bbVersion->version = bb->version;
  return bbVersion;
}

bool lookupBBVersionCmpFunc(void *_bbVersion, void *_pc) {
  BBVERSION *bbVersion = (BBVERSION*)_bbVersion;
  uint64_t pc = (uint64_t)_pc;
  return bbVersion->pc == pc;
}

BBVERSION *lookupBBVersion(BBINFO *bb, uint64_t pc) {
  return (BBVERSION*)lookupVec(&bb->prevVersion, sizeof(BBVERSION), (void*)pc, lookupBBVersionCmpFunc);
}

void insertBBVersion(BBINFO *bb, BBINFO *prevBB) {
  BBVERSION *bbVersion = createBBVersion(prevBB);
  insertVec(&bb->prevVersion, sizeof(BBVERSION), (void*)bbVersion);
  return;
}

BBINFO *createBB(CONTEXT *context) {
  BBINFO *bb = malloc(sizeof(BBINFO));
  memset(bb, 0, sizeof(BBINFO));
  bb->pc = context->regs[REG_PC];
  setupVec(&bb->prevVersion);
  bb->op = NULL;
  if (context->prevBB != NULL) {
    insertBBVersion(bb, context->prevBB);
    memcpy(bb->sRegRange, context->prevBB->eRegRange, sizeof(bb->sRegRange));
  } else {
    //NOTE: this is the entrypoint, setup states to reflect context
    for (uint64_t i = 0; i < REG_CNT; i++) {
      VAL_SET_CONCRETE(bb->sRegRange[i], context->regs[i]);
    }
  }
  return bb;
}

void destructBB(BBINFO *bb) {
  clearVec(&bb->prevVersion);
  free(bb->op);
  free(bb);
  return;
}

void runBB(CONTEXT *context, BBINFO *thisBB) {
  for (uint64_t i = 0; i < thisBB->opCnt && thisBB->op[i].op(context, thisBB->op[i].arg); i++) {}
  context->prevBB = thisBB;
  return;
}
