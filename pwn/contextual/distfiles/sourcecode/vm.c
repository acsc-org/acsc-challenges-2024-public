#include "vm.h"
#include "bb.h"
#include "compile.h"

void setupVM(CONTEXT *context, uint8_t *code, uint64_t codeLen) {
  context->status = VM_NEXT;
  setupVec(&context->bb);
  memcpy(context->code, code, codeLen);
  memset(&context->code[codeLen], 0, CODE_SIZE - codeLen);
  memset(context->memory, 0, MEMORY_SIZE);
  memcpy(&context->memory[CODE_SEG_ADDR], context->code, CODE_SIZE);
  memset(context->regs, 0, sizeof(context->regs));
  context->regs[REG_PC] = CODE_SEG_ADDR;
  context->regs[REG_LR] = U64_MAX;
  context->regs[REG_SP] = STACK_SEG_ADDR + STACK_SIZE;
  context->regs[REG_BP] = STACK_SEG_ADDR + STACK_SIZE;
  context->prevBB = NULL;
  return;
}

void clearVM(CONTEXT *context) {
  for (uint64_t i = 0; i < context->bb.len; i++) {
    destructBB(getBB(context, i));
  }
  clearVec(&context->bb);
  return;
}

void runVM(CONTEXT *context) {
  bool shouldRecompile;
  while (context->status == VM_NEXT) {
    if (context->regs[REG_PC] < CODE_SEG_ADDR || context->regs[REG_PC] >= CODE_SEG_ADDR + CODE_SIZE) {
      context->status = VM_ILLEGAL;
      break;
    }
    shouldRecompile = false;
    BBINFO *thisBB = lookupBB(context, context->regs[REG_PC]);
    if (thisBB == NULL) {
      //NOTE: The insertion of context->prevBB (if it exists) is handled while creatingBB, so no need to merge or whatever
      thisBB = createBB(context);
      compileBB(context, thisBB);
      insertBB(context, thisBB);
    } else {
      BBVERSION *prevVersion = lookupBBVersion(thisBB, context->prevBB->pc);
      //NOTE: context->prevBB cannot be NULL except for first block, which will be handled above
      if (prevVersion == NULL || prevVersion->version != context->prevBB->version) {
        //NOTE: previous optimization basis has changed, check if any range assumptions have been broken
        shouldRecompile = mergeRegRange(context, thisBB);
        if (prevVersion == NULL) {
          insertBBVersion(thisBB, context->prevBB);
        } else {
          prevVersion->version = context->prevBB->version;
        }
      }
      if (shouldRecompile) {
        compileBB(context, thisBB);
      }
    }
    runBB(context, thisBB);
  }
  return;
}

