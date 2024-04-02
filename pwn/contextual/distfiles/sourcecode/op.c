#include "op.h"

bool opIllegal(CONTEXT *context, uint64_t *arg) {
  context->status = VM_ILLEGAL;
  return false;
}

bool opLoadConcrete(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = <arg2> [arg1]
  context->regs[arg[0]] = 0;
  memcpy(&context->regs[arg[0]], &context->memory[arg[1]], arg[2]);
  return true;
}

bool opLoadRegNoCheck(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = <arg2> [R.arg1]
  context->regs[arg[0]] = 0;
  memcpy(&context->regs[arg[0]], &context->memory[context->regs[arg[1]]], arg[2]);
  return true;
}

bool opLoadRegCheck(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = <arg2> [R.arg1]
  if (!LEGAL_ADDR(context->regs[arg[1]], arg[2])) {
    context->status = VM_ILLEGAL;
    return false;
  } else {
    context->regs[arg[0]] = 0;
    memcpy(&context->regs[arg[0]], &context->memory[context->regs[arg[1]]], arg[2]);
    return true;
  }
}

bool opStoreImmConcrete(CONTEXT *context, uint64_t *arg) {
  //<arg2> [arg0] = arg1
  memcpy(&context->memory[arg[0]], &arg[1], arg[2]);
  return true;
}

bool opStoreImmRegNoCheck(CONTEXT *context, uint64_t *arg) {
  //<arg2> [R.arg0] = arg1
  memcpy(&context->memory[context->regs[arg[0]]], &arg[1], arg[2]);
  return true;
}

bool opStoreImmRegCheck(CONTEXT *context, uint64_t *arg) {
  //<arg2> [R.arg0] = arg1
  if (!LEGAL_ADDR(context->regs[arg[0]], arg[2])) {
    context->status = VM_ILLEGAL;
    return false;
  } else {
    memcpy(&context->memory[context->regs[arg[0]]], &arg[1], arg[2]);
    return true;
  }
}

bool opStoreRegConcrete(CONTEXT *context, uint64_t *arg) {
  //<arg2> [arg0] = R.arg1
  memcpy(&context->memory[arg[0]], &context->regs[arg[1]], arg[2]);
  return true;
}

bool opStoreRegRegNoCheck(CONTEXT *context, uint64_t *arg) {
  //<arg2> [R.arg0] = R.arg1
  memcpy(&context->memory[context->regs[arg[0]]], &context->regs[arg[1]], arg[2]);
  return true;
}

bool opStoreRegRegCheck(CONTEXT *context, uint64_t *arg) {
  //<arg2> [R.arg0] = R.arg1
  if (!LEGAL_ADDR(context->regs[arg[0]], arg[2])) {
    context->status = VM_ILLEGAL;
    return false;
  } else {
    memcpy(&context->memory[context->regs[arg[0]]], &context->regs[arg[1]], arg[2]);
    return true;
  }
}

bool opJmpA(CONTEXT *context, uint64_t *arg) {
  //R.arg0 satisfy A goto arg1 else arg2
  if ((context->regs[arg[0]] & CMP_A) != 0) {
    context->regs[REG_PC] = arg[1];
  } else {
    context->regs[REG_PC] = arg[2];
  }
  return true;
}

bool opJmpAE(CONTEXT *context, uint64_t *arg) {
  //R.arg0 satisfy AE goto arg1 else arg2
  if ((context->regs[arg[0]] & (CMP_A | CMP_E)) != 0) {
    context->regs[REG_PC] = arg[1];
  } else {
    context->regs[REG_PC] = arg[2];
  }
  return true;
}

bool opJmpE(CONTEXT *context, uint64_t *arg) {
  //R.arg0 satisfy E goto arg1 else arg2
  if ((context->regs[arg[0]] & (CMP_E)) != 0) {
    context->regs[REG_PC] = arg[1];
  } else {
    context->regs[REG_PC] = arg[2];
  }
  return true;
}

bool opJmpNE(CONTEXT *context, uint64_t *arg) {
  //R.arg0 satisfy NE goto arg1 else arg2
  if ((context->regs[arg[0]] & (CMP_E)) == 0) {
    context->regs[REG_PC] = arg[1];
  } else {
    context->regs[REG_PC] = arg[2];
  }
  return true;
}

bool opJmpB(CONTEXT *context, uint64_t *arg) {
  //R.arg0 satisfy B goto arg1 else arg2
  if ((context->regs[arg[0]] & CMP_B) != 0) {
    context->regs[REG_PC] = arg[1];
  } else {
    context->regs[REG_PC] = arg[2];
  }
  return true;
}

bool opJmpBE(CONTEXT *context, uint64_t *arg) {
  //R.arg0 satisfy BE goto arg1 else arg2
  if ((context->regs[arg[0]] & (CMP_B | CMP_E)) != 0) {
    context->regs[REG_PC] = arg[1];
  } else {
    context->regs[REG_PC] = arg[2];
  }
  return true;
}

bool opAddImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 + arg2
  context->regs[arg[0]] = context->regs[arg[1]] + arg[2];
  return true;
}

bool opSubImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 - arg2
  context->regs[arg[0]] = context->regs[arg[1]] - arg[2];
  return true;
}

bool opMulImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 * arg2
  context->regs[arg[0]] = context->regs[arg[1]] * arg[2];
  return true;
}

bool opDivImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 / arg2
  context->regs[arg[0]] = context->regs[arg[1]] / arg[2];
  return true;
}

bool opAndImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 & arg2
  context->regs[arg[0]] = context->regs[arg[1]] & arg[2];
  return true;
}

bool opOrImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 | arg2
  context->regs[arg[0]] = context->regs[arg[1]] | arg[2];
  return true;
}

bool opXorImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 ^ arg2
  context->regs[arg[0]] = context->regs[arg[1]] ^ arg[2];
  return true;
}

bool opShrImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 >> arg2
  context->regs[arg[0]] = context->regs[arg[1]] >> arg[2];
  return true;
}

bool opShlImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 << arg2
  context->regs[arg[0]] = context->regs[arg[1]] << arg[2];
  return true;
}

bool opMovImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = arg1
  context->regs[arg[0]] = arg[1];
  return true;
}

bool opCmpImm(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = CMP<R.arg1, arg2>
  if (context->regs[arg[1]] > arg[2]) {
    context->regs[arg[0]] = CMP_A;
  } else if (context->regs[arg[1]] < arg[2]) {
    context->regs[arg[0]] = CMP_B;
  } else {
    context->regs[arg[0]] = CMP_E;
  }
  return true;
}

bool opAddReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 + R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] + context->regs[arg[2]];
  return true;
}

bool opSubReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 - R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] - context->regs[arg[2]];
  return true;
}

bool opMulReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 * R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] * context->regs[arg[2]];
  return true;
}

bool opDivRegNoCheck(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 / R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] / context->regs[arg[2]];
  return true;
}

bool opDivRegCheck(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 / R.arg2
  if (context->regs[arg[2]] == 0) {
    context->status = VM_ILLEGAL;
    return false;
  } else {
    context->regs[arg[0]] = context->regs[arg[1]] / context->regs[arg[2]];
    return true;
  }
}

bool opAndReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 & R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] & context->regs[arg[2]];
  return true;
}

bool opOrReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 | R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] | context->regs[arg[2]];
  return true;
}

bool opXorReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 ^ R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] ^ context->regs[arg[2]];
  return true;
}

bool opShrReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 >> R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] >> context->regs[arg[2]];
  return true;
}

bool opShlReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1 << R.arg2
  context->regs[arg[0]] = context->regs[arg[1]] << context->regs[arg[2]];
  return true;
}

bool opMovReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = R.arg1
  context->regs[arg[0]] = context->regs[arg[1]];
  return true;
}

bool opCmpReg(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = CMP<R.arg1, R.arg2>
  if (context->regs[arg[1]] > context->regs[arg[2]]) {
    context->regs[arg[0]] = CMP_A;
  } else if (context->regs[arg[1]] < context->regs[arg[2]]) {
    context->regs[arg[0]] = CMP_B;
  } else {
    context->regs[arg[0]] = CMP_E;
  }
  return true;
}

bool opSyscall(CONTEXT *context, uint64_t *arg) {
  //R.arg0 = syscall[R.arg1](R.arg2, R.arg3, R.arg4)
  uint8_t *cursor;
  uint64_t remain;
  int cnt;
  switch(context->regs[arg[1]]) {
    case SYS_READ:
    case SYS_WRITE:
      if (
        (context->regs[arg[1]] == SYS_READ && context->regs[arg[2]] != STDIN_FILENO) ||
        (context->regs[arg[1]] == SYS_WRITE && context->regs[arg[2]] != STDOUT_FILENO) ||
        !LEGAL_ADDR(context->regs[arg[3]], context->regs[arg[4]])
      ) {
        context->regs[arg[0]] = U64_MAX;
      } else {
        cursor = &context->memory[context->regs[arg[3]]];
        remain = context->regs[arg[4]];
        while (remain > 0) {
          if (context->regs[arg[1]] == SYS_READ) {
            cnt = read(context->regs[arg[2]], cursor, remain);
          } else {
            cnt = write(context->regs[arg[2]], cursor, remain);
          }
          if (cnt <= 0) {
            break;
          }
          cursor += cnt;
          remain -= cnt;
        }
        context->regs[arg[0]] = context->regs[arg[4]] - remain;
      }
      break;
    default:
      context->regs[arg[0]] = U64_MAX;
  }
  return true;
}

bool opExit(CONTEXT *context, uint64_t *arg) {
  context->status = VM_EXIT;
  return true;
}
