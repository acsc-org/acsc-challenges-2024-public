#include "compile.h"
#include "bb.h"

//It is possible to catch illegal memory access here, instead of directly aborting, we model it as an illegal ir
void rangeAnalysis(uint64_t irCnt, IRINFO *ir, BBINFO *thisBB) {
  VALRANGE regRange[REG_CNT];
  //NOTE: fetch the initial reg range from block startRegRange
  memcpy(regRange, thisBB->sRegRange, sizeof(regRange));
  for (uint64_t i = 0; i < irCnt; i++) {
    if (IR_MEM_ACCESS(ir[i].ir)) {
      if (ir[i].ir == IR_STORE_REG) {
        if (VAL_CHECK_CONCRETE(regRange[ir[i].readReg[1]])) {
          //PRECONDIION : readReg[1].val is known
          //
          //  STORE_REG              =>  STORE_IMM
          //    readReg = (R0, R1)   =>    readReg = (R0)
          //                         =>    imm = R1.val
          //    size = S             =>    size = S
          SETUP_IR(ir[i], IR_STORE_IMM, ir[i].pc, 1, 0);
          ir[i].imm = regRange[ir[i].readReg[1]].l;
        }
      }
      if (VAL_CHECK_CONCRETE(regRange[ir[i].readReg[0]])) {
        //PRECONDIION : readReg[0].val is known, (readReg[0].val, readReg[0].val + size) range is not legal addr
        //
        //  LOAD / STORE_IMM / STORE_REG  =>  ILLEGAL
        if (!LEGAL_ADDR(regRange[ir[i].readReg[0]].l, (uint64_t)ir[i].size)) goto ILLEGAL_IR;
        //PRECONDIION : readReg[0].val is known
        //
        //  LOAD                   =>  LOAD (!check, concrete)
        //    readReg = (R)        =>    readReg = ()
        //    writeReg = (W)       =>    writeReg = (W)
        //    size = S             =>    size = S
        //                         =>    addr = R.val
        //
        //  STORE_IMM              =>  STORE_IMM (!check, concrete)
        //    readReg = (R)        =>    readReg = ()
        //    imm = I              =>    imm = I
        //    size = S             =>    size = S
        //                         =>    addr = R.val
        //
        //  STORE_REG              =>  STORE_REG (!check, concrete)
        //    readReg = (R0, R1)   =>    readReg = (R1)
        //    size = S             =>    size = S
        //                         =>    addr = R0.val
        ir[i].check = false;
        ir[i].concrete = true;
        ir[i].addr = regRange[ir[i].readReg[0]].l;
        ir[i].readRegCnt -= 1;
        if (ir[i].ir == IR_STORE_REG) {
          ir[i].readReg[0] = ir[i].readReg[1];
        }
      } else if (
        LEGAL_ADDR(regRange[ir[i].readReg[0]].u, (uint64_t)ir[i].size) &&
        LEGAL_ADDR(regRange[ir[i].readReg[0]].l, regRange[ir[i].readReg[0]].u)
      ) {
        //PRECONDIION : readReg[0].val is not known, entire (readReg[0].l, readReg[0].u + size) range is legal addr
        //
        //  LOAD                   =>  LOAD (!check, !concrete)
        //    readReg = (R)        =>    readReg = (R)
        //    writeReg = (W)       =>    writeReg = (W)
        //    size = S             =>    size = S
        //
        //  STORE_IMM              =>  STORE_IMM (!check, !concrete)
        //    readReg = (R)        =>    readReg = (R)
        //    imm = I              =>    imm = I
        //    size = S             =>    size = S
        //
        //  STORE_REG              =>  STORE_REG (!check, !concrete)
        //    readReg = (R0, R1)   =>    readReg = (R0, R1)
        //    size = S             =>    size = S
        ir[i].check = false;
        ir[i].concrete = false;
      } else {
        //PRECONDIION : readReg[0].val is not known, do not know whether entire (readReg[0].l, readReg[0].u + size) range is legal addr or not
        //
        //  LOAD                   =>  LOAD (check, !concrete)
        //    readReg = (R)        =>    readReg = (R)
        //    writeReg = (W)       =>    writeReg = (W)
        //    size = S             =>    size = S
        //
        //  STORE_IMM              =>  STORE_IMM (check, !concrete)
        //    readReg = (R)        =>    readReg = (R)
        //    imm = I              =>    imm = I
        //    size = S             =>    size = S
        //
        //  STORE_REG              =>  STORE_REG (check, !concrete)
        //    readReg = (R0, R1)   =>    readReg = (R0, R1)
        //    size = S             =>    size = S
        ir[i].check = true;
        ir[i].concrete = false;
      }
      if (ir[i].ir == IR_LOAD) {
        //RANGE : writeReg[0] = [0, U(SIZE)_MAX]
        VAL_SET_FULL_RANGE(regRange[ir[i].writeReg[0]], ir[i].size);
      }
    } else if (ir[i].ir == IR_JCC) {
      if (VAL_CHECK_CONCRETE(regRange[ir[i].readReg[0]])) {
        //PRECONDIION : R.val is known
        //
        //  JCC                    =>  ALU (MOV_IMM)
        //    readReg = (R)        =>    readReg = ()
        //    writeReg = (W)       =>    writeReg = (W)
        //    imm = I              =>    imm = I if (C) else pc + 3
        //    cond = C             =>
        SETUP_IR(ir[i], IR_ALU, ir[i].pc, 0, 1);
        ir[i].alu = ALU_MOV_IMM;
        if (
          !((ir[i].cond == COND_A || ir[i].cond == COND_AE) && ((regRange[REG_FLAG].l & CMP_A) == CMP_A)) &&
          !((ir[i].cond == COND_B || ir[i].cond == COND_BE) && ((regRange[REG_FLAG].l & CMP_B) == CMP_B)) &&
          !((ir[i].cond == COND_E || ir[i].cond == COND_BE || ir[i].cond == COND_AE) && ((regRange[REG_FLAG].l & CMP_E) == CMP_E)) &&
          !((ir[i].cond == COND_NE) && ((regRange[REG_FLAG].l & CMP_E) != CMP_E))
        ) {
          ir[i].imm = ir[i].pc + 3;
        }
        //RANGE : writeReg[0] = [dst, dst]
        VAL_SET_CONCRETE(regRange[ir[i].writeReg[0]], ir[i].imm);
      } else {
        //RANGE : writeReg[0] = [MIN(dst0, dst1), MAX(dst0, dst1)]
        VAL_SET_RANGE(regRange[ir[i].writeReg[0]], MIN(ir[i].pc + 3, ir[i].imm), MAX(ir[i].pc + 3, ir[i].imm));
      }
    } else if (ir[i].ir == IR_ALU) {
      if (ir[i].alu == ALU_MOV_IMM) {
        //RANGE : writeReg[0] = [imm, imm]
        VAL_SET_CONCRETE(regRange[ir[i].writeReg[0]], ir[i].imm);
        continue;
      }
      VALRANGE v1, v2;
      v1 = regRange[ir[i].readReg[0]];
      if (ir[i].alu > ALU_MASK) {
        VAL_SET_CONCRETE(v2, ir[i].imm);
      } else {
        v2 = regRange[ir[i].readReg[1]];
      }
      switch(ir[i].alu & ALU_MASK) {
        case ALU_SUB:
          //NOTE: derive negative range so we can handle with addition
          uint64_t tmp;
          tmp = -v2.u;
          v2.u = -v2.l;
          v2.l = tmp;
          //fallthrough
        case ALU_ADD:
          if (v1.l + v2.l < v1.l) {
            //RANGE : RESULT = [v1.l + v2.l, v1.u + v2.u]  ##lower + lower overflows, so we're still dealing with a continuous range
            VAL_SET_RANGE(v1, v1.l + v2.l, v1.u + v2.u);
          } else if (v1.u + v2.u < v1.u) {
            //RANGE : RESULT = [0, U64_MAX]  ##lower + lower doesn't overflows while upper + upper does, so we're dealing with fractured range
            VAL_SET_FULL_RANGE(v1, sizeof(uint64_t));
          } else {
            //RANGE : RESULT = [v1.l + v2.l, v1.u + v2.u]  ##no overflows, continuous range
            VAL_SET_RANGE(v1, v1.l + v2.l, v1.u + v2.u);
          }
          break;
        case ALU_MUL:
          if (VAL_CHECK_CONCRETE(v1) && VAL_CHECK_CONCRETE(v2)) {
            //RANGE : RESULT.val = v1.val * v2.val  ##concrete args -> concrete res
            VAL_SET_CONCRETE(v1, v1.l * v2.l);
          } else if (v2.u == 0) {
            //RANGE : RESULT.val = 0  ##a * 0 = 0
            VAL_SET_CONCRETE(v1, 0);
          } else if (v1.u * v2.u / v2.u == v1.u) {
            //RANGE : RESULT = [v1.l * v2.l, v1.u * v2.u]  ##no overflows, can estimate continuous range
            VAL_SET_RANGE(v1, v1.l * v2.l, v1.u * v2.u)
          } else {
            //RANGE : RESULT = [0, U64_MAX]  ##non concrete overflows, give up
            VAL_SET_FULL_RANGE(v1, sizeof(uint64_t));
          }
          break;
        case ALU_DIV:
          //PRECONDITION: known v2.val, this is a known division by 0 here
          //  ALU (DIV)             =>  ILLEGAL
          if (VAL_CHECK_CONCRETE(v2) && v2.l == 0) goto ILLEGAL_IR;
          if (v2.l == 0) {
            //PRECONDITION: denominator might be 0, must proceed with care
            //  ALU (DIV)             =>  ALU (DIV check)
            ir[i].check = true;
            //RANGE : RESULT = [0, U64_MAX]  ##we can't estimate and afford this being optimized away due to concrete RESULT later
            VAL_SET_FULL_RANGE(v1, sizeof(uint64_t));
          } else {
            //PRECONDITION: denominator will not be 0, no need to check
            //  ALU (DIV)             =>  ALU (DIV !check)
            ir[i].check = false;
            //RANGE : RESULT = [v1.l / v2.u, v1.u / v2.l]
            VAL_SET_RANGE(v1, v1.l / v2.u, v1.u / v2.l);
          }
          break;
        case ALU_AND:
          if (VAL_CHECK_CONCRETE(v1) && VAL_CHECK_CONCRETE(v2)) {
            //RANGE : RESULT.val = v1.val & v2.val  ##concrete args -> concrete res
            VAL_SET_CONCRETE(v1, v1.l & v2.l);
          } else {
            //RANGE : RESULT = [0, MAX(v1.u, v2.u)]  ##a & b >= 0, a & b <= a, a & b < b
            VAL_SET_RANGE(v1, 0, MAX(v1.u, v2.u));
          }
          break;
        case ALU_OR:
          if (VAL_CHECK_CONCRETE(v1) && VAL_CHECK_CONCRETE(v2)) {
            //RANGE : RESULT.val = v1.val | v2.val  ##concrete args -> concrete res
            VAL_SET_CONCRETE(v1, v1.l | v2.l);
          } else {
            //RANGE : RESULT = [MIN(v1.l, v2.l), U64_MAX]  ##a | b >= a, a | b >= b
            VAL_SET_RANGE(v1, MIN(v1.l, v2.l), U64_MAX);
          }
          break;
        case ALU_XOR:
          if (VAL_CHECK_CONCRETE(v1) && VAL_CHECK_CONCRETE(v2)) {
            //RANGE : RESULT.val = v1.val ^ v2.val  ##concrete args -> concrete res
            VAL_SET_CONCRETE(v1, v1.l ^ v2.l);
          } else {
            //RANGE : RESULT = [0, U64_MAX]  ##give up analysis
            VAL_SET_FULL_RANGE(v1, sizeof(uint64_t));
          }
          break;
        case ALU_SHR:
          //NOTE: shr only takes 6 LSB (63), so we must update v2 range properly
          if ((v2.l >> 6) != (v2.u >> 6)) {
            //RANGE : v2 [v2.l & 0x3f, v2.u & 0x3f]  ##crosses boundary, fractured range
            VAL_SET_RANGE(v2, 0, 63);
          } else {
            //RANGE : v2 [v2.l & 0x3f, v2.u & 0x3f]  ##does not cross boundary, continuous range
            VAL_SET_RANGE(v2, v2.l & 0x3f, v2.u & 0x3f);
          }
          //RANGE : RESULT = [v1.l >> v2.u, v1.u >> v2.l]  ##a > b -> (a >> c) >= (b >> c), (c >> b) >= (c >> a)
          VAL_SET_RANGE(v1, v1.l >> v2.u, v1.u >> v2.l);
          break;
        case ALU_SHL:
          if (VAL_CHECK_CONCRETE(v1) && VAL_CHECK_CONCRETE(v2)) {
            //RANGE : RESULT.val = v1.val << (v2.val & 0x3f)  ##concrete args -> concrete res
            VAL_SET_CONCRETE(v1, v1.l << (v2.l & 0x3f));
          } else {
            //RANGE : RESULT = [0, U64_MAX]  ##shl has a lot more nuances compared to shr, given up would be easier
            VAL_SET_FULL_RANGE(v1, sizeof(uint64_t));
          }
          break;
        case ALU_MOV:
          //NOTE: This will not be ALU_MOV_IMM, which is already handled above
          //NOTE: ALU_MOV has rhs in readReg[0], so no need for further action
          break;
        case ALU_CMP:
          if (v1.l > v2.u) {
            //RANGE : RESULT = [CMP_A, CMP_A]  ##v1.u > v1.l > v2.u > v2.l
            VAL_SET_CONCRETE(v1, CMP_A);
          } else if (v1.u < v2.l) {
            //RANGE : RESULT = [CMP_B, CMP_B]  ##v1.l < v1.u < v2.l < v2.u
            VAL_SET_CONCRETE(v1, CMP_B);
          } else if (v1.l == v2.u && v1.u == v2.l) {
            //RANGE : RESULT = [CMP_B, CMP_B]  ##v1.u = v1.l = v2.u = v2.l
            VAL_SET_CONCRETE(v1, CMP_E);
          } else {
            //RANGE : RESULT = [CMP_MIN, CMP_MAX]  ##unknown compare res
            VAL_SET_RANGE(v1, CMP_MIN, CMP_MAX);
          }
          break;
      }
      if (VAL_CHECK_CONCRETE(v1)) {
        //PRECONDIION : RESULT.val is known
        //
        //  ALU (non IMM)          =>  ALU (MOV_IMM)
        //    readReg = (R0, R1?)  =>    readReg = ()
        //    writeReg = (W)       =>    writeReg = (W)
        //                         =>    imm = RESULT.val
        //
        //  ALU (IMM, non MOV_IMM) =>  ALU (MOV_IMM)
        //    readReg = (R)        =>    readReg = ()
        //    writeReg = (W)       =>    writeReg = (W)
        //                         =>    imm = RESULT.val
        SETUP_IR(ir[i], IR_ALU, ir[i].pc, 0, 1);
        ir[i].alu = ALU_MOV_IMM;
        ir[i].imm = v1.l;
      } else if (
        ir[i].alu != ALU_MOV && 
        ir[i].alu <= ALU_MASK &&
        VAL_CHECK_CONCRETE(regRange[ir[i].readReg[1]])
      ) {
        //PRECONDIION : R1.val is known
        //
        //  ALU (non IMM, non MOV) =>  ALU (matching IMM)
        //    readReg = (R0, R1)   =>    readReg = (R0)
        //    writeReg = (W)       =>    writeReg = (W)
        //                         =>    imm = R1.val
        SETUP_IR(ir[i], IR_ALU, ir[i].pc, 1, 1);
        ir[i].alu += ALU_ADD_IMM - ALU_ADD;
        ir[i].imm = regRange[ir[i].readReg[1]].l;
      }
      //RANGE : writeReg[0] = RESULT
      regRange[ir[i].writeReg[0]] = v1;
    } else if (ir[i].ir == IR_SYSCALL) {
      //RANGE : writeReg[0] = RESULT
      VAL_SET_FULL_RANGE(regRange[ir[i].writeReg[0]], sizeof(uint64_t));
    } else if (ir[i].ir == IR_EXIT || ir[i].ir == IR_NOOP) {
      //NOTE: no need for handling
    } else {
ILLEGAL_IR:
      ir[i].ir = IR_ILLEGAL;
      //RANGE : PC = [0, U64_MAX]  ##make pc unknown
      VAL_SET_FULL_RANGE(regRange[REG_PC], sizeof(uint64_t));
      break;
    }
  }
  //NOTE: update the final range anaysis result to block endRegRange
  memcpy(thisBB->eRegRange, regRange, sizeof(regRange));
  return;
}

void deadEliminate(uint64_t irCnt, IRINFO *ir, BBINFO *thisBB) {
  uint16_t written = 0;
  bool meaningfulIr;
  for (int64_t i = irCnt - 1; i >= 0; i--) {
    meaningfulIr = true;
    if (ir[i].ir == IR_LOAD || ir[i].ir == IR_ALU) {
      meaningfulIr = false;
      for (uint64_t j = 0; j < ir[i].writeRegCnt; j++) {
        if (((written >> ir[i].writeReg[j]) & 1) == 0) {
          meaningfulIr = true;
          break;
        }
      }
    }
    if (meaningfulIr) {
      for (uint64_t j = 0; j < ir[i].writeRegCnt; j++) {
        written |= (1 << ir[i].writeReg[j]);
      }
      for (uint64_t j = 0; j < ir[i].readRegCnt; j++) {
        written &= ~(1 << ir[i].readReg[j]);
      }
    } else {
      ir[i].ir = IR_NOOP;
    }
  }
  return;
}

void optimizeBB(CONTEXT *context, uint64_t irCnt, IRINFO *ir, BBINFO *thisBB) {
  rangeAnalysis(irCnt, ir, thisBB);
  deadEliminate(irCnt, ir, thisBB);
  return;
}

//NOTE: this function should jit the code, but since that is not the focus of the challenge, we chain functions instead to avoid misleading participants
void emitBB(CONTEXT *context, uint64_t irCnt, IRINFO *ir, BBINFO *thisBB) {
  uint64_t idx = 0;
  bool end = false;
  if (thisBB->op != NULL) {
    //NOTE: release previous op array if it exists, we don't need it anymore
    free(thisBB->op);
  }
  thisBB->opCnt = 0;
  //NOTE: count effective insns
  for (uint64_t i = 0; i < irCnt; i++) {
    if (ir[i].ir == IR_NOOP) continue;
    thisBB->opCnt += 1;
    //NOTE: while ILLEGAL means the irs after it would never be run, it is still necessary to run ILLEGAL itself, hence check after increment
    if (ir[i].ir == IR_ILLEGAL) break;
  }
  thisBB->op = malloc(sizeof(OPINFO) * thisBB->opCnt);
  if (thisBB->op == NULL) printError("emitBB::malloc failed");
  for (uint64_t i = 0; i < irCnt && !end; i++) {
    switch(ir[i].ir) {
      case IR_NOOP:
        break;
      case IR_ILLEGAL:
        //ILLEGAL                      =>  NONE
        thisBB->op[idx].op = opIllegal;
        idx++;
        end = true;
        break;
      case IR_LOAD:
        if (ir[i].concrete) {
          //LOAD (!check, concrete)      =>  R.arg0 = <arg2> [arg1]
          //  writeReg = (R)                 R        S      A
          //  size = S
          //  addr = A
          thisBB->op[idx].op = opLoadConcrete;
          thisBB->op[idx].arg[0] = ir[i].writeReg[0];
          thisBB->op[idx].arg[1] = ir[i].addr;
          thisBB->op[idx].arg[2] = ir[i].size;
        } else if (!ir[i].check){
          //LOAD (!check, !concrete)     =>  R.arg0 = <arg2> [R.arg1]
          //  readReg = (R)                  W        S      R
          //  writeReg = (W)
          //  size = S
          thisBB->op[idx].op = opLoadRegNoCheck;
          thisBB->op[idx].arg[0] = ir[i].writeReg[0];
          thisBB->op[idx].arg[1] = ir[i].readReg[0];
          thisBB->op[idx].arg[2] = ir[i].size;
        } else {
          //LOAD (check, !concrete)      =>  R.arg0 = <arg2> [R.arg1]
          //  readReg = (R)                  W        S      R
          //  writeReg = (W)
          //  size = S
          thisBB->op[idx].op = opLoadRegCheck;
          thisBB->op[idx].arg[0] = ir[i].writeReg[0];
          thisBB->op[idx].arg[1] = ir[i].readReg[0];
          thisBB->op[idx].arg[2] = ir[i].size;
        }
        idx++;
        break;
      case IR_STORE_IMM:
        if (ir[i].concrete) {
          //STORE_IMM (!check, concrete) =>  <arg2> [arg0] = arg1
          //  imm = I                        S      A        I
          //  size = S
          //  addr = A
          thisBB->op[idx].op = opStoreImmConcrete;
          thisBB->op[idx].arg[0] = ir[i].addr;
          thisBB->op[idx].arg[1] = ir[i].imm;
          thisBB->op[idx].arg[2] = ir[i].size;
        } else if (!ir[i].check){
          //STORE_IMM (!check, !concrete)=>  <arg2> [R.arg0] = arg1
          //  readReg = (R)                  S      R          I
          //  imm = I
          //  size = S
          thisBB->op[idx].op = opStoreImmRegNoCheck;
          thisBB->op[idx].arg[0] = ir[i].readReg[0];
          thisBB->op[idx].arg[1] = ir[i].imm;
          thisBB->op[idx].arg[2] = ir[i].size;
        } else {
          //STORE_IMM (check, !concrete) =>  <arg2> [R.arg0] = arg1
          //  readReg = (R)                  S      R          I
          //  imm = I
          //  size = S
          thisBB->op[idx].op = opStoreImmRegCheck;
          thisBB->op[idx].arg[0] = ir[i].readReg[0];
          thisBB->op[idx].arg[1] = ir[i].imm;
          thisBB->op[idx].arg[2] = ir[i].size;
        }
        idx++;
        break;
      case IR_STORE_REG:
        if (ir[i].concrete) {
          //STORE_REG (!check, concrete) =>  <arg2> [arg0] = R.arg1
          //  readReg = (R)                  S      A          R
          //  size = S
          //  addr = A
          thisBB->op[idx].op = opStoreRegConcrete;
          thisBB->op[idx].arg[0] = ir[i].addr;
          thisBB->op[idx].arg[1] = ir[i].readReg[0];
          thisBB->op[idx].arg[2] = ir[i].size;
        } else if (!ir[i].check){
          //STORE_REG (!check, !concrete)=>  <arg2> [R.arg0] = R.arg1
          //  readReg = (R0, R1)             S      R0         R1
          //  size = S
          thisBB->op[idx].op = opStoreRegRegNoCheck;
          thisBB->op[idx].arg[0] = ir[i].readReg[0];
          thisBB->op[idx].arg[1] = ir[i].readReg[1];
          thisBB->op[idx].arg[2] = ir[i].size;
        } else {
          //STORE_REG (check, !concrete) =>  <arg2> [R.arg0] = R.arg1
          //  readReg = (R0, R1)             S      R0         R1
          //  size = S
          thisBB->op[idx].op = opStoreRegRegCheck;
          thisBB->op[idx].arg[0] = ir[i].readReg[0];
          thisBB->op[idx].arg[1] = ir[i].readReg[1];
          thisBB->op[idx].arg[2] = ir[i].size;
        }
        idx++;
        break;
      case IR_JCC:
        //JCC                          =>  R.arg0 satisfy cond goto arg1 else arg2
        //  readReg = (R)                  R                        I         PC + 3
        //  writeReg = (W)
        //  imm = I
        //  cond = C
        switch(ir[i].cond) {
          case COND_A:
            thisBB->op[idx].op = opJmpA;
            break;
          case COND_AE:
            thisBB->op[idx].op = opJmpAE;
            break;
          case COND_E:
            thisBB->op[idx].op = opJmpE;
            break;
          case COND_NE:
            thisBB->op[idx].op = opJmpNE;
            break;
          case COND_B:
            thisBB->op[idx].op = opJmpB;
            break;
          case COND_BE:
            thisBB->op[idx].op = opJmpBE;
            break;
        }
        thisBB->op[idx].arg[0] = ir[i].readReg[0];
        thisBB->op[idx].arg[1] = ir[i].imm;
        thisBB->op[idx].arg[2] = ir[i].pc + 3;
        idx++;
        break;
      case IR_ALU:
        if (ir[i].alu == ALU_MOV) {
          //ALU (MOV)                    =>  R.arg0 = R.arg1
          //  readReg = (R)                  W        R
          //  writeReg = (W)
          thisBB->op[idx].op = opMovReg;
          thisBB->op[idx].arg[0] = ir[i].writeReg[0];
          thisBB->op[idx].arg[1] = ir[i].readReg[0];
        } else if (ir[i].alu == ALU_MOV_IMM) {
          //ALU (MOV_IMM)                =>  R.arg0 = arg1
          //  writeReg = (W)                 W        I
          //  imm = I
          thisBB->op[idx].op = opMovImm;
          thisBB->op[idx].arg[0] = ir[i].writeReg[0];
          thisBB->op[idx].arg[1] = ir[i].imm;
        } else {
          //ALU (non IMM, non MOV)       => R.arg0 = R.arg1 op R.arg2
          //  readReg = (R0, R1)            W        R0        R1
          //  writeReg = (W)
          //
          //ALU (IMM)                    => R.arg0 = R.arg1 op arg2
          //  readRegs = (R)                W        R         I
          //  writeRegs = (W)
          //  imm = I
          switch(ir[i].alu) {
            case ALU_ADD:
              thisBB->op[idx].op = opAddReg;
              break;
            case ALU_SUB:
              thisBB->op[idx].op = opSubReg;
              break;
            case ALU_MUL:
              thisBB->op[idx].op = opMulReg;
              break;
            case ALU_DIV:
              if (!ir[i].check) {
                thisBB->op[idx].op = opDivRegNoCheck;
              } else {
                thisBB->op[idx].op = opDivRegCheck;
              }
              break;
            case ALU_AND:
              thisBB->op[idx].op = opAndReg;
              break;
            case ALU_OR:
              thisBB->op[idx].op = opOrReg;
              break;
            case ALU_XOR:
              thisBB->op[idx].op = opXorReg;
              break;
            case ALU_SHR:
              thisBB->op[idx].op = opShrReg;
              break;
            case ALU_SHL:
              thisBB->op[idx].op = opShlReg;
              break;
            case ALU_CMP:
              thisBB->op[idx].op = opCmpReg;
              break;
            case ALU_ADD_IMM:
              thisBB->op[idx].op = opAddImm;
              break;
            case ALU_SUB_IMM:
              thisBB->op[idx].op = opSubImm;
              break;
            case ALU_MUL_IMM:
              thisBB->op[idx].op = opMulImm;
              break;
            case ALU_DIV_IMM:
              thisBB->op[idx].op = opDivImm;
              break;
            case ALU_AND_IMM:
              thisBB->op[idx].op = opAndImm;
              break;
            case ALU_OR_IMM:
              thisBB->op[idx].op = opOrImm;
              break;
            case ALU_XOR_IMM:
              thisBB->op[idx].op = opXorImm;
              break;
            case ALU_SHR_IMM:
              thisBB->op[idx].op = opShrImm;
              break;
            case ALU_SHL_IMM:
              thisBB->op[idx].op = opShlImm;
              break;
            case ALU_CMP_IMM:
              thisBB->op[idx].op = opCmpImm;
              break;
            default:
              break;
          }
          thisBB->op[idx].arg[0] = ir[i].writeReg[0];
          thisBB->op[idx].arg[1] = ir[i].readReg[0];
          if (ir[i].alu <= ALU_MASK) {
            thisBB->op[idx].arg[2] = ir[i].readReg[1];
          } else {
            thisBB->op[idx].arg[2] = ir[i].imm;
          }
        }
        idx++;
        break;
      case IR_SYSCALL:
        //SYSCALL                      =>  R.arg0 = syscall[R.arg1](R.arg2, R.arg3, R.arg4)
        //  readReg = (R0, R1, R2 ,R3)     W                R0      R1      R2      R3
        //  writeReg = (W)
        thisBB->op[idx].op = opSyscall;
        thisBB->op[idx].arg[0] = ir[i].writeReg[0];
        thisBB->op[idx].arg[1] = ir[i].readReg[0];
        thisBB->op[idx].arg[2] = ir[i].readReg[1];
        thisBB->op[idx].arg[3] = ir[i].readReg[2];
        thisBB->op[idx].arg[4] = ir[i].readReg[3];
        idx++;
        break;
      case IR_EXIT:
        //EXIT                         =>  NONE
        thisBB->op[idx].op = opExit;
        idx++;
        break;
    }
  }
  return;
}

void compileBB(CONTEXT *context, BBINFO *thisBB) {
  IRINFO ir[BB_MAX_IR];
  uint64_t irCnt = 0;
  uint64_t pc = context->regs[REG_PC];
  bool endBlock = false;
  while (!endBlock && irCnt < BB_MAX_IR - MAX_INSN_IR) {
    irCnt += parseInsn(context, ir, irCnt, &pc, &endBlock);
  }
  if (!endBlock) {
    //ir[0] : ALU (MOV_IMM)
    //          writeReg = (PC)
    //          imm = pc
    SETUP_IR(ir[irCnt], IR_ALU, ir[irCnt - 1].pc, 0, 1); //mov pc, next_block
    ir[irCnt].alu = ALU_MOV_IMM;
    ir[irCnt].imm = pc;
    ir[irCnt].writeReg[0] = REG_PC;
    irCnt += 1;
  }
  optimizeBB(context, irCnt, ir, thisBB);
  emitBB(context, irCnt, ir, thisBB);
  thisBB->version += 1;
  return;
}

bool mergeRegRange(CONTEXT *context, BBINFO *thisBB) {
  bool shouldRecompile = false;
  for (uint64_t i = 0; i < REG_CNT; i++) {
    if (
      thisBB->sRegRange[i].l > context->prevBB->eRegRange[i].l ||
      thisBB->sRegRange[i].u < context->prevBB->eRegRange[i].u
    ) {
      shouldRecompile = true;
      thisBB->sRegRangeChangeCnt[i] += 1;
      if (thisBB->sRegRangeChangeCnt[i] >= MAX_RELAX_TOLERANCE) {
        //NOTE: starting range of the register is too unpredictable, give up optimizing w.r.t. to it
        VAL_SET_FULL_RANGE(thisBB->sRegRange[i], sizeof(uint64_t));
      } else {
        //NOTE: expand the possible range of each register before recompiling
        uint64_t rl = MIN(thisBB->sRegRange[i].l, context->prevBB->eRegRange[i].l);
        uint64_t ru = MAX(thisBB->sRegRange[i].u, context->prevBB->eRegRange[i].u);
        thisBB->sRegRange[i].l = rl;
        thisBB->sRegRange[i].u = ru;
      }
    }
  }
  return shouldRecompile;
}
