#include "insn.h"

bool getCode(CONTEXT *context, uint64_t addr, uint64_t size, uint8_t *dst) {
  if (addr < CODE_SEG_ADDR || addr > CODE_SEG_ADDR + CODE_SIZE || size > CODE_SIZE || addr + size > CODE_SEG_ADDR + CODE_SIZE) return false;
  memcpy(dst, &context->code[addr - CODE_SEG_ADDR], size);
  return true;
}

uint64_t parseInsn(CONTEXT *context, IRINFO *ir, uint64_t irCnt, uint64_t *pc, bool *endBlock) {
  uint8_t opcode, immSize, regs, irIncrement = 1;
  uint64_t imm = 0;
  SETUP_IR(ir[irCnt], IR_ILLEGAL, *pc, 0, 0);
  if (!getCode(context, *pc, 1, &opcode)) {
    opcode = 0;
  }
  if (opcode < 0x08) { //illegal
    //ir[0] : ILLEGAL
    *pc += 1;
  } else if (opcode < 0x10) { //push imm
    immSize = GET_IMM_SIZE(opcode);
    if (getCode(context, *pc + 1, immSize, (uint8_t*)&imm)) {
      //ir[0] : ALU (SUB_IMM)
      //          readReg = (SP)
      //          writeReg = (SP)
      //          imm = immSize
      //ir[1] : STORE_IMM
      //          readReg = (SP)
      //          imm = imm
      //          size = immSize
      SETUP_IR(ir[irCnt], IR_ALU, *pc, 1, 1); //sub sp, size
      ir[irCnt].alu = ALU_SUB_IMM;
      ir[irCnt].readReg[0] = REG_SP;
      ir[irCnt].writeReg[0] = REG_SP;
      ir[irCnt].imm = immSize;
      SETUP_IR(ir[irCnt + 1], IR_STORE_IMM, *pc, 1, 0); //store <size> [sp], imm
      ir[irCnt + 1].readReg[0] = REG_SP;
      ir[irCnt + 1].size = immSize;
      ir[irCnt + 1].imm = imm;
      irIncrement = 2;
    }
    *pc += 1 + immSize;
  } else if (opcode < 0x18) { //pop
    if (getCode(context, *pc + 1, 1, (uint8_t*)&regs) && LEGAL_REG1(regs)) {
      //ir[0] : LOAD
      //          readReg = (SP)
      //          writeReg = (R[0])
      //          size = immSize
      //ir[1] : ALU (ADD_IMM)
      //          readRegs = (SP)
      //          writeRegs = (SP)
      //          imm = immSize
      SETUP_IR(ir[irCnt], IR_LOAD, *pc, 1, 1); //load <size> reg, [sp]
      ir[irCnt].readReg[0] = REG_SP;
      ir[irCnt].writeReg[0] = regs & 0xf;
      ir[irCnt].size = GET_IMM_SIZE(opcode);
      SETUP_IR(ir[irCnt + 1], IR_ALU, *pc, 1, 1); //add sp, size
      ir[irCnt + 1].alu = ALU_ADD_IMM;
      ir[irCnt + 1].readReg[0] = REG_SP;
      ir[irCnt + 1].writeReg[0] = REG_SP;
      ir[irCnt + 1].imm = ir[irCnt].size;
      irIncrement = 2;
    }
    *pc += 2;
  } else if (opcode < 0x20) { //push reg
    if (getCode(context, *pc + 1, 1, (uint8_t*)&regs) && LEGAL_REG1(regs)) {
      //ir[0] : ALU (SUB_IMM)
      //          readReg = (SP)
      //          writeReg = (SP)
      //          imm = immSize
      //ir[1] : STORE_REG
      //          readReg = (SP, R[0])
      //          size = immSize
      SETUP_IR(ir[irCnt], IR_ALU, *pc, 1, 1); //sub sp, size
      ir[irCnt].alu = ALU_SUB_IMM;
      ir[irCnt].readReg[0] = REG_SP;
      ir[irCnt].writeReg[0] = REG_SP;
      ir[irCnt].imm = GET_IMM_SIZE(opcode);
      SETUP_IR(ir[irCnt + 1], IR_STORE_REG, *pc, 2, 0); //store <size> [sp], reg
      ir[irCnt + 1].readReg[0] = REG_SP;
      ir[irCnt + 1].readReg[1] = regs & 0xf;
      ir[irCnt + 1].size = ir[irCnt].imm;
      irIncrement = 2;
    }
    *pc += 2;
  } else if (opcode < 0x28) { //load mem
    if (getCode(context, *pc + 1, 1, (uint8_t*)&regs) && LEGAL_REG1(regs) && LEGAL_REG2(regs)) {
      //ir[0] : LOAD
      //          readReg = (R[1])
      //          writeReg = (R[0])
      //          size = immSize
      SETUP_IR(ir[irCnt], IR_LOAD, *pc, 1, 1); //load <size> reg1, [reg2]
      ir[irCnt].readReg[0] = regs >> 4;
      ir[irCnt].writeReg[0] = regs & 0xf;
      ir[irCnt].size = GET_IMM_SIZE(opcode);
    }
    *pc += 2;
  } else if (opcode < 0x30) { //store reg
    if (getCode(context, *pc + 1, 1, (uint8_t*)&regs) && LEGAL_REG1(regs) && LEGAL_REG2(regs)) {
      //ir[0] : STORE_REG
      //          readReg = (R[0], R[1])
      //          size = immSize
      SETUP_IR(ir[irCnt], IR_STORE_REG, *pc, 2, 0); //store <size> [reg1], reg2
      ir[irCnt].readReg[0] = regs & 0xf;
      ir[irCnt].readReg[1] = regs >> 4;
      ir[irCnt].size = GET_IMM_SIZE(opcode);
    }
    *pc += 2;
  } else if (opcode < 0x38) { //load imm
    immSize = GET_IMM_SIZE(opcode);
    if (
      getCode(context, *pc + 1, 1, (uint8_t*)&regs) &&
      getCode(context, *pc + 2, immSize, (uint8_t*)&imm) &&
      LEGAL_REG1(regs)
    ) {
      //ir[0] : ALU (MOV_IMM)
      //          writeReg = (R[0])
      //          imm = imm
      SETUP_IR(ir[irCnt], IR_ALU, *pc, 0, 1); //mov reg, imm
      ir[irCnt].alu = ALU_MOV_IMM;
      ir[irCnt].writeReg[0] = regs & 0xf;
      ir[irCnt].imm = imm;
    }
    *pc += 2 + immSize;
  } else if (opcode < 0x40) { //store imm
    immSize = GET_IMM_SIZE(opcode);
    if (
      getCode(context, *pc + 1, 1, (uint8_t*)&regs) &&
      getCode(context, *pc + 2, immSize, (uint8_t*)&imm) &&
      LEGAL_REG1(regs)
    ) {
      //ir[0] : STORE_IMM
      //          readReg = (R[0])
      //          imm = imm
      //          size = immSize
      SETUP_IR(ir[irCnt], IR_STORE_IMM, *pc, 1, 0); //store <size> [reg], imm
      ir[irCnt].readReg[0] = regs & 0xf;
      ir[irCnt].imm = imm;
      ir[irCnt].size = immSize;
    }
    *pc += 2 + immSize;
  } else if (opcode < 0x48) { //flow
    if (getCode(context, *pc + 1, 2, (uint8_t*)&imm)) {
      if (imm >= 0x8000) {
        imm |= 0xffffffffffff0000;
      }
      if (opcode == 0x40) { //call
        //ir[0] : ALU (SUB_IMM)
        //          readReg = (SP)
        //          writeReg = (SP)
        //          imm = 6
        //ir[1] : STORE_REG
        //          readReg = (SP, LR)
        //          size = 6
        //ir[2] : ALU (SUB_IMM)
        //          readReg = (SP)
        //          writeReg = (SP)
        //          imm = 6
        //ir[3] : STORE_REG
        //          readReg = (SP, BP)
        //          size = 6
        //ir[4] : ALU (MOV)
        //          readReg = (SP)
        //          writeReg = (BP)
        //ir[5] : ALU (MOV_IMM)
        //          writeReg = (LR)
        //          imm = *pc + 3
        //ir[6] : ALU (MOV_IMM)
        //          writeReg = (PC)
        //          imm = *pc + 3 + imm
        SETUP_IR(ir[irCnt], IR_ALU, *pc, 1, 1); //sub sp, 6
        ir[irCnt].alu = ALU_SUB_IMM;
        ir[irCnt].readReg[0] = REG_SP;
        ir[irCnt].writeReg[0] = REG_SP;
        ir[irCnt].imm = 6;
        SETUP_IR(ir[irCnt + 1], IR_STORE_REG, *pc, 2, 0); //store <6> [sp], lr
        ir[irCnt + 1].readReg[0] = REG_SP;
        ir[irCnt + 1].readReg[1] = REG_LR;
        ir[irCnt + 1].size = 6;
        SETUP_IR(ir[irCnt + 2], IR_ALU, *pc, 1, 1); //sub sp, 6
        ir[irCnt + 2].alu = ALU_SUB_IMM;
        ir[irCnt + 2].readReg[0] = REG_SP;
        ir[irCnt + 2].writeReg[0] = REG_SP;
        ir[irCnt + 2].imm = 6;
        SETUP_IR(ir[irCnt + 3], IR_STORE_REG, *pc, 2, 0); //store <6> [sp], bp
        ir[irCnt + 3].readReg[0] = REG_SP;
        ir[irCnt + 3].readReg[1] = REG_BP;
        ir[irCnt + 3].size = 6;
        SETUP_IR(ir[irCnt + 4], IR_ALU, *pc, 1, 1); //mov bp, sp
        ir[irCnt + 4].alu = ALU_MOV;
        ir[irCnt + 4].readReg[0] = REG_SP;
        ir[irCnt + 4].writeReg[0] = REG_BP;
        SETUP_IR(ir[irCnt + 5], IR_ALU, *pc, 0, 1); //mov lr, pc + 3
        ir[irCnt + 5].alu = ALU_MOV_IMM;
        ir[irCnt + 5].writeReg[0] = REG_LR;
        ir[irCnt + 5].imm = *pc + 3;
        SETUP_IR(ir[irCnt + 6], IR_ALU, *pc, 0, 1); //mov pc, pc + 3 + off
        ir[irCnt + 6].alu = ALU_MOV_IMM;
        ir[irCnt + 6].writeReg[0] = REG_PC;
        ir[irCnt + 6].imm = *pc + 3 + imm;
        irIncrement = 7;
      } else if (opcode == 0x41) { //jmp
        //ir[0] : ALU (MOV_IMM)
        //          writeReg = (PC)
        //          imm = *pc + 3 + imm
        SETUP_IR(ir[irCnt], IR_ALU, *pc, 0, 1); //mov pc, pc + 3 + off
        ir[irCnt].alu = ALU_MOV_IMM;
        ir[irCnt].writeReg[0] = REG_PC;
        ir[irCnt].imm = *pc + 3 + imm;
      } else { //jcc
        //ir[0] : JCC
        //          readReg = (FLAG)
        //          writeReg = (PC)
        //          imm = *pc + 3 + imm
        //          cond = cond
        SETUP_IR(ir[irCnt], IR_JCC, *pc, 1, 1); //jcc off
        ir[irCnt].readReg[0] = REG_FLAG;
        ir[irCnt].writeReg[0] = REG_PC;
        ir[irCnt].imm = *pc + imm + 3;
        ir[irCnt].cond = (opcode & 0xf) - 1;
      }
      *endBlock = true;
    }
    *pc += 3;
  } else if (opcode < 0x50) { //illegal
    //ir[0] : ILLEGAL
    *pc += 1;
  } else if (opcode < 0x5b) { //alu
    if (getCode(context, *pc + 1, 1, (uint8_t*)&regs) && LEGAL_REG1(regs) && LEGAL_REG2(regs)) {
      if (opcode == 0x59) { //mov
        //ir[0] : ALU (MOV)
        //          readReg = (R[1])
        //          writeReg = (R[0])
        SETUP_IR(ir[irCnt], IR_ALU, *pc, 1, 1); //mov reg1, reg2
        ir[irCnt].readReg[0] = regs >> 4;
      } else {
        //ir[0] : ALU (ADD / SUB / MUL / DIV / AND / OR / XOR / SHR / SHL / MOV / CMP)
        //          readReg = (R[0], R[1])
        //          writeReg = (FLAG if CMP else R[0])
        SETUP_IR(ir[irCnt], IR_ALU, *pc, 2, 1); //"op" reg1, reg2
        ir[irCnt].readReg[0] = regs & 0xf;
        ir[irCnt].readReg[1] = regs >> 4;
      }
      if (opcode == 0x5a) { //cmp
        ir[irCnt].writeReg[0] = REG_FLAG;
      } else {
        ir[irCnt].writeReg[0] = regs & 0xf;
      }
      ir[irCnt].alu = opcode - 0x50;
    }
    *pc += 2;
  } else if (opcode < 0xfd) { //illegal
    //ir[0] : ILLEGAL
    *pc += 1;
  } else if (opcode < 0xfe) { //return
    //ir[0] : ALU (MOV)
    //          readReg = (BP)
    //          writeReg = (SP)
    //ir[1] : ALU (MOV)
    //          readReg = (LR)
    //          writeReg = (PC)
    //ir[2] : LOAD
    //          readReg = (SP)
    //          writeReg = (BP)
    //          size = 6
    //ir[3] : ALU (ADD_IMM)
    //          readReg = (SP)
    //          writeReg = (SP)
    //          imm = 6
    //ir[4] : LOAD
    //          readReg = (SP)
    //          writeReg = (LR)
    //          size = 6
    //ir[5] : ALU (ADD_IMM)
    //          readReg = (SP)
    //          writeReg = (SP)
    //          size = 6
    SETUP_IR(ir[irCnt], IR_ALU, *pc, 1, 1); //mov sp, bp
    ir[irCnt].alu = ALU_MOV;
    ir[irCnt].readReg[0] = REG_BP;
    ir[irCnt].writeReg[0] = REG_SP;
    SETUP_IR(ir[irCnt + 1], IR_ALU, *pc, 1, 1); //mov pc, lr
    ir[irCnt + 1].alu = ALU_MOV;
    ir[irCnt + 1].readReg[0] = REG_LR;
    ir[irCnt + 1].writeReg[0] = REG_PC;
    SETUP_IR(ir[irCnt + 2], IR_LOAD, *pc, 1, 1); //load <6> bp, [sp]
    ir[irCnt + 2].readReg[0] = REG_SP;
    ir[irCnt + 2].writeReg[0] = REG_BP;
    ir[irCnt + 2].size = 6;
    SETUP_IR(ir[irCnt + 3], IR_ALU, *pc, 1, 1); //add sp, 6
    ir[irCnt + 3].alu = ALU_ADD_IMM;
    ir[irCnt + 3].readReg[0] = REG_SP;
    ir[irCnt + 3].writeReg[0] = REG_SP;
    ir[irCnt + 3].imm = 6;
    SETUP_IR(ir[irCnt + 4], IR_LOAD, *pc, 1, 1); //load <6> lr, [sp]
    ir[irCnt + 4].readReg[0] = REG_SP;
    ir[irCnt + 4].writeReg[0] = REG_LR;
    ir[irCnt + 4].size = 6;
    SETUP_IR(ir[irCnt + 5], IR_ALU, *pc, 1, 1); //add sp, 6
    ir[irCnt + 5].alu = ALU_ADD_IMM;
    ir[irCnt + 5].readReg[0] = REG_SP;
    ir[irCnt + 5].writeReg[0] = REG_SP;
    ir[irCnt + 5].imm = 6;
    irIncrement = 6;
    *pc += 1;
    *endBlock = true;
  } else if (opcode < 0xff) { //syscall
    //ir[0] : ALU (MOV_IMM)
    //          writeReg = (PC)
    //          imm = *pc + 1
    //ir[1] : SYSCALL
    //          readReg = (R0, R1, R2 ,R3)
    //          writeReg = (R0)
    SETUP_IR(ir[irCnt], IR_ALU, *pc, 0, 1); //mov pc, pc + 1
    ir[irCnt].alu = ALU_MOV_IMM;
    ir[irCnt].writeReg[0] = REG_PC;
    ir[irCnt].imm = *pc + 1;
    SETUP_IR(ir[irCnt + 1], IR_SYSCALL, *pc, 4, 1); //syscall
    ir[irCnt + 1].readReg[0] = REG_R0;
    ir[irCnt + 1].readReg[1] = REG_R1;
    ir[irCnt + 1].readReg[2] = REG_R2;
    ir[irCnt + 1].readReg[3] = REG_R3;
    ir[irCnt + 1].writeReg[0] = REG_R0;
    irIncrement = 2;
    *pc += 1;
    *endBlock = true;
  } else { //exit
    //ir[0] : ALU (MOV_IMM)
    //          writeReg = (PC)
    //          imm = *pc + 1
    //ir[1] : EXIT
    SETUP_IR(ir[irCnt], IR_ALU, *pc, 0, 1); //mov pc, pc + 1
    ir[irCnt].alu = ALU_MOV_IMM;
    ir[irCnt].writeReg[0] = REG_PC;
    ir[irCnt].imm = *pc + 1;
    SETUP_IR(ir[irCnt + 1], IR_EXIT, *pc, 0, 0); //exit
    irIncrement = 2;
    *pc += 1;
    *endBlock = true;
  }
  if (ir[irCnt].ir == IR_ILLEGAL) *endBlock = true;
  return irIncrement;
}
