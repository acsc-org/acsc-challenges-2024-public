#include "debug.h"
#include "compile.h"

void debugRegState(uint64_t *reg) {
  printf("DEBUG::REG_STATE\n");
  for(uint64_t i = 0; i < REG_CNT; i++) {
    printf("DEBUG::    r%02d %llx\n", i, reg[i]);
  }
}

void debugRegRange(VALRANGE* regRange) {
  printf("DEBUG::REG_RANGE\n");
  for(uint64_t i = 0; i < REG_CNT; i++) {
    printf("DEBUG::    r%02d %llx %llx\n", i, regRange[i].l, regRange[i].u);
  }
}

void debugIr(IRINFO *ir, bool optimized) {
  printf("DEBUG::IR (%llx)\n", ir->pc);
  switch(ir->ir) {
    case IR_NOOP:
      printf("DEBUG::    IR_NOOP\n");
      break;
    case IR_ILLEGAL:
      printf("DEBUG::    IR_ILLEGAL\n");
      break;
    case IR_LOAD:
      printf("DEBUG::    IR_LOAD\n");
      printf("DEBUG::        r%02d = <%d> [", ir->writeReg[0], ir->size);
      if (optimized && ir->concrete) {
        printf("%llx]\n", ir->addr);
      } else if (optimized && !ir->check) {
        printf("r%02d]    //NO CHECK\n", ir->readReg[0]);
      } else {
        printf("r%02d]\n", ir->readReg[0]);
      }
      break;
    case IR_STORE_IMM:
      printf("DEBUG::    IR_STORE_IMM\n");
      printf("DEBUG::        <%d> [", ir->size);
      if (optimized && ir->concrete) {
        printf("%llx] = %llx\n", ir->addr, ir->imm);
      } else if (optimized && !ir->check){
        printf("r%02d] = %llx    //NO CHECK\n", ir->readReg[0], ir->imm);
      } else {
        printf("r%02d] = %llx\n", ir->readReg[0], ir->imm);
      }
      break;
    case IR_STORE_REG:
      printf("DEBUG::    IR_STORE_REG\n");
      printf("DEBUG::        <%d> [", ir->size);
      if (optimized && ir->concrete) {
        printf("%llx] = r%02d\n", ir->addr, ir->readReg[0]);
      } else if (optimized && !ir->check){
        printf("r%02d] = r%02d    //NO CHECK\n", ir->readReg[0], ir->readReg[1]);
      } else {
        printf("r%02d] = r%02d\n", ir->readReg[0], ir->readReg[1]);
      }
      break;
    case IR_JCC:
      printf("DEBUG::    IR_JCC\n");
      switch (ir->cond) {
        case COND_A:
          printf("DEBUG::        goto %llx if (a) else %llx\n", ir->imm, ir->pc + 3);
          break;
        case COND_AE:
          printf("DEBUG::        goto %llx if (ae) else %llx\n", ir->imm, ir->pc + 3);
          break;
        case COND_E:
          printf("DEBUG::        goto %llx if (e) else %llx\n", ir->imm, ir->pc + 3);
          break;
        case COND_NE:
          printf("DEBUG::        goto %llx if (ne) else %llx\n", ir->imm, ir->pc + 3);
          break;
        case COND_B:
          printf("DEBUG::        goto %llx if (b) else %llx\n", ir->imm, ir->pc + 3);
          break;
        case COND_BE:
          printf("DEBUG::        goto %llx if (be) else %llx\n", ir->imm, ir->pc + 3);
          break;
      }
      break;
    case IR_ALU:
      printf("DEBUG::    IR_ALU\n");
      if (ir->alu == ALU_MOV) {
        printf("DEBUG::        r%02d = r%02d\n", ir->writeReg[0], ir->readReg[0]);
      } else if (ir->alu == ALU_MOV_IMM) {
        printf("DEBUG::        r%02d = %llx\n", ir->writeReg[0], ir->imm);
      } else if (ir->alu == ALU_CMP) {
        printf("DEBUG::        r%02d = r%02d cmp r%02d\n", ir->writeReg[0], ir->readReg[0], ir->readReg[1]);
      } else if (ir->alu == ALU_CMP_IMM) {
        printf("DEBUG::        r%02d = r%02d cmp %llx\n", ir->writeReg[0], ir->readReg[0], ir->imm);
      } else {
        printf("DEBUG::        r%02d = r%02d ", ir->writeReg[0], ir->readReg[0]);
        switch (ir->alu & ALU_MASK) {
          case ALU_ADD:
            printf("+");
            break;
          case ALU_SUB:
            printf("-");
            break;
          case ALU_MUL:
            printf("*");
            break;
          case ALU_DIV:
            printf("/");
            break;
          case ALU_AND:
            printf("&");
            break;
          case ALU_OR:
            printf("|");
            break;
          case ALU_XOR:
            printf("^");
            break;
          case ALU_SHR:
            printf(">>");
            break;
          case ALU_SHL:
            printf("<<");
            break;
        }
        if (ir->alu <= ALU_MASK) {
          printf(" r%02d", ir->readReg[1]);
          if (ir->alu == ALU_DIV && optimized && !ir->check) {
            printf("    //NO CHECK\n");
          } else {
            printf("\n");
          }
        } else {
          printf(" %llx\n", ir->imm);
        }
      }
      break; 
    case IR_SYSCALL:
      printf("DEBUG::    IR_SYSCALL\n");
      printf("DEBUG::        syscall<r00>(r01, r02, r03)\n");
      break;
    case IR_EXIT:
      printf("DEBUG::    IR_EXIT\n");
      break;
  }
}
