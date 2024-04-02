#include "main.h"

void readCode(uint8_t *code, uint64_t *codeLen) {
  writeStr("input codeLen (<= 0x1000) : ");
  *codeLen = readInt();
  if (*codeLen > CODE_SIZE) printError("readCode:: codeLen exceeded max size");
  writeStr("input code : ");
  readStr(code, *codeLen, NULL);
  return;
}

int main() {
  CONTEXT context;
  uint8_t code[CODE_SIZE];
  uint64_t codeLen;
  readCode(code, &codeLen);
  setupVM(&context, code, codeLen);
  runVM(&context);
  clearVM(&context);
  return 0;
}
