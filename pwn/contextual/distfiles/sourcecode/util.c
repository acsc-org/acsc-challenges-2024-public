#include "util.h"

void printError(char *msg) {
  puts(msg);
  _exit(0);
}

void setupVec(VEC *vec) {
  vec->len = 0;
  vec->cap = 0;
  vec->entries = NULL;
  return;
}

void clearVec(VEC *vec) {
  vec->len = 0;
  vec->cap = 0;
  free(vec->entries);
  vec->entries = NULL;
  return;
}

void *lookupVec(VEC *vec, uint64_t entrySize, void *key, bool (*cmpFunc)(void *entry, void *key)) {
  void *entry;
  for (uint64_t i = 0; i < vec->len; i++) {
    entry = (void*)(((uint64_t)(vec->entries)) + entrySize * i);
    if (cmpFunc(entry, key)) {
      return entry;
    }
  }
  return NULL;
}

void *getVec(VEC *vec, uint64_t entrySize, uint64_t idx) {
  return (void*)(((uint64_t)(vec->entries)) + entrySize * idx);
}

void insertVec(VEC *vec, uint64_t entrySize, void *entry) {
  //NOTE: it is the caller's responsibility to not insert the same entry more than once so that lookupVec works properly
  if (vec->len == vec->cap) {
    if (vec->cap == 0) {
      vec->cap = 16;
    } else {
      vec->cap *= 2;
    }
    if (vec->cap < vec->len || vec->cap * entrySize / entrySize != vec->cap) printError("vecInsert:: vec->cap too large");
    vec->entries = realloc(vec->entries, vec->cap * entrySize);
    if (vec->entries == NULL) printError("vecInsert::realloc failed");
  }
  memcpy((void*)(((uint64_t)(vec->entries)) + entrySize * vec->len), entry, entrySize);
  vec->len += 1;
  return;
}

void writeStr(char *buf) {
  write(STDOUT_FILENO, buf, strlen(buf));
  return;
}

void readStr(uint8_t *buf, uint64_t size, char *delim) {
  uint64_t remain = size, cnt;
  uint8_t *cursor = buf;
  while (remain > 0) {
    cnt = read(STDIN_FILENO, cursor, remain);
    if (cnt <= 0) printError("readStr::read failed");
    remain -= cnt;
    cursor += cnt;
    if (delim != NULL && cursor[-1] == *delim) {
      cursor[-1] = '\0';
      break;
    }
  }
  return;
}

uint64_t readInt() {
  uint8_t buf[0x10] = {'\0'};
  readStr(buf, sizeof(buf) - 1, "\n");
  return strtoull((const char*)buf, NULL, 10);
}
