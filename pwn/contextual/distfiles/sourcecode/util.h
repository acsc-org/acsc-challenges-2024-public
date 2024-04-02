#ifndef __UTIL_HEADER__
#define __UTIL_HEADER__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define U64_MAX 0xffffffffffffffff

typedef struct Vector {
  uint64_t cap;
  uint64_t len;
  void *entries;
} VEC;

void printError(char *msg);
void setupVec(VEC *vec);
void clearVec(VEC *vec);
void *lookupVec(VEC *vec, uint64_t entrySize, void *key, bool (*cmpFunc)(void *entry, void *key));
void *getVec(VEC *vec, uint64_t entrySize, uint64_t idx);
void insertVec(VEC *vec, uint64_t entrySize, void *entry);
void writeStr(char *buf);
void readStr(uint8_t *buf, uint64_t size, char *delim);
uint64_t readInt();

#endif
