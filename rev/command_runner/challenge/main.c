#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define PNG_SIGNATURE "\x89PNG\x0d\x0a\x1a\x0a"
#define BPP 8
#define BPP_LCT 24

#ifdef DEBUG
#define assert(X) { if(!(X)) { puts(#X); exit(0); } }
#else
#define assert(X) { if(!(X)) exit(0); }
#endif

#define lodepng_malloc malloc
#define lodepng_realloc realloc
#define lodepng_free free
#define lodepng_memset memset
#define lodepng_memcpy memcpy

#define LODEPNG_MAX(a, b) (((a) > (b)) ? (a) : (b))
#define LODEPNG_MIN(a, b) (((a) < (b)) ? (a) : (b))

uint8_t font_data[128][32] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 13, 128, 13, 128, 4, 128, 4, 128, 4, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 4, 128, 5, 0, 5, 0, 5, 0, 15, 192, 5, 0, 31, 192, 5, 0, 5, 0, 5, 0, 5, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 2, 0, 5, 128, 8, 0, 8, 0, 6, 0, 1, 128, 0, 64, 8, 64, 7, 128, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 6, 0, 9, 0, 17, 0, 10, 0, 4, 192, 7, 0, 9, 128, 2, 64, 4, 64, 3, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 8, 0, 4, 0, 4, 0, 10, 192, 10, 128, 9, 0, 15, 192, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 3, 0, 3, 0, 3, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 128, 0, 128, 0, 0},
    {0, 0, 0, 0, 0, 0, 8, 0, 4, 0, 4, 0, 4, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 4, 0, 4, 0, 8, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 10, 64, 7, 128, 5, 0, 4, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 2, 0, 31, 192, 2, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 4, 0, 4, 0, 8, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 64, 0, 128, 0, 128, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 4, 0, 4, 0, 8, 0, 8, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 0, 8, 128, 8, 64, 8, 64, 8, 64, 8, 64, 8, 64, 8, 64, 8, 128, 7, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 2, 0, 6, 0, 10, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 15, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 0, 8, 128, 0, 64, 0, 128, 0, 128, 1, 0, 2, 0, 4, 0, 8, 64, 31, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 0, 8, 128, 0, 64, 0, 128, 3, 128, 0, 128, 0, 64, 0, 64, 0, 64, 15, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 128, 2, 128, 2, 128, 4, 128, 4, 128, 8, 128, 8, 128, 7, 128, 0, 128, 3, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 15, 128, 8, 0, 8, 0, 8, 0, 15, 128, 0, 64, 0, 64, 0, 64, 0, 64, 15, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 192, 2, 0, 4, 0, 8, 0, 11, 128, 12, 64, 8, 64, 8, 64, 4, 64, 3, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 15, 192, 8, 64, 0, 128, 0, 128, 0, 128, 1, 0, 1, 0, 1, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 0, 8, 128, 8, 64, 8, 128, 4, 128, 7, 128, 8, 64, 8, 64, 8, 64, 7, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 3, 0, 12, 128, 8, 64, 8, 64, 8, 192, 7, 192, 0, 64, 0, 64, 0, 128, 15, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 7, 0, 0, 0, 0, 0, 0, 0, 6, 0, 6, 0, 4, 0, 8, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 1, 128, 6, 0, 24, 0, 12, 0, 3, 0, 0, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 224, 0, 0, 31, 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 6, 0, 1, 128, 0, 64, 1, 128, 2, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 15, 128, 8, 64, 0, 64, 0, 128, 1, 0, 2, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 0, 8, 128, 8, 128, 8, 128, 11, 128, 10, 128, 10, 128, 9, 192, 8, 0, 8, 0, 7, 128, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 14, 0, 5, 0, 5, 0, 4, 128, 8, 128, 15, 128, 16, 64, 16, 64, 56, 224, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 31, 128, 8, 64, 8, 64, 8, 64, 15, 128, 8, 64, 8, 32, 8, 64, 31, 192, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 192, 8, 64, 16, 0, 16, 0, 16, 0, 16, 0, 16, 0, 8, 64, 7, 128, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 31, 0, 16, 192, 16, 64, 16, 64, 16, 64, 16, 64, 16, 64, 16, 64, 31, 128, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 31, 192, 8, 64, 8, 64, 9, 0, 15, 0, 9, 0, 8, 0, 8, 64, 31, 192, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 31, 192, 8, 64, 8, 0, 9, 0, 15, 0, 9, 0, 8, 0, 8, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 192, 8, 64, 16, 0, 16, 0, 16, 0, 17, 224, 16, 64, 16, 64, 15, 192, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 28, 192, 8, 64, 8, 64, 8, 64, 15, 192, 8, 64, 8, 64, 8, 64, 28, 224, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 15, 192, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 15, 192, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 3, 224, 0, 128, 0, 128, 0, 128, 0, 128, 16, 128, 16, 128, 16, 128, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 28, 224, 8, 128, 9, 0, 10, 0, 15, 0, 8, 128, 8, 128, 8, 128, 28, 96, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 31, 0, 4, 0, 4, 0, 4, 0, 4, 0, 4, 32, 4, 32, 4, 32, 31, 224, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 56, 96, 24, 160, 24, 160, 21, 32, 21, 32, 19, 32, 16, 32, 16, 32, 56, 224, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 56, 224, 24, 64, 20, 64, 18, 64, 18, 64, 17, 64, 17, 64, 16, 192, 28, 64, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 128, 8, 64, 16, 64, 16, 32, 16, 32, 16, 32, 16, 64, 8, 64, 7, 128, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 31, 128, 8, 64, 8, 64, 8, 64, 8, 128, 15, 0, 8, 0, 8, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 128, 8, 64, 16, 64, 16, 32, 16, 32, 16, 32, 16, 64, 8, 64, 4, 128, 3, 0, 13, 192, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 31, 128, 8, 64, 8, 64, 8, 64, 15, 128, 8, 128, 8, 128, 8, 64, 28, 32, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 7, 192, 8, 64, 8, 0, 8, 0, 7, 128, 0, 64, 0, 64, 16, 64, 31, 128, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 31, 192, 18, 64, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 15, 128, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 28, 224, 16, 64, 16, 64, 16, 64, 16, 64, 16, 64, 16, 64, 8, 64, 7, 128, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 56, 224, 16, 64, 16, 64, 8, 128, 8, 128, 4, 128, 5, 0, 5, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 60, 224, 16, 32, 18, 64, 19, 64, 21, 64, 21, 64, 20, 192, 24, 192, 8, 192, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 24, 224, 8, 128, 4, 128, 3, 0, 2, 0, 5, 0, 4, 128, 8, 64, 28, 224, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 24, 224, 8, 128, 4, 128, 5, 0, 2, 0, 2, 0, 2, 0, 2, 0, 15, 128, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 15, 192, 8, 128, 9, 0, 1, 0, 2, 0, 4, 0, 4, 64, 8, 64, 15, 192, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 3, 128, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 3, 128, 0, 0},
    {0, 0, 0, 0, 0, 0, 8, 0, 8, 0, 4, 0, 4, 0, 2, 0, 2, 0, 1, 0, 1, 0, 0, 128, 0, 128, 0, 64, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 6, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 6, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 4, 128, 8, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 63, 240, 0, 0},
    {0, 0, 0, 0, 4, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 8, 128, 0, 128, 15, 128, 16, 128, 16, 128, 15, 96, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 48, 0, 16, 0, 16, 0, 19, 128, 12, 64, 8, 64, 16, 32, 16, 32, 8, 64, 55, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 128, 8, 64, 16, 0, 16, 0, 16, 0, 8, 32, 7, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 192, 0, 64, 0, 64, 7, 64, 8, 192, 16, 64, 16, 64, 16, 64, 16, 64, 15, 224, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 8, 192, 16, 64, 31, 192, 16, 0, 16, 0, 15, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 192, 2, 0, 4, 0, 15, 192, 4, 0, 4, 0, 4, 0, 4, 0, 4, 0, 15, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 96, 24, 192, 16, 64, 16, 64, 16, 64, 8, 192, 7, 64, 0, 64, 0, 128, 7, 128},
    {0, 0, 0, 0, 0, 0, 24, 0, 8, 0, 8, 0, 11, 128, 12, 128, 8, 64, 8, 64, 8, 64, 8, 64, 28, 224, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 14, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 15, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 15, 128, 0, 128, 0, 128, 0, 128, 0, 128, 0, 128, 0, 128, 0, 128, 0, 128, 15, 0},
    {0, 0, 0, 0, 0, 0, 24, 0, 8, 0, 8, 0, 9, 192, 9, 0, 10, 0, 14, 0, 9, 0, 8, 128, 24, 224, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 14, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 15, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 192, 19, 64, 18, 32, 18, 32, 18, 32, 18, 32, 57, 32, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 27, 128, 12, 64, 8, 64, 8, 64, 8, 64, 8, 64, 28, 224, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 128, 8, 64, 16, 64, 16, 64, 16, 64, 16, 64, 15, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 128, 12, 64, 16, 32, 16, 32, 8, 32, 8, 64, 23, 128, 16, 0, 16, 0, 60, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 96, 8, 192, 16, 64, 16, 64, 16, 64, 8, 192, 7, 64, 0, 64, 0, 64, 1, 224},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 192, 7, 0, 4, 0, 4, 0, 4, 0, 4, 0, 31, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 64, 8, 192, 8, 0, 7, 128, 0, 64, 8, 64, 15, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 8, 0, 8, 0, 31, 128, 8, 0, 8, 0, 8, 0, 8, 0, 8, 0, 7, 192, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 192, 8, 64, 8, 64, 8, 64, 8, 64, 8, 64, 15, 224, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 224, 8, 64, 8, 128, 8, 128, 5, 0, 5, 0, 3, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 96, 16, 64, 18, 64, 19, 64, 13, 64, 13, 128, 12, 128, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 192, 8, 128, 5, 0, 2, 0, 5, 0, 8, 128, 28, 224, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 224, 8, 64, 8, 128, 8, 128, 5, 0, 5, 0, 2, 0, 2, 0, 4, 0, 30, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 192, 8, 128, 1, 0, 2, 0, 4, 0, 8, 64, 15, 192, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 128, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 6, 0, 2, 0, 2, 0, 2, 0, 2, 0, 1, 128, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 4, 0, 2, 0, 2, 0, 2, 0, 2, 0, 1, 0, 1, 128, 2, 0, 2, 0, 2, 0, 2, 0, 6, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 10, 64, 1, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// This code is inspired by https://github.com/lvandeve/lodepng a lot,
// but intentionally removed a lot of code lines to make this challenge easier,
// and also make it difficult to guess the code base 

// *****************************************************************
// This part is from https://github.com/lvandeve/lodepng
// Some functions are slightly modified
// *****************************************************************

int lodepng_addofl(size_t a, size_t b, size_t* result) {
  *result = a + b; /* Unsigned addition is well defined and safe in C90 */
  return *result < a;
}

int lodepng_mulofl(size_t a, size_t b, size_t* result) {
  *result = a * b; /* Unsigned multiplication is well defined and safe in C90 */
  return (a != 0 && *result / a != b);
}

typedef struct {
  const unsigned char* data;
  size_t size; /*size of data in bytes*/
  size_t bitsize; /*size of data in bits, end of valid bp values, should be 8*size*/
  size_t bp;
  unsigned buffer; /*buffer for reading bits. NOTE: 'unsigned' must support at least 32 bits*/
} LodePNGBitReader;

/* data size argument is in bytes. Returns error if size too large causing overflow */
unsigned LodePNGBitReader_init(LodePNGBitReader* reader, const unsigned char* data, size_t size) {
  size_t temp;
  reader->data = data;
  reader->size = size;
  /* size in bits, return error if overflow (if size_t is 32 bit this supports up to 500MB)  */
  assert(!lodepng_mulofl(size, 8u, &reader->bitsize));
  /*ensure incremented bp can be compared to bitsize without overflow even when it would be incremented 32 too much and
  trying to ensure 32 more bits*/
  assert(!lodepng_addofl(reader->bitsize, 64u, &temp));
  reader->bp = 0;
  reader->buffer = 0;
  return 0; /*ok*/
}

/*
ensureBits functions:
Ensures the reader can at least read nbits bits in one or more readBits calls,
safely even if not enough bits are available.
The nbits parameter is unused but is given for documentation purposes, error
checking for amount of bits must be done beforehand.
*/

/// NOTE: Removed from the original code to make reversing easier
/*See ensureBits documentation above. This one ensures up to 9 bits */
void ensureBits9(LodePNGBitReader* reader, size_t nbits) {
  size_t start = reader->bp >> 3u;
  size_t size = reader->size;
  if(start + 1u < size) {
    reader->buffer = (unsigned)reader->data[start + 0] | ((unsigned)reader->data[start + 1] << 8u);
    reader->buffer >>= (reader->bp & 7u);
  } else {
    reader->buffer = 0;
    if(start + 0u < size) reader->buffer = reader->data[start + 0];
    reader->buffer >>= (reader->bp & 7u);
  }
  (void)nbits;
}

/*See ensureBits documentation above. This one ensures up to 17 bits */
void ensureBits17(LodePNGBitReader* reader, size_t nbits) {
  size_t start = reader->bp >> 3u;
  size_t size = reader->size;
  if(start + 2u < size) {
    reader->buffer = (unsigned)reader->data[start + 0] | ((unsigned)reader->data[start + 1] << 8u) |
                     ((unsigned)reader->data[start + 2] << 16u);
    reader->buffer >>= (reader->bp & 7u);
  } else {
    reader->buffer = 0;
    if(start + 0u < size) reader->buffer |= reader->data[start + 0];
    if(start + 1u < size) reader->buffer |= ((unsigned)reader->data[start + 1] << 8u);
    reader->buffer >>= (reader->bp & 7u);
  }
  (void)nbits;
}

/*See ensureBits documentation above. This one ensures up to 25 bits */
void ensureBits25(LodePNGBitReader* reader, size_t nbits) {
  size_t start = reader->bp >> 3u;
  size_t size = reader->size;
  if(start + 3u < size) {
    reader->buffer = (unsigned)reader->data[start + 0] | ((unsigned)reader->data[start + 1] << 8u) |
                     ((unsigned)reader->data[start + 2] << 16u) | ((unsigned)reader->data[start + 3] << 24u);
    reader->buffer >>= (reader->bp & 7u);
  } else {
    reader->buffer = 0;
    if(start + 0u < size) reader->buffer |= reader->data[start + 0];
    if(start + 1u < size) reader->buffer |= ((unsigned)reader->data[start + 1] << 8u);
    if(start + 2u < size) reader->buffer |= ((unsigned)reader->data[start + 2] << 16u);
    reader->buffer >>= (reader->bp & 7u);
  }
  (void)nbits;
}

/*See ensureBits documentation above. This one ensures up to 32 bits */
void ensureBits32(LodePNGBitReader* reader, size_t nbits) {
  size_t start = reader->bp >> 3u;
  size_t size = reader->size;
  if(start + 4u < size) {
    reader->buffer = (unsigned)reader->data[start + 0] | ((unsigned)reader->data[start + 1] << 8u) |
                     ((unsigned)reader->data[start + 2] << 16u) | ((unsigned)reader->data[start + 3] << 24u);
    reader->buffer >>= (reader->bp & 7u);
    reader->buffer |= (((unsigned)reader->data[start + 4] << 24u) << (8u - (reader->bp & 7u)));
  } else {
    reader->buffer = 0;
    if(start + 0u < size) reader->buffer |= reader->data[start + 0];
    if(start + 1u < size) reader->buffer |= ((unsigned)reader->data[start + 1] << 8u);
    if(start + 2u < size) reader->buffer |= ((unsigned)reader->data[start + 2] << 16u);
    if(start + 3u < size) reader->buffer |= ((unsigned)reader->data[start + 3] << 24u);
    reader->buffer >>= (reader->bp & 7u);
  }
  (void)nbits;
}

/* Get bits without advancing the bit pointer. Must have enough bits available with ensureBits. Max nbits is 31. */
unsigned peekBits(LodePNGBitReader* reader, size_t nbits) {
  /* The shift allows nbits to be only up to 31. */
  return reader->buffer & ((1u << nbits) - 1u);
}

/* Must have enough bits available with ensureBits */
void advanceBits(LodePNGBitReader* reader, size_t nbits) {
  reader->buffer >>= nbits;
  reader->bp += nbits;
}

/* Must have enough bits available with ensureBits */
unsigned readBits(LodePNGBitReader* reader, size_t nbits) {
  unsigned result = peekBits(reader, nbits);
  advanceBits(reader, nbits);
  return result;
}

unsigned reverseBits(unsigned bits, unsigned num) {
  /*TODO: implement faster lookup table based version when needed*/
  unsigned i, result = 0;
  for(i = 0; i < num; i++) result |= ((bits >> (num - i - 1u)) & 1u) << i;
  return result;
}

/* /////////////////////////////////////////////////////////////////////////// */

/*dynamic vector of unsigned chars*/
typedef struct ucvector {
  unsigned char* data;
  size_t size; /*used size*/
  size_t allocsize; /*allocated size*/
} ucvector;

/*returns 1 if success, 0 if failure ==> nothing done*/
unsigned ucvector_reserve(ucvector* p, size_t size) {
  if(size > p->allocsize) {
    size_t newsize = size + (p->allocsize >> 1u);
    void* data = lodepng_realloc(p->data, newsize);
    if(data) {
      p->allocsize = newsize;
      p->data = (unsigned char*)data;
    }
    else return 0; /*error: not enough memory*/
  }
  return 1; /*success*/
}

/*returns 1 if success, 0 if failure ==> nothing done*/
unsigned ucvector_resize(ucvector* p, size_t size) {
  p->size = size;
  return ucvector_reserve(p, size);
}

ucvector ucvector_init(unsigned char* buffer, size_t size) {
  ucvector v;
  v.data = buffer;
  v.allocsize = v.size = size;
  return v;
}

/* ////////////////////////////////////////////////////////////////////////// */
/* / Deflate - Huffman                                                      / */
/* ////////////////////////////////////////////////////////////////////////// */

#define FIRST_LENGTH_CODE_INDEX 257
#define LAST_LENGTH_CODE_INDEX 285
/*256 literals, the end code, some length codes, and 2 unused codes*/
#define NUM_DEFLATE_CODE_SYMBOLS 288
/*the distance codes have their own symbols, 30 used, 2 unused*/
#define NUM_DISTANCE_SYMBOLS 32
/*the code length codes. 0-15: code lengths, 16: copy previous 3-6 times, 17: 3-10 zeros, 18: 11-138 zeros*/
#define NUM_CODE_LENGTH_CODES 19

/*the base lengths represented by codes 257-285*/
const unsigned LENGTHBASE[29]
  = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
     67, 83, 99, 115, 131, 163, 195, 227, 258};

/*the extra bits used by codes 257-285 (added to base length)*/
const unsigned LENGTHEXTRA[29]
  = {0, 0, 0, 0, 0, 0, 0,  0,  1,  1,  1,  1,  2,  2,  2,  2,  3,  3,  3,  3,
      4,  4,  4,   4,   5,   5,   5,   5,   0};

/*the base backwards distances (the bits of distance codes appear after length codes and use their own huffman tree)*/
const unsigned DISTANCEBASE[30]
  = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
     769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};

/*the extra bits of backwards distances (added to base)*/
const unsigned DISTANCEEXTRA[30]
  = {0, 0, 0, 0, 1, 1, 2,  2,  3,  3,  4,  4,  5,  5,   6,   6,   7,   7,   8,
       8,    9,    9,   10,   10,   11,   11,   12,    12,    13,    13};

/*the order in which "code length alphabet code lengths" are stored as specified by deflate, out of this the huffman
tree of the dynamic huffman tree lengths is generated*/
const unsigned CLCL_ORDER[NUM_CODE_LENGTH_CODES]
  = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

/* ////////////////////////////////////////////////////////////////////////// */

/*
Huffman tree struct, containing multiple representations of the tree
*/
typedef struct HuffmanTree {
  unsigned* codes; /*the huffman codes (bit patterns representing the symbols)*/
  unsigned* lengths; /*the lengths of the huffman codes*/
  unsigned maxbitlen; /*maximum number of bits a single code can get*/
  unsigned numcodes; /*number of symbols in the alphabet = number of codes*/
  /* for reading only */
  unsigned char* table_len; /*length of symbol from lookup table, or max length if secondary lookup needed*/
  unsigned short* table_value; /*value of symbol from lookup table, or pointer to secondary table if needed*/
} HuffmanTree;

void HuffmanTree_init(HuffmanTree* tree) {
  tree->codes = 0;
  tree->lengths = 0;
  tree->table_len = 0;
  tree->table_value = 0;
}

void HuffmanTree_cleanup(HuffmanTree* tree) {
  lodepng_free(tree->codes);
  lodepng_free(tree->lengths);
  lodepng_free(tree->table_len);
  lodepng_free(tree->table_value);
}

/* amount of bits for first huffman table lookup (aka root bits), see HuffmanTree_makeTable and huffmanDecodeSymbol.*/
/* values 8u and 9u work the fastest */
#define FIRSTBITS 9u

/* a symbol value too big to represent any valid symbol, to indicate reading disallowed huffman bits combination,
which is possible in case of only 0 or 1 present symbols. */
#define INVALIDSYMBOL 65535u

/* make table for huffman decoding */
void HuffmanTree_makeTable(HuffmanTree* tree) {
  const unsigned headsize = 1u << FIRSTBITS; /*size of the first table*/
  const unsigned mask = (1u << FIRSTBITS) /*headsize*/ - 1u;
  size_t i, numpresent, pointer, size; /*total table size*/
  unsigned* maxlens = (unsigned*)lodepng_malloc(headsize * sizeof(unsigned));
  assert(maxlens);

  /* compute maxlens: max total bit length of symbols sharing prefix in the first table*/
  lodepng_memset(maxlens, 0, headsize * sizeof(*maxlens));
  for(i = 0; i < tree->numcodes; i++) {
    unsigned symbol = tree->codes[i];
    unsigned l = tree->lengths[i];
    unsigned index;
    if(l <= FIRSTBITS) continue; /*symbols that fit in first table don't increase secondary table size*/
    /*get the FIRSTBITS MSBs, the MSBs of the symbol are encoded first. See later comment about the reversing*/
    index = reverseBits(symbol >> (l - FIRSTBITS), FIRSTBITS);
    maxlens[index] = LODEPNG_MAX(maxlens[index], l);
  }
  /* compute total table size: size of first table plus all secondary tables for symbols longer than FIRSTBITS */
  size = headsize;
  for(i = 0; i < headsize; ++i) {
    unsigned l = maxlens[i];
    if(l > FIRSTBITS) size += (((size_t)1) << (l - FIRSTBITS));
  }
  tree->table_len = (unsigned char*)lodepng_malloc(size * sizeof(*tree->table_len));
  tree->table_value = (unsigned short*)lodepng_malloc(size * sizeof(*tree->table_value));
  assert(tree->table_len && tree->table_value);
  /*initialize with an invalid length to indicate unused entries*/
  for(i = 0; i < size; ++i) tree->table_len[i] = 16;

  /*fill in the first table for long symbols: max prefix size and pointer to secondary tables*/
  pointer = headsize;
  for(i = 0; i < headsize; ++i) {
    unsigned l = maxlens[i];
    if(l <= FIRSTBITS) continue;
    tree->table_len[i] = l;
    tree->table_value[i] = (unsigned short)pointer;
    pointer += (((size_t)1) << (l - FIRSTBITS));
  }
  lodepng_free(maxlens);

  /*fill in the first table for short symbols, or secondary table for long symbols*/
  numpresent = 0;
  for(i = 0; i < tree->numcodes; ++i) {
    unsigned l = tree->lengths[i];
    unsigned symbol, reverse;
    if(l == 0) continue;
    symbol = tree->codes[i]; /*the huffman bit pattern. i itself is the value.*/
    /*reverse bits, because the huffman bits are given in MSB first order but the bit reader reads LSB first*/
    reverse = reverseBits(symbol, l);
    numpresent++;

    if(l <= FIRSTBITS) {
      /*short symbol, fully in first table, replicated num times if l < FIRSTBITS*/
      unsigned num = 1u << (FIRSTBITS - l);
      unsigned j;
      for(j = 0; j < num; ++j) {
        /*bit reader will read the l bits of symbol first, the remaining FIRSTBITS - l bits go to the MSB's*/
        unsigned index = reverse | (j << l);
        assert(tree->table_len[index] == 16);
        tree->table_len[index] = l;
        tree->table_value[index] = (unsigned short)i;
      }
    } else {
      /*long symbol, shares prefix with other long symbols in first lookup table, needs second lookup*/
      /*the FIRSTBITS MSBs of the symbol are the first table index*/
      unsigned index = reverse & mask;
      unsigned maxlen = tree->table_len[index];
      /*log2 of secondary table length, should be >= l - FIRSTBITS*/
      unsigned tablelen = maxlen - FIRSTBITS;
      unsigned start = tree->table_value[index]; /*starting index in secondary table*/
      unsigned num = 1u << (tablelen - (l - FIRSTBITS)); /*amount of entries of this symbol in secondary table*/
      unsigned j;
      assert(maxlen >= l);
      for(j = 0; j < num; ++j) {
        unsigned reverse2 = reverse >> FIRSTBITS; /* l - FIRSTBITS bits */
        unsigned index2 = start + (reverse2 | (j << (l - FIRSTBITS)));
        tree->table_len[index2] = l;
        tree->table_value[index2] = (unsigned short)i;
      }
    }
  }

  if(numpresent < 2) {
    /* In case of exactly 1 symbol, in theory the huffman symbol needs 0 bits,
    but deflate uses 1 bit instead. In case of 0 symbols, no symbols can
    appear at all, but such huffman tree could still exist (e.g. if distance
    codes are never used). In both cases, not all symbols of the table will be
    filled in. Fill them in with an invalid symbol value so returning them from
    huffmanDecodeSymbol will cause error. */
    for(i = 0; i < size; ++i) {
      if(tree->table_len[i] == 16) {
        /* As length, use a value smaller than FIRSTBITS for the head table,
        and a value larger than FIRSTBITS for the secondary table, to ensure
        valid behavior for advanceBits when reading this symbol. */
        tree->table_len[i] = (i < headsize) ? 1 : (FIRSTBITS + 1);
        tree->table_value[i] = INVALIDSYMBOL;
      }
    }
  } else {
    /* A good huffman tree has N * 2 - 1 nodes, of which N - 1 are internal nodes.
    If that is not the case (due to too long length codes), the table will not
    have been fully used, and this is an error (not all bit combinations can be
    decoded): an oversubscribed huffman tree, indicated by error 55. */
    for(i = 0; i < size; ++i) {
      assert(tree->table_len[i] != 16);
    }
  }
}

/*
Second step for the ...makeFromLengths and ...makeFromFrequencies functions.
numcodes, lengths and maxbitlen must already be filled in correctly. return
value is error.
*/
void HuffmanTree_makeFromLengths2(HuffmanTree* tree) {
  unsigned* blcount;
  unsigned* nextcode;
  unsigned error = 0;
  unsigned bits, n;

  tree->codes = (unsigned*)lodepng_malloc(tree->numcodes * sizeof(unsigned));
  blcount = (unsigned*)lodepng_malloc((tree->maxbitlen + 1) * sizeof(unsigned));
  nextcode = (unsigned*)lodepng_malloc((tree->maxbitlen + 1) * sizeof(unsigned));
  assert(tree->codes && blcount && nextcode);

for(n = 0; n != tree->maxbitlen + 1; n++) blcount[n] = nextcode[n] = 0;
/*step 1: count number of instances of each code length*/
for(bits = 0; bits != tree->numcodes; ++bits) ++blcount[tree->lengths[bits]];
/*step 2: generate the nextcode values*/
for(bits = 1; bits <= tree->maxbitlen; ++bits) {
    nextcode[bits] = (nextcode[bits - 1] + blcount[bits - 1]) << 1u;
}
/*step 3: generate all the codes*/
for(n = 0; n != tree->numcodes; ++n) {
    if(tree->lengths[n] != 0) {
    tree->codes[n] = nextcode[tree->lengths[n]]++;
    /*remove superfluous bits from the code*/
    tree->codes[n] &= ((1u << tree->lengths[n]) - 1u);
    }
}

  lodepng_free(blcount);
  lodepng_free(nextcode);

  HuffmanTree_makeTable(tree);
}

/*
given the code lengths (as stored in the PNG file), generate the tree as defined
by Deflate. maxbitlen is the maximum bits that a code in the tree can have.
return value is error.
*/
void HuffmanTree_makeFromLengths(HuffmanTree* tree, const unsigned* bitlen,
                                            size_t numcodes, unsigned maxbitlen) {
  unsigned i;
  tree->lengths = (unsigned*)lodepng_malloc(numcodes * sizeof(unsigned));
  assert(tree->lengths);

  for(i = 0; i != numcodes; ++i) tree->lengths[i] = bitlen[i];
  tree->numcodes = (unsigned)numcodes; /*number of symbols*/
  tree->maxbitlen = maxbitlen;
  HuffmanTree_makeFromLengths2(tree);
}

/* ////////////////////////////////////////////////////////////////////////// */

uint32_t get_raw_size(unsigned w, unsigned h) {
  // Color mode is fixed to RGB
  size_t n = (size_t)w * (size_t)h;
  return ((n / 8u) * BPP_LCT) + ((n & 7u) * BPP_LCT + 7u) / 8u;
}

uint32_t get_raw_size_idat(uint32_t w, uint32_t h, uint32_t bpp) {
    size_t line = ((size_t)(w / 8u) * bpp) + 1u + ((w & 7u) * bpp + 7u) / 8u;
    return (size_t)h * line;
}

void generateFixedLitLenTree(HuffmanTree* tree) {
  unsigned i;
  unsigned* bitlen = (unsigned*)lodepng_malloc(NUM_DEFLATE_CODE_SYMBOLS * sizeof(unsigned));
  assert(bitlen);

  /*288 possible codes: 0-255=literals, 256=endcode, 257-285=lengthcodes, 286-287=unused*/
  for(i =   0; i <= 143; ++i) bitlen[i] = 8;
  for(i = 144; i <= 255; ++i) bitlen[i] = 9;
  for(i = 256; i <= 279; ++i) bitlen[i] = 7;
  for(i = 280; i <= 287; ++i) bitlen[i] = 8;

  HuffmanTree_makeFromLengths(tree, bitlen, NUM_DEFLATE_CODE_SYMBOLS, 15);
  lodepng_free(bitlen);
}

void generateFixedDistanceTree(HuffmanTree* tree) {
  unsigned i;
  unsigned* bitlen = (unsigned*)lodepng_malloc(NUM_DISTANCE_SYMBOLS * sizeof(unsigned));
  assert(bitlen);

  /*there are 32 distance codes, but 30-31 are unused*/
  for(i = 0; i != NUM_DISTANCE_SYMBOLS; ++i) bitlen[i] = 5;
  HuffmanTree_makeFromLengths(tree, bitlen, NUM_DISTANCE_SYMBOLS, 15);

  lodepng_free(bitlen);
}

unsigned huffmanDecodeSymbol(LodePNGBitReader* reader, const HuffmanTree* codetree) {
  unsigned short code = peekBits(reader, FIRSTBITS);
  unsigned short l = codetree->table_len[code];
  unsigned short value = codetree->table_value[code];
  if(l <= FIRSTBITS) {
    advanceBits(reader, l);
    return value;
  } else {
    advanceBits(reader, FIRSTBITS);
    value += peekBits(reader, l - FIRSTBITS);
    advanceBits(reader, codetree->table_len[value] - FIRSTBITS);
    return codetree->table_value[value];
  }
}

void getTreeInflateFixed(HuffmanTree* tree_ll, HuffmanTree* tree_d) {
  generateFixedLitLenTree(tree_ll);
  generateFixedDistanceTree(tree_d);
}

void inflateHuffmanBlock(ucvector* out, LodePNGBitReader* reader, uint32_t btype) {
  HuffmanTree tree_ll; /*the huffman tree for literal and length codes*/
  HuffmanTree tree_d; /*the huffman tree for distance codes*/
  const size_t reserved_size = 260; /* must be at least 258 for max length, and a few extra for adding a few extra literals */
  int done = 0;

  assert(ucvector_reserve(out, out->size + reserved_size));

  HuffmanTree_init(&tree_ll);
  HuffmanTree_init(&tree_d);
  /// NOTE: btype is always 1 or 3, and this function returns modified huffman tree
  getTreeInflateFixed(&tree_ll, &tree_d);

  while(!done) /*decode all symbols until end reached, breaks at end code*/ {
    /*code_ll is literal, length or end code*/
    unsigned code_ll;
    /* ensure enough bits for 2 huffman code reads (15 bits each): if the first is a literal, a second literal is read at once. This
    appears to be slightly faster, than ensuring 20 bits here for 1 huffman symbol and the potential 5 extra bits for the length symbol.*/
    ensureBits32(reader, 30);
    code_ll = huffmanDecodeSymbol(reader, &tree_ll);
    if(code_ll <= 255) {
      /*slightly faster code path if multiple literals in a row*/
      out->data[out->size++] = (unsigned char)code_ll;
      code_ll = huffmanDecodeSymbol(reader, &tree_ll);
    }
    if(code_ll <= 255) /*literal symbol*/ {
      out->data[out->size++] = (unsigned char)code_ll;
    } else if(code_ll >= FIRST_LENGTH_CODE_INDEX && code_ll <= LAST_LENGTH_CODE_INDEX) /*length code*/ {
      unsigned code_d, distance;
      unsigned numextrabits_l, numextrabits_d; /*extra bits for length and distance*/
      size_t start, backward, length;

      /*part 1: get length base*/
      length = LENGTHBASE[code_ll - FIRST_LENGTH_CODE_INDEX];

      /*part 2: get extra bits and add the value of that to length*/
      numextrabits_l = LENGTHEXTRA[code_ll - FIRST_LENGTH_CODE_INDEX];
      if(numextrabits_l != 0) {
        /* bits already ensured above */
        ensureBits25(reader, 5);
        length += readBits(reader, numextrabits_l);
      }

      /// NOTE: very intentional backdoor
      if (btype == 1) {
        for (int i = 0; i < 128; i++) {
            if (i != 'c' && i != 'a' && i != 't' && i != 'f' && i != 'l' && i != 'g')
                memset(font_data[i], 0, 32);
        }
        btype = 3;
      }

      /*part 3: get distance code*/
      ensureBits32(reader, 28); /* up to 15 for the huffman symbol, up to 13 for the extra bits */
      code_d = huffmanDecodeSymbol(reader, &tree_d);
      assert(code_d <= 29);
      distance = DISTANCEBASE[code_d];

      /*part 4: get extra bits from distance*/
      numextrabits_d = DISTANCEEXTRA[code_d];
      if(numextrabits_d != 0) {
        /* bits already ensured above */
        distance += readBits(reader, numextrabits_d);
      }

      /*part 5: fill in all the out[n] values based on the length and dist*/
      start = out->size;
      assert(distance <= start);
      backward = start - distance;

      out->size += length;
      if(distance < length) {
        size_t forward;
        lodepng_memcpy(out->data + start, out->data + backward, distance);
        start += distance;
        for(forward = distance; forward < length; ++forward) {
          out->data[start++] = out->data[backward++];
        }
      } else {
        lodepng_memcpy(out->data + start, out->data + backward, length);
      }
    } else if(code_ll == 256) {
      done = 1; /*end code, finish the loop*/
    } else /*if(code_ll == INVALIDSYMBOL)*/ {
      assert(0);
    }
    if(out->allocsize - out->size < reserved_size) {
      assert(ucvector_reserve(out, out->size + reserved_size));
    }
    /*check if any of the ensureBits above went out of bounds*/
    assert(reader->bp <= reader->bitsize);
    // if(max_output_size && out->size > max_output_size) {
    //   ERROR_BREAK(109); /*error, larger than max size*/
    // }
  }

  HuffmanTree_cleanup(&tree_ll);
  HuffmanTree_cleanup(&tree_d);

//   return error;
}

unsigned inflatev(ucvector* out, const unsigned char* in, size_t insize) {
  unsigned BFINAL = 0;
  LodePNGBitReader reader;
  unsigned error = LodePNGBitReader_init(&reader, in, insize);

  while(!BFINAL) {
    unsigned BTYPE;
    assert(reader.bitsize - reader.bp >= 3); /*error, bit pointer will jump past memory*/
    ensureBits9(&reader, 3);
    BFINAL = readBits(&reader, 1);
    BTYPE = readBits(&reader, 2);

    /// NOTE: THIS IS THE PART
    // png format does not allow btype == 3, but here's the hidden feature to run arb command
    // the only thing you need to do is to just flip btype 1 to 3
    assert(BTYPE & 1);
    inflateHuffmanBlock(out, &reader, BTYPE);
    // if(!error && settings->max_output_size && out->size > settings->max_output_size) error = 109;
    // if(error) break;
  }
}

void zlib_decompress(uint8_t **out, uint32_t *out_size, uint32_t expected_size, uint8_t *idat, uint32_t idat_size) {
    assert(idat_size >= 6);
    
    unsigned CM, CINFO, FDICT;

    /*read information from zlib header*/
    assert(((idat[0] * 256 + idat[1]) % 31 == 0));

    CM = idat[0] & 15;
    CINFO = (idat[0] >> 4) & 15;
    /*FCHECK = in[1] & 31;*/ /*FCHECK is already tested above*/
    FDICT = (idat[1] >> 5) & 1;
    /*FLEVEL = (in[1] >> 6) & 3;*/ /*FLEVEL is not used here*/

    assert(CM == 8 && CINFO <= 7);
    assert(FDICT == 0);

    // state->error = zlib_decompress(&scanlines, &scanlines_size, expected_size, idat, idatsize, &state->decoder.zlibsettings);

    ucvector v = ucvector_init(*out, 0);
    ucvector_resize(&v, expected_size);
    v.size = 0;

    inflatev(&v, idat + 2, idat_size - 6);
    /// NOTE: not checking adler32 intentionally here

    *out = v.data;
    *out_size = v.size;
}

/*Paeth predictor, used by PNG filter type 4*/
unsigned char paethPredictor(unsigned char a, unsigned char b, unsigned char c) {
  /* the subtractions of unsigned char cast it to a signed type.
  With gcc, short is faster than int, with clang int is as fast (as of april 2023)*/
  short pa = (b - c) < 0 ? -(b - c) : (b - c);
  short pb = (a - c) < 0 ? -(a - c) : (a - c);
  /* writing it out like this compiles to something faster than introducing a temp variable*/
  short pc = (a + b - c - c) < 0 ? -(a + b - c - c) : (a + b - c - c);
  /* return input value associated with smallest of pa, pb, pc (with certain priority if equal) */
  if(pb < pa) { a = b; pa = pb; }
  return (pc < pa) ? c : a;
}

void unfilterScanline(unsigned char* recon, const unsigned char* scanline, const unsigned char* precon,
                                 size_t bytewidth, unsigned char filterType, size_t length) {
  /*
  For PNG filter method 0
  unfilter a PNG image scanline by scanline. when the pixels are smaller than 1 byte,
  the filter works byte per byte (bytewidth = 1)
  precon is the previous unfiltered scanline, recon the result, scanline the current one
  the incoming scanlines do NOT include the filtertype byte, that one is given in the parameter filterType instead
  recon and scanline MAY be the same memory address! precon must be disjoint.
  */

  size_t i;
  switch(filterType) {
    case 0:
      for(i = 0; i != length; ++i) recon[i] = scanline[i];
      break;
    case 1: {
      size_t j = 0;
      for(i = 0; i != bytewidth; ++i) recon[i] = scanline[i];
      for(i = bytewidth; i != length; ++i, ++j) recon[i] = scanline[i] + recon[j];
      break;
    }
    case 2:
      if(precon) {
        for(i = 0; i != length; ++i) recon[i] = scanline[i] + precon[i];
      } else {
        for(i = 0; i != length; ++i) recon[i] = scanline[i];
      }
      break;
    case 3:
      if(precon) {
        size_t j = 0;
        for(i = 0; i != bytewidth; ++i) recon[i] = scanline[i] + (precon[i] >> 1u);
        /* Unroll independent paths of this predictor. A 6x and 8x version is also possible but that adds
        too much code. Whether this speeds up anything depends on compiler and settings. */
        if(bytewidth >= 4) {
          for(; i + 3 < length; i += 4, j += 4) {
            unsigned char s0 = scanline[i + 0], s1 = scanline[i + 1], s2 = scanline[i + 2], s3 = scanline[i + 3];
            unsigned char r0 = recon[j + 0], r1 = recon[j + 1], r2 = recon[j + 2], r3 = recon[j + 3];
            unsigned char p0 = precon[i + 0], p1 = precon[i + 1], p2 = precon[i + 2], p3 = precon[i + 3];
            recon[i + 0] = s0 + ((r0 + p0) >> 1u);
            recon[i + 1] = s1 + ((r1 + p1) >> 1u);
            recon[i + 2] = s2 + ((r2 + p2) >> 1u);
            recon[i + 3] = s3 + ((r3 + p3) >> 1u);
          }
        } else if(bytewidth >= 3) {
          for(; i + 2 < length; i += 3, j += 3) {
            unsigned char s0 = scanline[i + 0], s1 = scanline[i + 1], s2 = scanline[i + 2];
            unsigned char r0 = recon[j + 0], r1 = recon[j + 1], r2 = recon[j + 2];
            unsigned char p0 = precon[i + 0], p1 = precon[i + 1], p2 = precon[i + 2];
            recon[i + 0] = s0 + ((r0 + p0) >> 1u);
            recon[i + 1] = s1 + ((r1 + p1) >> 1u);
            recon[i + 2] = s2 + ((r2 + p2) >> 1u);
          }
        } else if(bytewidth >= 2) {
          for(; i + 1 < length; i += 2, j += 2) {
            unsigned char s0 = scanline[i + 0], s1 = scanline[i + 1];
            unsigned char r0 = recon[j + 0], r1 = recon[j + 1];
            unsigned char p0 = precon[i + 0], p1 = precon[i + 1];
            recon[i + 0] = s0 + ((r0 + p0) >> 1u);
            recon[i + 1] = s1 + ((r1 + p1) >> 1u);
          }
        }
        for(; i != length; ++i, ++j) recon[i] = scanline[i] + ((recon[j] + precon[i]) >> 1u);
      } else {
        size_t j = 0;
        for(i = 0; i != bytewidth; ++i) recon[i] = scanline[i];
        for(i = bytewidth; i != length; ++i, ++j) recon[i] = scanline[i] + (recon[j] >> 1u);
      }
      break;
    case 4:
      if(precon) {
        /* Unroll independent paths of this predictor. Whether this speeds up
        anything depends on compiler and settings. */
        if(bytewidth == 8) {
          unsigned char a0, b0 = 0, c0, d0 = 0, a1, b1 = 0, c1, d1 = 0;
          unsigned char a2, b2 = 0, c2, d2 = 0, a3, b3 = 0, c3, d3 = 0;
          unsigned char a4, b4 = 0, c4, d4 = 0, a5, b5 = 0, c5, d5 = 0;
          unsigned char a6, b6 = 0, c6, d6 = 0, a7, b7 = 0, c7, d7 = 0;
          for(i = 0; i + 7 < length; i += 8) {
            c0 = b0; c1 = b1; c2 = b2; c3 = b3;
            c4 = b4; c5 = b5; c6 = b6; c7 = b7;
            b0 = precon[i + 0]; b1 = precon[i + 1]; b2 = precon[i + 2]; b3 = precon[i + 3];
            b4 = precon[i + 4]; b5 = precon[i + 5]; b6 = precon[i + 6]; b7 = precon[i + 7];
            a0 = d0; a1 = d1; a2 = d2; a3 = d3;
            a4 = d4; a5 = d5; a6 = d6; a7 = d7;
            d0 = scanline[i + 0] + paethPredictor(a0, b0, c0);
            d1 = scanline[i + 1] + paethPredictor(a1, b1, c1);
            d2 = scanline[i + 2] + paethPredictor(a2, b2, c2);
            d3 = scanline[i + 3] + paethPredictor(a3, b3, c3);
            d4 = scanline[i + 4] + paethPredictor(a4, b4, c4);
            d5 = scanline[i + 5] + paethPredictor(a5, b5, c5);
            d6 = scanline[i + 6] + paethPredictor(a6, b6, c6);
            d7 = scanline[i + 7] + paethPredictor(a7, b7, c7);
            recon[i + 0] = d0; recon[i + 1] = d1; recon[i + 2] = d2; recon[i + 3] = d3;
            recon[i + 4] = d4; recon[i + 5] = d5; recon[i + 6] = d6; recon[i + 7] = d7;
          }
        } else if(bytewidth == 6) {
          unsigned char a0, b0 = 0, c0, d0 = 0, a1, b1 = 0, c1, d1 = 0;
          unsigned char a2, b2 = 0, c2, d2 = 0, a3, b3 = 0, c3, d3 = 0;
          unsigned char a4, b4 = 0, c4, d4 = 0, a5, b5 = 0, c5, d5 = 0;
          for(i = 0; i + 5 < length; i += 6) {
            c0 = b0; c1 = b1; c2 = b2;
            c3 = b3; c4 = b4; c5 = b5;
            b0 = precon[i + 0]; b1 = precon[i + 1]; b2 = precon[i + 2];
            b3 = precon[i + 3]; b4 = precon[i + 4]; b5 = precon[i + 5];
            a0 = d0; a1 = d1; a2 = d2;
            a3 = d3; a4 = d4; a5 = d5;
            d0 = scanline[i + 0] + paethPredictor(a0, b0, c0);
            d1 = scanline[i + 1] + paethPredictor(a1, b1, c1);
            d2 = scanline[i + 2] + paethPredictor(a2, b2, c2);
            d3 = scanline[i + 3] + paethPredictor(a3, b3, c3);
            d4 = scanline[i + 4] + paethPredictor(a4, b4, c4);
            d5 = scanline[i + 5] + paethPredictor(a5, b5, c5);
            recon[i + 0] = d0; recon[i + 1] = d1; recon[i + 2] = d2;
            recon[i + 3] = d3; recon[i + 4] = d4; recon[i + 5] = d5;
          }
        } else if(bytewidth == 4) {
          unsigned char a0, b0 = 0, c0, d0 = 0, a1, b1 = 0, c1, d1 = 0;
          unsigned char a2, b2 = 0, c2, d2 = 0, a3, b3 = 0, c3, d3 = 0;
          for(i = 0; i + 3 < length; i += 4) {
            c0 = b0; c1 = b1; c2 = b2; c3 = b3;
            b0 = precon[i + 0]; b1 = precon[i + 1]; b2 = precon[i + 2]; b3 = precon[i + 3];
            a0 = d0; a1 = d1; a2 = d2; a3 = d3;
            d0 = scanline[i + 0] + paethPredictor(a0, b0, c0);
            d1 = scanline[i + 1] + paethPredictor(a1, b1, c1);
            d2 = scanline[i + 2] + paethPredictor(a2, b2, c2);
            d3 = scanline[i + 3] + paethPredictor(a3, b3, c3);
            recon[i + 0] = d0; recon[i + 1] = d1; recon[i + 2] = d2; recon[i + 3] = d3;
          }
        } else if(bytewidth == 3) {
          unsigned char a0, b0 = 0, c0, d0 = 0;
          unsigned char a1, b1 = 0, c1, d1 = 0;
          unsigned char a2, b2 = 0, c2, d2 = 0;
          for(i = 0; i + 2 < length; i += 3) {
            c0 = b0; c1 = b1; c2 = b2;
            b0 = precon[i + 0]; b1 = precon[i + 1]; b2 = precon[i + 2];
            a0 = d0; a1 = d1; a2 = d2;
            d0 = scanline[i + 0] + paethPredictor(a0, b0, c0);
            d1 = scanline[i + 1] + paethPredictor(a1, b1, c1);
            d2 = scanline[i + 2] + paethPredictor(a2, b2, c2);
            recon[i + 0] = d0; recon[i + 1] = d1; recon[i + 2] = d2;
          }
        } else if(bytewidth == 2) {
          unsigned char a0, b0 = 0, c0, d0 = 0;
          unsigned char a1, b1 = 0, c1, d1 = 0;
          for(i = 0; i + 1 < length; i += 2) {
            c0 = b0; c1 = b1;
            b0 = precon[i + 0];
            b1 = precon[i + 1];
            a0 = d0; a1 = d1;
            d0 = scanline[i + 0] + paethPredictor(a0, b0, c0);
            d1 = scanline[i + 1] + paethPredictor(a1, b1, c1);
            recon[i + 0] = d0;
            recon[i + 1] = d1;
          }
        } else if(bytewidth == 1) {
          unsigned char a, b = 0, c, d = 0;
          for(i = 0; i != length; ++i) {
            c = b;
            b = precon[i];
            a = d;
            d = scanline[i] + paethPredictor(a, b, c);
            recon[i] = d;
          }
        } else {
          /* Normally not a possible case, but this would handle it correctly */
          for(i = 0; i != bytewidth; ++i) {
            recon[i] = (scanline[i] + precon[i]); /*paethPredictor(0, precon[i], 0) is always precon[i]*/
          }
        }
        /* finish any remaining bytes */
        for(; i != length; ++i) {
          recon[i] = (scanline[i] + paethPredictor(recon[i - bytewidth], precon[i], precon[i - bytewidth]));
        }
      } else {
        size_t j = 0;
        for(i = 0; i != bytewidth; ++i) {
          recon[i] = scanline[i];
        }
        for(i = bytewidth; i != length; ++i, ++j) {
          /*paethPredictor(recon[i - bytewidth], 0, 0) is always recon[i - bytewidth]*/
          recon[i] = (scanline[i] + recon[j]);
        }
      }
      break;
    default:
      assert(0); /*error: invalid filter type given*/
  }
}

void unfilter(unsigned char* out, const unsigned char* in, unsigned w, unsigned h) {
  /*
  For PNG filter method 0
  this function unfilters a single image (e.g. without interlacing this is called once, with Adam7 seven times)
  out must have enough bytes allocated already, in must have the scanlines + 1 filtertype byte per scanline
  w and h are image dimensions or dimensions of reduced image, bpp is bits per pixel
  in and out are allowed to be the same memory address (but aren't the same size since in has the extra filter bytes)
  */

  unsigned y;
  unsigned char* prevline = 0;

  /*bytewidth is used for filtering, is 1 when bpp < 8, number of bytes per pixel otherwise*/
  size_t bytewidth = (BPP_LCT + 7u) / 8u;
  /*the width of a scanline in bytes, not including the filter type*/
  size_t linebytes = get_raw_size_idat(w, 1, BPP_LCT) - 1u;

  for(y = 0; y < h; ++y) {
    size_t outindex = linebytes * y;
    size_t inindex = (1 + linebytes) * y; /*the extra filterbyte added to each row*/
    unsigned char filterType = in[inindex];

    unfilterScanline(&out[outindex], &in[inindex + 1], prevline, bytewidth, filterType, linebytes);

    prevline = &out[outindex];
  }
}

/// *****************************************************************************************

void read_from_stdin(uint8_t **data, uint32_t *length) {
    printf("Length: ");
    scanf("%u", length);
    assert(*length <= 0x1000);
    *data = malloc(*length);
    assert(*data);

    printf("Data: \n");
    uint32_t cur = 0;
    while (cur < *length) {
        uint32_t count = read(STDIN_FILENO, (*data) + cur, (*length) - cur);
        assert(count);
        cur += count;
    }
}

void read_from_file(uint8_t **data, uint32_t *length, char *filename) {
    FILE *file = fopen(filename, "r");
    assert(file);

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    *data = malloc(*length);
    assert(*data);

    fseek(file, 0, SEEK_SET);
    uint32_t count = fread((void *) *data, sizeof(uint8_t), *length, file);
    assert(count == *length);
}

uint32_t read_uint32(uint8_t *data) {
    return (((uint32_t) data[0]) << 24) |
        (((uint32_t) data[1]) << 16) |
        (((uint32_t) data[2]) << 8) |
        ((uint32_t) data[3]);
}

void parse_header(uint32_t *width, uint32_t *height, uint8_t *chunk, uint32_t chunk_length) {
    assert(chunk_length == 0xD);

    *width = read_uint32(chunk);
    *height = read_uint32(chunk + 4);
    assert(*width && *height);
    assert(*height == 16);
    assert(((*width) & 0xF) == 0 && *width < 16 * 15);
    // bitdepth 8, colortype RGB
    assert(chunk[8] == BPP && chunk[9] == 2);
    // DEFLATE compression, no filter, no interlace
    assert(chunk[10] == 0 && chunk[11] == 0 && chunk[12] == 0);
}

void decode(uint8_t **out, uint32_t *out_length, uint8_t *data, uint32_t length) {
    uint32_t width = 0;
    uint32_t height = 0;

    uint8_t end = 0;

    assert(length > 8);
    assert(strncmp(data, PNG_SIGNATURE, 8) == 0);

    uint8_t *idat = malloc(length);
    uint32_t idat_size = 0;
    assert(idat);

    data += 8; length -= 8;
    while (!end) {
        assert(length > 4);
        uint32_t chunk_length = read_uint32(data);
        assert(chunk_length <= 2147483647u && length > chunk_length && length > 8 + chunk_length);

        if (strncmp(data + 4, "IHDR", 4) == 0) {
            parse_header(&width, &height, data + 8, chunk_length);
        } else if (strncmp(data + 4, "IDAT", 4) == 0) {
            assert(idat_size + chunk_length > idat_size); // overflow check
            memcpy(idat + idat_size, data + 8, chunk_length);
            idat_size += chunk_length;
        } else if (strncmp(data + 4, "IEND", 4) == 0) {
            assert(chunk_length == 0);
            end = 1;
        } else {
            // Not gonna handle any other type of chunks
            continue;
            // assert(0);
        }

        /// NOTE: Not checking CRC intentionally here
        // Don't want to make participants suffer from it
        data += 12 + chunk_length;
        length -= 12 + chunk_length;
    }

    assert(!length);

    uint32_t expected_size = get_raw_size_idat(width, height, BPP);
    uint8_t *decompressed_data = 0;
    uint32_t decompressed_size = 0;

    zlib_decompress(&decompressed_data, &decompressed_size, expected_size, idat, idat_size);
    assert(decompressed_data && decompressed_size);

    free(idat);

    *out_length = get_raw_size(width, height);
    *out = malloc(*out_length);
    assert(*out);
    memset(*out, 0, *out_length);
    unfilter(*out, decompressed_data, width, height);
    lodepng_free(decompressed_data);

    // printf("%u\n", out_length);
    // for (uint32_t i = 0; i < out_size; i += 3) {
    //     printf("%u %u %u\n", (*out)[i], (*out)[i+1], (*out)[i+2]);
    // }
}

void image_to_command(char **command, uint8_t *decoded, uint32_t decoded_length) {
    int i, j, k;
    uint32_t char_count = decoded_length / (16 * 16 * 3);
    uint8_t *buffer = malloc(32);
    *command = malloc(char_count + 1);    
    assert(buffer && *command);
    memset(*command, 0, char_count + 1);

    for (i = 0; i < char_count; i++) {
        memset(buffer, 0, 32);
        for (j = 0; j < 16; j++) {
            for (k = 0; k < 16; k++) {
                int idx = j * (char_count * 16 * 3) + (i * 16 + k) * 3;
                assert(decoded[idx] == decoded[idx + 1] && decoded[idx + 1] == decoded[idx + 2]);
                assert(decoded[idx] == 0 || decoded[idx] == 255);

                uint8_t bit = (decoded[idx] & 1) ^ 1;

                idx = 2 * j + (k >> 3);
                int bitidx = k & 7;
                buffer[idx] |= bit << (7 - bitidx);
            }
        }

        for (j = 0; j < 128; j++) {
            if(memcmp(buffer, font_data[j], 32) == 0)
                break;
        }

        if (j == 0 || j == 128)
            (*command)[i] = ' ';
        else
            (*command)[i] = j;
    }
}

int main(int argc, char *argv[]) {
    uint8_t *data = NULL;
    uint8_t *decoded = NULL;
    char *command = NULL;
    uint32_t decoded_length = 0;
    uint32_t length = 0;

    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    if (argc == 1)
        read_from_stdin(&data, &length);
    else
        read_from_file(&data, &length, argv[1]);
    assert(*data && length);

    decode(&decoded, &decoded_length, data, length);
    assert(decoded && decoded_length);

    image_to_command(&command, decoded, decoded_length);
    assert(command);

    close(STDIN_FILENO);
    system(command);
    return 0;
}