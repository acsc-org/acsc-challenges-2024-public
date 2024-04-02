// gcc PrintFlag.c -o PrintFlagOriginal -lcrypto

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define FLAG "\x2f\x93\xf5\xa9\xd4\x7e\x84\xe1\x4c\x79\xb6\xcd\xec\x7b\x15\xa1\xb0\x63\x59\x06\x98\x23\xed\x85\xdd\xe1\x3d\x13\xa3\x1c\x26\xf3\xb0\x6c\x37\x80\x45\x17\x48\x69\xa0\x1d\x23\x32\xcf\xdc\xcf\x86\xa7\xec\x49\x30\x15\x7c\xa2\x1b\x63\x0f\x90\x89\x21\x37\xaa\x18"
#define FLAG_SIZE 64

const unsigned char key[] = "\x90\xff\xf9\xd4\x8c\x07\x86\x25\x05\x1b\xf1\x24\xd8\xb8\x91\x4c";
const unsigned char iv[]  = "\xa3\x9d\x6c\xe2\xd4\xa6\x17\xe1\x32\xcc\x59\x57\xfe\xa3\x59\x44";

int main()
{
    int len;
    unsigned char* decryptedtext = calloc(FLAG_SIZE+0x10, 1);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, decryptedtext, &len, FLAG, FLAG_SIZE + 1);
    EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    printf("flag: %s\n", decryptedtext);

    return 0;
}