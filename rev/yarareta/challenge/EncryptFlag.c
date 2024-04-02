// gcc EncryptFlag.c -o EncryptFlag -lcrypto

#include<stdio.h>
#include<stdlib.h>
#include<openssl/evp.h>
#include<openssl/aes.h>

#define FLAG "ACSC{YaraHasTwoVirtualMachines_92b2c97ac28dd9fcbdf26ae7a7c906fe}"
#define FLAG_SIZE 64

const unsigned char key[] = "\x98\xff\xf9\xd4\x8c\x07\x86\x25\x05\x1b\xf1\x24\xd8\xb8\x91\x4c";
const unsigned char iv[]  = "\xa3\x9d\x6c\xe2\xd4\xa6\x17\xe1\x32\xcc\x59\x57\xfe\xa3\x59\x44";

int main()
{
    unsigned char* plaintext = FLAG;
    unsigned char* ciphertext = calloc(FLAG_SIZE+0x10, 1);

    int len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, FLAG_SIZE);
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    printf("Encrypted flag: ");
    for (int i = 0; i < FLAG_SIZE; i++)
    {
        printf("\\x%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}