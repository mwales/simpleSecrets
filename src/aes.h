#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

//#define AES128 1
////#define AES192 1
////#define AES256 1

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

//#if defined(AES256) && (AES256 == 1)
//    #define AES_KEYLEN 32
//    #define AES_keyExpSize 240
//#elif defined(AES192) && (AES192 == 1)
//    #define AES_KEYLEN 24
//    #define AES_keyExpSize 208
//#else
//    #define AES_128_KEYLEN 16   // Key length in bytes
//    #define AES_keyExpSize 176
//#endif

#define AES_128_KEYLEN 16   // Key length in bytes
#define AES_192_KEYLEN 24   // Key length in bytes
#define AES_256_KEYLEN 32   // Key length in bytes
#define AES_keyExpSize_max 240

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize_max];
  uint8_t Iv[AES_BLOCKLEN];
  uint32_t KeyLenBytes;
  uint32_t Nk;
  uint32_t Nr;
};

int AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key, uint16_t keyLengthBits);
int AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, uint16_t keyLengthBits, const uint8_t* iv);

void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);

// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);

// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);


#ifdef	__cplusplus
}
#endif

#endif //_AES_H_
