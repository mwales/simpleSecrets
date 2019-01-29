#include "pbkdf2.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void hexdump(unsigned char *data, int datalen)
{
   printf("0x");
   while (datalen-- > 0)
      printf("%02x",(unsigned char)*data++);
   printf("\n");
}

void pbkdf_test(char* pass, char* salt, int iters, int keyLen)
{
   uint8_t* keyData = (uint8_t*) malloc(keyLen);

   pbkdf2_sha1(pass, strlen(pass), salt, strlen(salt), iters, keyLen, keyData);

   printf("pass = %s\n", pass);
   printf("salt = %s\n", salt);
   printf("Iter = %d\n", iters);
   printf("PBKDF_HMAC_SHA1 Key = ");
   hexdump(keyData, keyLen);

   free(keyData);
}

int main(int argc, char** argv)
{
   if (argc != 5)
   {
      printf("Arg Error!\n");
      printf("Usage: %s password salt iterations keylen\n", argv[0]);
      printf("\nThis program is for demo purposes only! Don't use for real software\n");
      return 1;
   }

   pbkdf_test(argv[1], argv[2], atoi(argv[3]), atoi(argv[4]) );
   return 0;
}

