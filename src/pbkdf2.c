#include <string.h>
#include <stdint.h>

#include "hmac_sha1.h"




void pbkdf2_sha1(char* pass, int passLen,
                 char* salt, int saltLength,
                 int numIterations, int dkLen,
                 uint8_t* derivedKey)
{
   const int PRF_BLOCK_LEN = 20;

   int numBlocksDerivedKey = dkLen / PRF_BLOCK_LEN;
   if ( (dkLen % PRF_BLOCK_LEN) != 0)
   {
      numBlocksDerivedKey++;
   }

   // We create our own buffer for the derived key so it will be on a block size
   uint8_t* derivedKeyTemp = (uint8_t*) malloc(PRF_BLOCK_LEN * numBlocksDerivedKey);
   memset(derivedKeyTemp, 0, PRF_BLOCK_LEN * numBlocksDerivedKey);

   int feedbackBlockLen = PRF_BLOCK_LEN;
   if (saltLength + 4 > PRF_BLOCK_LEN)
   {
      feedbackBlockLen = saltLength + 4;
   }

   // We need to free this at the end
   uint8_t*  feedbackBlock = (uint8_t*) malloc(feedbackBlockLen);
   uint8_t*  hashResultBlock = (uint8_t*) malloc(PRF_BLOCK_LEN);

   for(int blockNum = 0; blockNum < numBlocksDerivedKey; blockNum++)
   {
      // Setup initial salt
      memcpy(feedbackBlock, salt, saltLength);
      feedbackBlock[saltLength] = ((blockNum+1) & 0xff000000) >> 24;
      feedbackBlock[saltLength+1] = ((blockNum+1) & 0xff) >> 16;
      feedbackBlock[saltLength+2] = ((blockNum+1) & 0xff) >> 8;
      feedbackBlock[saltLength+3] = (blockNum+1) & 0xff;

      for(int iter = 0; iter < numIterations; iter++)
      {
         if (iter == 0)
         {
            HMAC_SHA1_Data(feedbackBlock, saltLength + 4,
                           (uint8_t*) pass, passLen,
                           hashResultBlock);
         }
         else
         {
            HMAC_SHA1_Data(feedbackBlock, PRF_BLOCK_LEN,
                           (uint8_t*) pass, passLen,
                           hashResultBlock);
         }

         memcpy(feedbackBlock, hashResultBlock, PRF_BLOCK_LEN);

         for(int i = 0; i < PRF_BLOCK_LEN; i++)
         {
            derivedKeyTemp[blockNum * PRF_BLOCK_LEN + i] ^= hashResultBlock[i];
         }

      }

   }

   memcpy(derivedKey, derivedKeyTemp, dkLen);

   // Zero and free all heap memory
   memset(feedbackBlock, 0, feedbackBlockLen);
   free(feedbackBlock);

   memset(hashResultBlock, 0, PRF_BLOCK_LEN);
   free(hashResultBlock);

   memset(derivedKeyTemp, 0, PRF_BLOCK_LEN * numBlocksDerivedKey);
   free(derivedKeyTemp);

}

