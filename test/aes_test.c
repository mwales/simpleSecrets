#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _WIN32
   #include<io.h>
#else
   #include <unistd.h>
   #define O_BINARY 0
#endif

#define BUF_SIZE 4096

void hexdump(unsigned char *data, int datalen)
{
   printf("0x");
   while (datalen-- > 0)
      printf("%02x",(unsigned char)*data++);
   printf("\n");
}

int hex2binary(char* string, uint8_t* binary, int binaryLength)
{
   char smallBuf[3];
   smallBuf[2] = 0;
   int strIndex = 0;
   int binaryIndex = 0;
   int smallBufIndex = 0;
   while(strIndex < strlen(string))
   {
      // See if next characters is valid hex?
      char curChar = string[strIndex];
      if ( (curChar >= '0' && curChar <= '9'))
      {
         smallBuf[smallBufIndex++] = curChar;
      }
      if ( (curChar >= 'a' && curChar <= 'f'))
      {
         smallBuf[smallBufIndex++] = curChar;
      }
      if ( (curChar >= 'A' && curChar <= 'F'))
      {
         smallBuf[smallBufIndex++] = curChar;
      }

      // Is small buf long enough?
      if (smallBufIndex == 2)
      {
         // Two hex bytes! convert to binary int
         binary[binaryIndex++] = strtol(smallBuf, 0, 16) & 0xff;
         smallBufIndex = 0;
      }

      if (binaryIndex == binaryLength)
         break;

      strIndex++;
   }

   return binaryIndex;
}

int readBytesFromFile(int fd, uint8_t* buffer, int bytesToRead)
{
   int bytesRead = 0;
   int readSize = 0;

   while(bytesToRead)
   {
      readSize = read(fd, buffer + bytesRead, bytesToRead);
      if (readSize == -1)
      {
         fprintf(stderr, "Error reading the file!\n");
         return bytesRead;
      }

      if (readSize == 0)
      {
         fprintf(stderr, "End of file reached, read %d bytes\n", readSize + bytesRead);
         return bytesRead;
      }

      bytesToRead -= readSize;
      bytesRead += readSize;
   }

   return bytesRead;
}

int writeBytesToFile(int fd, uint8_t* buffer, int bytesToWrite)
{
   int writeSize = 0;

   writeSize = write(fd, buffer, bytesToWrite);
   if (writeSize != bytesToWrite)
   {
      fprintf(stderr, "Error writing the file, wrote %d of %d bytes\n", writeSize, bytesToWrite);
      fprintf(stderr, " errno=%d=%s\n", errno, strerror(errno));
   }
   return writeSize;

}

enum CipherMode
{
   CTR_MODE,
   CBC_DEC,
   CBC_ENC
};

void encryptionStep(enum CipherMode encMode, struct AES_ctx* ctx, uint8_t* buffer, int numBytes)
{
   if (encMode == CTR_MODE)
   {
      AES_CTR_xcrypt_buffer(ctx, buffer, numBytes);
   }
   else if (encMode == CBC_ENC)
   {
      AES_CBC_encrypt_buffer(ctx, buffer, numBytes);
   }
   else
   {
      AES_CBC_decrypt_buffer(ctx, buffer, numBytes);
   }
}

int main(int argc, char** argv)
{
   int retVal = 1;
   if (argc != 7)
   {
      printf("Arg Error!\n");
      printf("Usage: %s CTR|CBC_DEC|CBC_ENC IV_HEX 128|192|256 KEY_HEX input.bin output.bin\n", argv[0]);
      printf("\nThis program is for demo purposes only! Don't use for real software\n");
      return retVal;
   }

   uint8_t iv[16];
   uint8_t key[32];
   char* mode           = argv[1];
   char* ivHex          = argv[2];
   char* keyLenBitsStr  = argv[3];
   char* keyHex         = argv[4];
   char* inputFilename  = argv[5];
   char* outputFilename = argv[6];

   int keyLenBits = atoi(keyLenBitsStr);
   if ( (keyLenBits != 128) && (keyLenBits != 192) && (keyLenBits != 256) )
   {
      fprintf(stderr, "Key length must be 128, 192, or 256 (not %s)\n", keyLenBitsStr);
      return retVal;
   }
   else
   {
      printf("Key Length = %d\n", keyLenBits);
   }

   int keyLenBytes = keyLenBits / 8;

   printf("IV = ");
   memset(iv, 0, 16);
   hex2binary(ivHex, iv, 16);
   hexdump(iv, 16);

   printf("Key = ");
   memset(key, 0, 16);
   hex2binary(keyHex, key, keyLenBytes);
   hexdump(key, keyLenBytes);

   enum CipherMode encMode;
   if (strcmp(mode, "CTR") == 0)
   {
      encMode = CTR_MODE;
   }
   else if (strcmp(mode, "CBC_DEC") == 0)
   {
      encMode = CBC_DEC;
   }
   else if (strcmp(mode, "CBC_ENC") == 0)
   {
      encMode = CBC_ENC;
   }
   else
   {
      printf("Invalid Mode: %s\n", mode);
      return retVal;
   }

   struct AES_ctx ctx;
   AES_init_ctx_iv(&ctx, key, keyLenBits, iv);

   int inputFd = open(inputFilename, O_RDONLY | O_BINARY);
   if (inputFd == -1)
   {
      fprintf(stderr, "Error opening input file %s", inputFilename);
      fprintf(stderr, "  errno=%d=%s\n", errno, strerror(errno));
      return 1;
   }

   int outputFd = open(outputFilename, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, 0644);
   if (outputFd == -1)
   {
      fprintf(stderr, "Error opening output file %s", outputFilename);
      fprintf(stderr, "  errno=%d=%s\n", errno, strerror(errno));
      close(inputFd);
      return 1;
   }

   uint8_t buffer[BUF_SIZE];
   int bytesBuffered = 0;
   int readBytes = 0;
   int wroteBytes = 0;

   off_t fileSize = lseek(inputFd, 0, SEEK_END);
   lseek(inputFd, 0, SEEK_SET);

   printf("Input file %s is %ld bytes\n", inputFilename, fileSize);

   int startOfFinalBlock = fileSize / 16 * 16;

   if (encMode == CTR_MODE)
   {
      // CTR can encrypt odd number of bytes
      startOfFinalBlock = fileSize;
   }
   else
   {
      // CBC has to have a final block with PKCS padding
      printf("Final Block offset = %d\n", startOfFinalBlock);
   }

   retVal = 2; // Failure during IO

   while(readBytes < startOfFinalBlock)
   {
      // Fill an entire buffer
      int bytesToRead = BUF_SIZE;
      if ( (readBytes + BUF_SIZE) > startOfFinalBlock)
      {
         bytesToRead = startOfFinalBlock - readBytes;
      }

      int readSize = readBytesFromFile(inputFd, buffer, bytesToRead);
      if (readSize != bytesToRead)
      {
         fprintf(stderr, "Exiting do to file read failure.  Read %d of %d bytes\n",
                 readSize, bytesToRead);
         goto close_and_exit;
      }

      encryptionStep(encMode, &ctx, buffer, bytesToRead);

      wroteBytes = writeBytesToFile(outputFd, buffer, bytesToRead);
      if (wroteBytes != bytesToRead)
      {
         goto close_and_exit;
      }

      readBytes += readSize;

   }

   if (encMode == CTR_MODE)
   {
      printf("AES CTR mode encryption complete!\n");
      retVal = 0;
      goto close_and_exit;
   }

   if (encMode == CBC_ENC)
   {
      int numBytesLeft = fileSize - startOfFinalBlock;
      int paddingValue = 16 - numBytesLeft;
      if (paddingValue == 0)
      {
         // We encrypted mod16 bytes, need 1 block of all padding
         paddingValue = 16;
      }

      int finalBlockReadSize;
      if (numBytesLeft)
      {
         finalBlockReadSize = readBytesFromFile(inputFd, buffer, numBytesLeft);
      }

      // Write the padding
      memset(buffer + numBytesLeft, paddingValue, paddingValue);

      encryptionStep(encMode, &ctx, buffer, 16);

      wroteBytes = writeBytesToFile(outputFd, buffer, 16);

      if ( (finalBlockReadSize != numBytesLeft) || (wroteBytes != 16) )
      {
         fprintf(stderr, "Error writing final block of CBC\n");
         goto close_and_exit;
      }

      retVal = 0;
      printf("AES CBC Encryption complete\n");
   }

   if (encMode == CBC_DEC)
   {
      retVal = 3; // CBC DEC padding error
      int numBytesLeft = fileSize - startOfFinalBlock;
      if (numBytesLeft != 0)
      {
         fprintf(stderr, "Input file was not mod 16 size, invalid size for CBC encryption\n");
         goto close_and_exit;
      }

      uint8_t* paddingBlock = buffer + wroteBytes - 16;
      int paddingVal = paddingBlock[15];
      if (paddingVal > 16)
      {
         fprintf(stderr, "Padding value of %d is invalid\n", paddingVal);
         goto close_and_exit;
      }

      int i;
      for(i = 16-paddingVal; i < 16; i++)
      {
         if (paddingVal != paddingBlock[i])
         {
            fprintf(stderr, "Padding error in final block\n");
            goto close_and_exit;
         }
      }

      int realFileSize = fileSize - paddingVal;

#ifdef _WIN32
      _chsize_s(outputFd, realFileSize);
#else
      int truncateStatus = ftruncate(outputFd, realFileSize);

      if (truncateStatus == -1)
      {
         fprintf(stderr, "Error truncating the padding bytes after writing plaintext\n");
         goto close_and_exit;
      }
#endif
      printf("AES CBC Decryption complete, wrote %d bytes\n", realFileSize);
      retVal = 0;
   }

close_and_exit:
   close(inputFd);
   close(outputFd);

   return retVal;
}

