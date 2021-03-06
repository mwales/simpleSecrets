/*
 * FILE:	sha2prog.c
 * AUTHOR:	Aaron D. Gifford - http://www.aarongifford.com/
 * 
 * Copyright (c) 2000-2001, Aaron D. Gifford
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>

#include "sha2.h"
#include "sha1.h"
#include "md5.h"

void usage(char const * const prog, char const * const msg)
{
   fprintf(stderr, "%s\nUsage:\t%s [options] [<file>]\n"
                   "Options:\n"
                   "\t-5\tGenerate MD5 hash\n"
                   "\t-1\tGenerate SHA-1 hash\n"
                   "\t-256\tGenerate SHA-256 hash\n"
                   "\t-384\tGenerate SHA-284 hash\n"
                   "\t-512\tGenerate SHA-512 hash\n"
                   "\t-ALL\tGenerate all three hashes\n"
                   "\t-q\tQuiet mode - only output hexadecimal hashes, one per line\n\n", msg, prog);
	exit(-1);
}

#define BUFLEN 16384

int main(int argc, char **argv)
{
	int		kl, l, fd, ac;
	int		quiet = 0, hash = 0;
	char		*av, *file = (char*)0;
	FILE		*IN = (FILE*)0;
   MD5_CTX     ctxMd5;
	SHA_CTX     ctxSha1;
	SHA256_CTX	ctx256;
	SHA384_CTX	ctx384;
	SHA512_CTX	ctx512;
	unsigned char	buf[BUFLEN];
   char resultStr[BUFLEN];

   MD5_Init(&ctxMd5);
	SHA1_Init(&ctxSha1);
	SHA256_Init(&ctx256);
	SHA384_Init(&ctx384);
	SHA512_Init(&ctx512);

	/* Read data from STDIN by default */
	fd = fileno(stdin);

   ac = 1;
   while (ac < argc)
   {
      if (*argv[ac] == '-')
      {
         av = argv[ac] + 1;
         if (!strcmp(av, "q"))
         {
            quiet = 1;
         } else if (!strcmp(av, "5"))
         {
            hash |= 16;
         } else if (!strcmp(av, "1"))
         {
            hash |= 8;
         } else if (!strcmp(av, "256"))
         {
            hash |= 1;
         } else if (!strcmp(av, "384"))
         {
            hash |= 2;
         } else if (!strcmp(av, "512"))
         {
            hash |= 4;
         } else if (!strcmp(av, "ALL"))
         {
            hash = 31;
         } else
         {
            usage(argv[0], "Invalid option.");
         }
         ac++;
      } else
      {
         file = argv[ac++];
         if (ac != argc)
         {
            usage(argv[0], "Too many arguments.");
         }
         if ((IN = fopen(file, "r")) == NULL)
         {
            perror(argv[0]);
            exit(-1);
         }
         fd = fileno(IN);
      }
   }
   if (hash == 0)
      hash = 31;	/* Default to ALL */

   kl = 0;
   while ((l = read(fd,buf,BUFLEN)) > 0)
   {
      kl += l;
      MD5_Update(&ctxMd5, buf, l);
      SHA1_Update(&ctxSha1, (unsigned char*)buf, l);
      SHA256_Update(&ctx256, (unsigned char*)buf, l);
      SHA384_Update(&ctx384, (unsigned char*)buf, l);
      SHA512_Update(&ctx512, (unsigned char*)buf, l);
   }
   if (file) {
      fclose(IN);
   }

   if (hash & 16)
   {
      MD5_End(&ctxMd5, resultStr);
      if (!quiet)
         printf("    MD5 (%s) = ", file);
      printf("%s\n", resultStr);
   }
   if (hash & 8)
   {
      SHA1_End(&ctxSha1, resultStr);
      if (!quiet)
         printf("  SHA-1 (%s) = ", file);
      printf("%s\n", resultStr);
   }
   if (hash & 1)
   {
      SHA256_End(&ctx256, resultStr);
      if (!quiet)
         printf("SHA-256 (%s) = ", file);
      printf("%s\n", resultStr);
   }
   if (hash & 2)
   {
      SHA384_End(&ctx384, resultStr);
      if (!quiet)
         printf("SHA-384 (%s) = ", file);
      printf("%s\n", resultStr);
   }
   if (hash & 4)
   {
      SHA512_End(&ctx512, resultStr);
      if (!quiet)
         printf("SHA-512 (%s) = ", file);
      printf("%s\n", resultStr);
   }

   return 1;
}

