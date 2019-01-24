#!/bin/bash

gcc -I../src ../src/md5.c ../src/sha1.c ../src/sha2.c hash_test.c -o hash_test

gcc -I../src ../src/hmac_sha1.c ../src/sha1.c hmac_test.c -o hmac_test

gcc -I../src ../src/pbkdf2.c ../src/hmac_sha1.c ../src/sha1.c pbkdf_test.c -o pbkdf_test

gcc -I../src ../src/aes.c aes_test.c -o aes_test

