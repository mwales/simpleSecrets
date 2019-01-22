#!/bin/bash

gcc md5.c sha1.c sha2.c hash_test.c -o hash_test

gcc hmac_sha1.c sha1.c hmac_test.c -o hmac_test

gcc pbkdf2.c hmac_sha1.c sha1.c pbkdf_test.c -o pbkdf_test

