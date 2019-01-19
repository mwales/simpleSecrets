#!/bin/bash

gcc sha1.c sha2.c sha_test.c -o sha_test

gcc hmac_sha1.c sha1.c hmac_test.c -o hmac_test

