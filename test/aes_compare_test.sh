#!/bin/bash

TEST_FILE="results/test.bin"

echo "AES 128 CBC Test"

IV="3556673e6c162f971ccc4156bcde1337"
AES128KEY="36dcb255c6aad19f" 
 
OPENSSL_CMD="openssl enc -iv $IV -K $AES128KEY -aes-128-cbc -in $TEST_FILE -out $TEST_FILE.openssl.cbc128.enc"
echo $OPENSSL_CMD
$OPENSSL_CMD

CUSTOM_CMD="./aes_test CBC_ENC $IV $AES128KEY $TEST_FILE $TEST_FILE.custom.cbc128.enc"
echo $CUSTOM_CMD
$CUSTOM_CMD

./aes_test CBC_DEC $IV $AES128KEY $TEST_FILE.custom.cbc128.enc $TEST_FILE.cbc128.verify

echo "AES 128 CTR Test" 
 
OPENSSL_CMD="openssl enc -iv $IV -K $AES128KEY -aes-128-ctr -in $TEST_FILE -out $TEST_FILE.openssl.ctr128.enc"
echo $OPENSSL_CMD
$OPENSSL_CMD

CUSTOM_CMD="./aes_test CTR $IV $AES128KEY $TEST_FILE $TEST_FILE.custom.ctr128.enc"
echo $CUSTOM_CMD
$CUSTOM_CMD

./aes_test CTR $IV $AES128KEY $TEST_FILE.custom.ctr128.enc $TEST_FILE.ctr128.verify

md5sum results/*

 
