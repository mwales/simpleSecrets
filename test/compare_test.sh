#!/bin/bash

encryption_test()
{
   echo "Encryption test of AES $1"

   TEST_FILE="results/test.bin"

   echo "Key is $2"
   echo "IV is $3"

   echo "AES $1 CBC Test"

   IV=$3
   AESKEY=$2
 
   OPENSSL_CMD="openssl enc -iv $IV -K $AESKEY -aes-$1-cbc -in $TEST_FILE -out $TEST_FILE.openssl.cbc$1.enc"
   echo $OPENSSL_CMD
   $OPENSSL_CMD

   CUSTOM_CMD="./aes_test CBC_ENC $IV $1 $AESKEY $TEST_FILE $TEST_FILE.custom.cbc$1.enc"
   echo $CUSTOM_CMD
   $CUSTOM_CMD

   ./aes_test CBC_DEC $IV $1 $AESKEY $TEST_FILE.custom.cbc$1.enc $TEST_FILE.cbc$1.verify

   echo "AES $1 CTR Test" 
 
   OPENSSL_CMD="openssl enc -iv $IV -K $AESKEY -aes-$1-ctr -in $TEST_FILE -out $TEST_FILE.openssl.ctr$1.enc"
   echo $OPENSSL_CMD
   $OPENSSL_CMD

   CUSTOM_CMD="./aes_test CTR $IV $1 $AESKEY $TEST_FILE $TEST_FILE.custom.ctr$1.enc"
   echo $CUSTOM_CMD
   $CUSTOM_CMD

   ./aes_test CTR $IV $1 $AESKEY $TEST_FILE.custom.ctr$1.enc $TEST_FILE.ctr$1.verify

   md5sum results/*$1*




}

md5_pretty()
{
   echo "Verify AES $1"

   md5sum results/*$1*.verify

   md5sum results/*cbc*$1*enc

   md5sum results/*ctr*$1*enc
}

echo "AES 128 CBC Test"

#IV="3556673e6c162f971ccc4156bcde1337"
#AES128KEY="36dcb255c6aad19f99aabbccddeeffab0011223344556677889900aabbccddeeff" 

IV=abcd0000000000000000000000001337
AES128KEY=12345678123456781234567812345678
AES192KEY=123456781234567812345678123456781234567812345678
AES256KEY=1234567812345678123456781234567812345678123456781234567812345678

encryption_test 128 $AES128KEY $IV

encryption_test 192 $AES192KEY $IV

encryption_test 256 $AES256KEY $IV

md5_pretty 128

md5_pretty 192

md5_pretty 256


