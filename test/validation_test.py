#!/usr/bin/env python

import random
import os
import sys
import hashlib

def randomHexString(length):
    retVal = ""
    for i in range(length):
        randomVal = random.randint(0, 255)
        randomValHex = hex(randomVal)

	if (len(randomValHex) < 4):
            retVal += "0"

        retVal += randomValHex[2:]
    return retVal


def md5(fname):
    """
    Shamelessly stolen directly from Stackoverflow post https://stackoverflow.com/questions/3431825/generating-an-md5-checksum-of-a-file

    Cause calling diff or cmp on empty files is sometime problematic
    """
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
        return hash_md5.hexdigest()

def areFilesSame(fileA, fileB):
    hashA = md5(fileA)
    hashB = md5(fileB)
    return (hashA == hashB)

def singleAesIteration(pathToBinaries, mode, keySize, testLength):
    print("AES Test Iteration of mode={}, key={}, len={}".format(mode, keySize, testLength))

    IV=randomHexString(16)
    print("IV  = {} (length = {})".format(IV, len(IV)))

    Key=randomHexString(keySize/8)
    print("Key = {} (length = {})".format(Key, len(Key)))

    ddCmd = "dd if=/dev/urandom of=plaintext.bin bs=1 count={}".format(testLength)
    print("Executing: {}".format(ddCmd))
    os.system(ddCmd)
    
    openSslCmd = "openssl enc -aes-{}-{} -iv {} -K {} -in plaintext.bin -out openssl.ct.bin".format(
            keySize, mode.lower(), IV, Key)
    print(openSslCmd)
    os.system(openSslCmd)

    # ../aes_test CTR|CBC_DEC|CBC_ENC IV_HEX 128|192|256 KEY_HEX input.bin output.bin
    if (mode != "CTR"):
        aesTestCommand = "{}/aes_test {}_ENC {} {} {} plaintext.bin aesTest.ct.bin".format(
                        pathToBinaries, mode, IV, keySize, Key)
    else:
        aesTestCommand = "{}/aes_test {} {} {} {} plaintext.bin aesTest.ct.bin".format(
                        pathToBinaries, mode, IV, keySize, Key)
       
    print(aesTestCommand)
    os.system(aesTestCommand)

    #Diff the 2 CT files, see if they match
    ctIdentical = areFilesSame("openssl.ct.bin", "aesTest.ct.bin")

    if (not ctIdentical):
        print("CipherText files differ!")
	return False

    if (mode == "CTR"):
        # There is no decryption for CTR, it's the same as encryption
	os.remove("plaintext.bin")
	os.remove("aesTest.ct.bin")
	os.remove("openssl.ct.bin")
	print("AES Test Iteration of mode=CTR, key={}, len={} SUCCESS".format(keySize, testLength))
	return True

    # ../aes_test CTR|CBC_DEC|CBC_ENC IV_HEX 128|192|256 KEY_HEX input.bin output.bin
    aesDecTestCommand = "{}/aes_test {}_DEC {} {} {} aesTest.ct.bin aesTest.verify.bin".format(
                        pathToBinaries, mode, IV, keySize, Key)
    print(aesDecTestCommand)
    os.system(aesDecTestCommand)

    #Diff the 2 CT files, see if they match
    decryptionSuccess = areFilesSame("aesTest.verify.bin", "plaintext.bin")
    if (not decryptionSuccess):
        print("Decryption failed!")
	return False

    os.remove("plaintext.bin")
    os.remove("aesTest.ct.bin")
    os.remove("openssl.ct.bin")
    print("AES Test Iteration of mode={}, key={}, len={} SUCCESS".format(mode, keySize, testLength))
	
    return True

        

# AES
# CTR and CBC mode
# 128, 192, and 256 key length

# Messages size 0-32 bytes
# Messages size 1K, 1MB, 1GB, 5GB
def aes_test_suite(pathToBinaries):
    modes = [ 'CTR', 'CBC' ]
    keySize = [ 128, 192, 256 ]
    msgSizes = range(32)
    msgSizes.append(1 * 1024)
    msgSizes.append(1 * 1024 * 1024)
    
    # Only uncomment if you have fast CPU and lots of time
    # msgSizes.append(1 * 1024 * 1024 * 1024)
    # msgSizes.append(5 * 1024 * 1024 * 1024)

    for curMode in modes:
        for keyLength in keySize:
            for curMsgLen in msgSizes:
                if (singleAesIteration(pathToBinaries, curMode, keyLength, curMsgLen) == False):
		    print("Terminating AES Test Suite Early due to failure")
		    return False
		    
                #print("hi")

				

def main(args):
    if (len(args) != 2):
        print("Invalid Usgae!")
        print("Usage: {} pathToTestBinaries".format(args[0]))
	return

    pathToBinaries = args[1]

    print("Execute AES Test")
    aes_test_suite(pathToBinaries)






if __name__ == "__main__":
    main(sys.argv)



