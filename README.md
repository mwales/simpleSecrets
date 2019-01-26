# simpleSecrets

Simple to use encryption and hashing tools.

## Goals

* Can easily build and staticly link into your binary
* MIT or BSD license for pain free distribution
* Not alot of choices, just the core set of tools

## What it does not provide

* Thorough testing like libsodium or OpenSSL
* Public-private encryption stuff like RSA, Diffie-Helman (just the math
  libraries to support those tools becomes heavy)
* Speedy libraries.  They are all C, but no optimization attempted.

## What is provided

* MD5 Hashing (avoid on new things, but included because it so so common)
* SHA1 Hashing
* SHA256, SHA384, and SHA512 Hashing
* HMAC_SHA1 hashing / authentication
* PBKDF2_HMAC_SHA1 key derivation function
* Simple demo programs / examples / crypto tools
* AES-128, AES-192, and AES-256 with CBC and CTR cipher modes

## To do list / outstanding features

* Test on ARM 32-bit, Win 32, Win 64, Linux 32-bit (development on AMD64 only)
* Windows support

For future development

* Cryptographic random number generator
* A simple API to AES-256 encrypt a buffer of data using CBC mode, PKCS
  padding, random IV generation, PBKDF2 key derivation, and HMAC_SHA1
  verification
* More advanced hashing functions with SHA256 and SHA512 suport

# Credits

* MD5 (public domain): Alexander Peslyak (solar@openwall.com)
* SHA1 (public domain): Steve Reid (steve@edmweb.com) and Aaron D. Gifford
  (agifford@infowest.com)
* SHA256/SHA384/SHA512 (BSD): Aaron D. Gifford (agifford@infowest.com)
* HMAC_SHA1 (BSD): Aaron D. Gifford (agifford@infowest.com)
* PBKDF2 (MIT): Michael Wales (mwales3@gmail.com)
* AES (public domain): https://github.com/kokke

