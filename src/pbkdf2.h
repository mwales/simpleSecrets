#ifndef PBKDF2_H
#define PBKDR2_H

#include "sha1.h"
#include "hmac_sha1.h"

// Implemented PBKDF2 myself.  Not going to set any speed records.

/// @todo Add other PRF besides just SHA1

// Have 20-bytes of memory allocated for the derived key
void pbkdf2_sha1(char* pass, int passLen,
                 char* salt, int saltLength,
                 int numIterations, int dkLen,
                 char* derivedKey);

#endif
