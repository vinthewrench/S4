//
//  s4.h
//  S4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//  S4Crypto


/**
 * @file S4Crypto.h
 * @author 4th-A Technologies, LLC
 * @brief Umbrella include for S4Crypto library
 *
 */

#ifndef S4_h
#define S4_h

/**
 * @brief Apple implementions can use build in crypto for certian functions:
 *
 *	currently this only includes MD5, SHA1, SHA224, SHA256, SHA384 and SHA512
 *  and the low level PBKDF2, the rest is done by S4Crypto
 */

#ifdef __APPLE__
#ifndef _S4_USES_COMMON_CRYPTO_
#define _S4_USES_COMMON_CRYPTO_ 1
#endif
#endif


#define _USES_XXHASH_ 1
#define _USES_SHA3_ 	1

#include "s4pubtypes.h"
#include "s4rng.h"
#include "s4hash.h"
#include "s4mac.h"
#include "s4cipher.h"
#include "s4p2k.h"
#include "s4tbc.h"
#include "s4ecc.h"
#include "s4share.h"
#include "s4keys.h"
#include "s4utilities.h"
#include "s4keysinternal.h"

#endif /* S4_h */
