//
//  s4.h
//  S4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//  S4Crypto

#ifndef S4_h
#define S4_h

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
