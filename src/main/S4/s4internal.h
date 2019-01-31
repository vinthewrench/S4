//
//  s4internal.h
//  S4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//
//
//  s4.h
//  S4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef s4internal_h
#define s4internal_h

#include "S4Crypto.h"
#include "s4keysinternal.h"
#include "tomcrypt.h"
#include "threefishApi.h"

/*
#ifdef __APPLE__
#import "git_version_hash.h"
#else
#define GIT_COMMIT_HASH __DATE__
#endif
 */
#define GIT_COMMIT_HASH __DATE__

#if _S4_USES_COMMON_CRYPTO_
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonRandom.h>

#define kCCHmacAlgInvalid UINT32_MAX

#endif


#define CKSTAT {if (status != CRYPT_OK)  goto done; }

#ifndef roundup
#define	roundup(x, y)	((((x) % (y)) == 0) ? \
(x) : ((x) + ((y) - ((x) % (y)))))
#endif

const struct ltc_hash_descriptor* sDescriptorForHash(HASH_Algorithm algorithm);

S4Err sCrypt2S4Err(int t_err);

bool sECC_ContextIsValid( const ECC_ContextRef  ref);
bool sS4SharesContextIsValid( const S4SharesContextRef  ref);
bool sS4SharesPartContextIsValid( const S4SharesPartContextRef  ref);

#define validateECCContext( s )		\
ValidateParam( sECC_ContextIsValid( s ) )

#define PRAGMA_MACRO(x) _Pragma(#x)

#ifndef FIX_BEFORE_SHIP

#if DEBUG
#define FIX_BEFORE_SHIP(msg) PRAGMA_MACRO(message "FIX_BEFORE_SHIP: " msg)
#else
#define FIX_BEFORE_SHIP(msg) PRAGMA_MACRO(GCC error "FIX_BEFORE_SHIP: " msg)
#endif

#endif

#ifdef EMSCRIPTEN
#include <emscripten.h>

//functions not defined in EMSCRIPTEN
/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char * strnstr(const char *haystack, const char *needle, size_t len);


#define EXPORT_FUNCTION EMSCRIPTEN_KEEPALIVE
#else
#define  EXPORT_FUNCTION


#endif
#endif /* s4internal_h */
