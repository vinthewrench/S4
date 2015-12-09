//
//  s4Internal.h
//  S4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef s4Internal_h
#define s4Internal_h


#include <tomcrypt.h>
#include <skein_port.h>
#include <threefishApi.h>


#include "s4.h"
#include "s4Internal.h"

#ifdef __APPLE__
#import "git_version_hash.h"
#else
#define GIT_COMMIT_HASH __DATE__
#endif

#if _USES_COMMON_CRYPTO_
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

#define validateECCContext( s )		\
ValidateParam( sECC_ContextIsValid( s ) )

#endif /* s4Internal_h */
