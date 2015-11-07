//
//  c4Internal.h
//  C4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef c4Internal_h
#define c4Internal_h


#include <tomcrypt.h>
#include <skein_port.h>
#include <threefishApi.h>


#include "c4.h"
#include "c4Internal.h"

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

C4Err sCrypt2C4Err(int t_err);

#endif /* c4Internal_h */
