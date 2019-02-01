//
//  s4tbc.h
//  S4Crypto
//
//  Created by vinnie on 1/31/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

/**
 * @file s4tbc.h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Tweekable Block Cipher functions
 *
 */

#ifndef s4tbc_h
#define s4tbc_h

#include "s4pubtypes.h"

S4_ASSUME_NONNULL_BEGIN

#ifdef __clang__
#pragma mark -  tweakable block cipher functions
#endif


typedef struct TBC_Context *      TBC_ContextRef;

#define	kInvalidTBC_ContextRef		((TBC_ContextRef) NULL)

#define TBC_ContextRefIsValid( ref )		( (ref) != kInvalidTBC_ContextRef )


S4Err TBC_Init(Cipher_Algorithm algorithm,
			   const void *key,
			   size_t keylen,
			   TBC_ContextRef __NULLABLE_REF_POINTER ctx);

S4Err TBC_SetTweek(TBC_ContextRef ctx,
				   const void *	tweek,
				   size_t 		tweeklen);		// tweek must be 16 bytes..

S4Err TBC_Encrypt(TBC_ContextRef ctx,
				  const void *	in,
				  void *         out );

S4Err TBC_Decrypt(TBC_ContextRef ctx,
				  const void *	in,
				  void *         out );

void TBC_Free(TBC_ContextRef  ctx);

S4_ASSUME_NONNULL_END

#endif /* s4tbc_h */
