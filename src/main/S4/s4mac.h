//
//  s4Mac.h
//  S4Crypto
//
//  Created by vinnie on 1/31/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

/**
 * @file s4mac.h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Message Athentication Code Functions
 *
 */

#ifndef s4Mac_h
#define s4Mac_h

#include "s4pubtypes.h"

S4_ASSUME_NONNULL_BEGIN
#ifdef __clang__
#pragma mark - Message  Authentication Code wrappers
#endif


enum MAC_Algorithm_
{
	kMAC_Algorithm_HMAC            = 1,
	kMAC_Algorithm_SKEIN          = 2,

	kMAC_Algorithm_Invalid           =  kEnumMaxValue,

	ENUM_FORCE( MAC_Algorithm_ )
};

ENUM_TYPEDEF( MAC_Algorithm_, MAC_Algorithm   );

typedef struct MAC_Context *      MAC_ContextRef;

#define	kInvalidMAC_ContextRef		((MAC_ContextRef) NULL)

#define MAC_ContextRefIsValid( ref )		( (ref) != kInvalidMAC_ContextRef )

bool MAC_AlgorithmIsAvailable(MAC_Algorithm algorithm);

S4Err MAC_GetName(MAC_Algorithm algorithm, __CONST_CHAR_P_P macName);

S4Err MAC_Init(MAC_Algorithm     mac,
			   HASH_Algorithm    hash,
			   const void        *macKey,
			   size_t            macKeyLen,
			   MAC_ContextRef __NULLABLE_REF_POINTER ctx);

S4Err MAC_Update(MAC_ContextRef  ctx,
				 const void      *data,
				 size_t          dataLength);

S4Err MAC_Final(MAC_ContextRef   ctx,
				void             *macOut,
				size_t           *resultLen);

void MAC_Free(MAC_ContextRef  ctx);

S4Err MAC_HashSize( MAC_ContextRef  ctx,
				   size_t         * hashSizeBytes);

S4Err MAC_GetAlgorithm(MAC_ContextRef ctx, MAC_Algorithm *algorithm);

S4Err  MAC_KDF(MAC_Algorithm     mac,
			   HASH_Algorithm    hash,
			   uint8_t*        K,
			   unsigned long   Klen,
			   const char*    label,
			   const uint8_t* context,
			   unsigned long   contextLen,
			   size_t        	 hashLen,
			   unsigned long   outLen,
			   uint8_t         *out);



S4_ASSUME_NONNULL_END


#endif /* s4Mac_h */
