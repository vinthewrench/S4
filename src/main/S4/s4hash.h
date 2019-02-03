//
//  s4Hash.h
//  S4Crypto
//
//  Created by vinnie on 1/31/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

/**
 * @file s4Hash.h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Hash functions
 *
 */

#ifndef s4Hash_h
#define s4Hash_h


#include "s4pubtypes.h"

S4_ASSUME_NONNULL_BEGIN


#ifdef __clang__
#pragma mark - HASH function wrappers
#endif

/**
 * @brief HASH_Context
 *
 *	HASH_Context is the object passed around by various hash functions.
 *
 */

typedef struct HASH_Context *      HASH_ContextRef;

#define	kInvalidHASH_ContextRef		((HASH_ContextRef) NULL)

#define HASH_ContextRefIsValid( ref )		( (ref) != kInvalidHASH_ContextRef )

#define kHASH_ContextAllocSize 512

enum HASH_Algorithm_
{
	kHASH_Algorithm_MD5             = 1,
	kHASH_Algorithm_SHA1            = 2,
	kHASH_Algorithm_SHA224          = 3,
	kHASH_Algorithm_SHA256          = 4,
	kHASH_Algorithm_SHA384          = 5,
	kHASH_Algorithm_SHA512          = 6,
	kHASH_Algorithm_SKEIN256        = 7,
	kHASH_Algorithm_SKEIN512        = 8,
	kHASH_Algorithm_SKEIN1024       = 9,
	kHASH_Algorithm_SHA512_256      = 10,

#if _USES_XXHASH_
	kHASH_Algorithm_xxHash32        = 20,
	kHASH_Algorithm_xxHash64        = 21,
#endif

#if _USES_SHA3_
	kHASH_Algorithm_SHA3_224     	= 30,
	kHASH_Algorithm_SHA3_256    	= 31,
	kHASH_Algorithm_SHA3_384     	= 32,
	kHASH_Algorithm_SHA3_512     	= 33,

	kHASH_Algorithm_KECCAK_256   	= 34,	// as seen in Ethereum
#endif

	kHASH_Algorithm_Invalid           =  kEnumMaxValue,

	ENUM_FORCE( HASH_Algorithm_ )
};


ENUM_TYPEDEF( HASH_Algorithm_, HASH_Algorithm   );

S4Err HASH_GetBits(HASH_Algorithm algorithm, size_t *hashBits);  // number of bits in hash

S4Err HASH_GetName(HASH_Algorithm algorithm, __CONST_CHAR_P_P hashName);

// Get an malloc array of available algorithms
// calller must deallocate the outAlgorithms typically with XFREE
//
S4Err HASH_GetAvailableAlgorithms(HASH_Algorithm __NULLABLE_XFREE_P_P outAlgorithms,
								  size_t* __S4_NULLABLE outCount);

bool HASH_AlgorithmIsAvailable(HASH_Algorithm algorithm);

S4Err HASH_Init(HASH_Algorithm algorithm,
				HASH_ContextRef __NULLABLE_REF_POINTER ctx);

S4Err HASH_Update(HASH_ContextRef ctx, const void *data, size_t dataLength);

S4Err HASH_Final(HASH_ContextRef  ctx, void *hashOut);

S4Err HASH_GetSize(HASH_ContextRef  ctx, size_t *hashSizeBytes);

void HASH_Free(HASH_ContextRef  ctx);

S4Err HASH_Reset(HASH_ContextRef  ctx);

S4Err HASH_GetAlgorithm(HASH_ContextRef ctx, HASH_Algorithm *algorithm);

S4Err HASH_Export(HASH_ContextRef ctx, void *outData, size_t bufSize, size_t *datSize);

S4Err HASH_Import(void *inData, size_t bufSize,
				  HASH_ContextRef __NULLABLE_REF_POINTER  ctx);

S4Err HASH_DO(HASH_Algorithm algorithm,
			  const void *__S4_NONNULL in,
			  size_t inlen,
			  void * __S4_NONNULL out,
			  size_t outLen);

S4Err HASH_NormalizePassPhrase(const uint8_t    *passphrase,
							   size_t           passphraseLen,
							   const uint8_t    *salt,
							   size_t           saltLen,
							   uint8_t __NULLABLE_XFREE_P_P outAllocData,
							   size_t* __S4_NULLABLE outSize);


S4_ASSUME_NONNULL_END

#endif /* s4Hash_h */
