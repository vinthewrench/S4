//
//  s4ecc.h
//  S4Crypto
//
//  Created by vinnie on 1/31/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

/**
 * @file s4ecc.h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Low level elliptic curve public key functions
 *
 */

#ifndef s4ecc_h
#define s4ecc_h
#include "s4pubtypes.h"

S4_ASSUME_NONNULL_BEGIN


#ifdef __clang__
#pragma mark - ECC function wrappers
#endif

enum ECC_Algorithm_
{
	// be carefule with these values.. they need to map to Cipher_Algorithm
	kECC_Algorithm_ECC384         		= kCipher_Algorithm_ECC384,
	kECC_Algorithm_NISTP384				= kCipher_Algorithm_NISTP384,

	kECC_Algorithm_Curve41417        	= kCipher_Algorithm_ECC41417,

	kECC_Algorithm_Invalid           =  kEnumMaxValue,

	ENUM_FORCE( ECC_Algorithm_ )
};

ENUM_TYPEDEF( ECC_Algorithm_, ECC_Algorithm );

typedef struct ECC_Context *      ECC_ContextRef;

#define	kInvalidECC_ContextRef		((ECC_ContextRef) NULL)

#define ECC_ContextRefIsValid( ref )		( (ref) != kInvalidECC_ContextRef )

S4Err ECC_Init(ECC_Algorithm algorithm,
			   ECC_ContextRef __NULLABLE_REF_POINTER ctx);

S4Err ECC_GetName(ECC_Algorithm algorithm, __CONST_CHAR_P_P algorName);

S4Err ECC_GetKeySizeInBytes(ECC_Algorithm algorithm,
							size_t* __S4_NULLABLE keySizeBytes);

// Get an malloc array of available algorithms
// calller must deallocate the outAlgorithms typically with XFREE
//
S4Err ECC_GetAvailableAlgorithms(ECC_Algorithm __NULLABLE_XFREE_P_P outAlgorithms,
								 size_t* __S4_NULLABLE outCount);

bool ECC_AlgorithmIsAvailable(ECC_Algorithm algorithm);

S4Err ECC_Import_ANSI_X963(const void *in, size_t inlen,
						   ECC_ContextRef __NULLABLE_REF_POINTER ctxOUT);

S4Err ECC_Import(const void *in, size_t inlen,
				 ECC_ContextRef __NULLABLE_REF_POINTER ctxOUT );

void ECC_Free(ECC_ContextRef  ctx);

bool ECC_isPrivate(ECC_ContextRef  ctx );

S4Err ECC_Export(ECC_ContextRef  ctx,
				 bool           exportPrivate,
				 void            *outData,
				 size_t          bufSize,
				 size_t          *datSize);

S4Err ECC_Import_Info( const void *in, size_t inlen,
					  bool *isPrivate,
					  bool *isANSIx963,
					  size_t *keySizeOut  );

S4Err ECC_GetAlgorithm(ECC_ContextRef ctx, ECC_Algorithm *algorithm);

S4Err ECC_Export_ANSI_X963(ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *datSize);

S4Err ECC_PubKeyHash( ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t* __S4_NULLABLE outDataLen);

S4Err ECC_SharedSecret (ECC_ContextRef privCtx,
						ECC_ContextRef  pubCtx,
						void *outData,
						size_t bufSize,
						size_t* __S4_NULLABLE datSize);

S4Err ECC_KeySize( ECC_ContextRef  ctx, size_t * bits);

S4Err ECC_Encrypt(ECC_ContextRef  pubCtx, const void *inData, size_t inDataLen,
				  void *outData, size_t bufSize, size_t *outDataLen);

S4Err ECC_Decrypt(ECC_ContextRef  privCtx, const void *inData, size_t inDataLen,
				  void *outData, size_t bufSize, size_t *outDataLen);

S4Err ECC_Verify(ECC_ContextRef  pubCtx, void *sig, size_t sigLen,  void *hash, size_t hashLen);

S4Err ECC_Sign(ECC_ContextRef  privCtx, void *inData, size_t inDataLen,
			   void *outData, size_t bufSize, size_t *outDataLen);





S4_ASSUME_NONNULL_END

#endif /* s4ecc_h */
