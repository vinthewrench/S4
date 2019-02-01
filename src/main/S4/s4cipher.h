//
//  s4cipher.h
//  S4Crypto
//
//  Created by vinnie on 1/31/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

/**
 * @file s4cipher.h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Low level symmetric encryption functions
 *
 */

#ifndef s4cipher_h
#define s4cipher_h
#include "s4pubtypes.h"


S4_ASSUME_NONNULL_BEGIN

#ifdef __clang__
#pragma mark - Cipher function wrappers
#endif

enum Cipher_Algorithm_
{
	kCipher_Algorithm_AES128         = 1,
	kCipher_Algorithm_AES192         = 2,
	kCipher_Algorithm_AES256         = 3,
	kCipher_Algorithm_2FISH256       = 4,

	kCipher_Algorithm_3FISH256      = 100,
	kCipher_Algorithm_3FISH512      = 102,
	kCipher_Algorithm_3FISH1024     = 103,

	kCipher_Algorithm_SharedKey      =  200,

	kCipher_Algorithm_ECC384        =  300,
	kCipher_Algorithm_NISTP384		=  300,

	kCipher_Algorithm_ECC414        =  301, /*  Dan Bernstein Curve3617  */
	kCipher_Algorithm_ECC41417		=  301,


	kCipher_Algorithm_Unknown          =  9999,

	kCipher_Algorithm_Invalid           =  kEnumMaxValue,

	ENUM_FORCE( Cipher_Algorithm_ )
};

ENUM_TYPEDEF( Cipher_Algorithm_, Cipher_Algorithm   );


S4Err Cipher_GetSize(Cipher_Algorithm  algorithm, size_t *bytesOut)
DEPRECATED_MSG_ATTRIBUTE("Use Cipher_GetKeySize and convert to bytes  instead.");

bool Cipher_AlgorithmIsAvailable(Cipher_Algorithm algorithm);

S4Err Cipher_GetName(Cipher_Algorithm algorithm, __CONST_CHAR_P_P cipherName);

S4Err Cipher_GetKeySize(Cipher_Algorithm algorithm, size_t *keyBits);

S4Err Cipher_GetBlockSize(Cipher_Algorithm algorithm, size_t *blockSizeBytes);

S4Err ECB_Encrypt(Cipher_Algorithm algorithm,
				  const void *	key,
				  const void *	in,
				  size_t         bytesIn,
				  void *         out );

S4Err ECB_Decrypt(Cipher_Algorithm algorithm,
				  const void *	key,
				  const void *	in,
				  size_t         bytesIn,
				  void *         out );

typedef struct CBC_Context *      CBC_ContextRef;

#define	kInvalidCBC_ContextRef		((CBC_ContextRef) NULL)

#define CBC_ContextRefIsValid( ref )		( (ref) != kInvalidCBC_ContextRef )


S4Err CBC_Init(Cipher_Algorithm cipher,
			   const void *key,
			   const void *iv,
			   CBC_ContextRef __NULLABLE_REF_POINTER ctxOut);

S4Err CBC_GetAlgorithm(CBC_ContextRef ctx, Cipher_Algorithm *algorithm);

S4Err CBC_Encrypt(CBC_ContextRef ctx,
				  const void *	in,
				  size_t         bytesIn,
				  void *         out );

S4Err CBC_Decrypt(CBC_ContextRef ctx,
				  const void *	in,
				  size_t         bytesIn,
				  void *         out );

void CBC_Free(CBC_ContextRef  ctx);

/* higher level CBC encode/decod with padding */

S4Err CBC_EncryptPAD(Cipher_Algorithm algorithm,
					 uint8_t *key,
					 const uint8_t *iv,
					 const uint8_t *in, size_t in_len,
					 uint8_t __NULLABLE_XFREE_P_P outAllocData,
					 size_t* __S4_NULLABLE outSize);

S4Err CBC_DecryptPAD(Cipher_Algorithm algorithm,
					 uint8_t *key,
					 const uint8_t *iv,
					 const uint8_t *in, size_t in_len,
					 uint8_t __NULLABLE_XFREE_P_P outAllocData,
					 size_t* __S4_NULLABLE outSize);



S4_ASSUME_NONNULL_END

#endif /* s4cipher_h */
