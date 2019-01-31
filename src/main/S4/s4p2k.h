//
//  s4p2k.h
//  S4Crypto
//
//  Created by vinnie on 1/31/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

#ifndef s4p2k_h
#define s4p2k_h

#include "s4pubtypes.h"

S4_ASSUME_NONNULL_BEGIN

#ifdef __clang__
#pragma mark - High level Password to Key function wrappers
#endif

// high level P2K API
enum P2K_Algorithm_
{
	kP2K_Algorithm_Argon2d             = 0,  //	Argon2_d = 0,
	kP2K_Algorithm_Argon2i             = 1,  // Argon2_i = 1,
	kP2K_Algorithm_Argon2id            = 2,	//	Argon2_id = 2

	kP2K_Algorithm_PBKDF2            	= 100,

	kP2K_Algorithm_Invalid           =  kEnumMaxValue,

	ENUM_FORCE( P2K_Algorithm_ )
};

ENUM_TYPEDEF( P2K_Algorithm_, P2K_Algorithm );

typedef struct P2K_Context *      P2K_ContextRef;

#define	kInvalidP2K_ContextRef		((P2K_ContextRef) NULL)

#define P2K_ContextRefIsValid( ref )		( (ref) != kInvalidP2K_ContextRef )

S4Err P2K_Init( P2K_Algorithm algorithm,
			   P2K_ContextRef __NULLABLE_REF_POINTER ctx);

void  P2K_Free(P2K_ContextRef  ctx);

S4Err P2K_EncodePassword(P2K_ContextRef  ctx,
						 const uint8_t 	 *password,
						 size_t  		password_len,
						 size_t		 	 salt_len,
						 size_t		 	 key_len,
						 uint8_t 		*key_buf,
						 char __NULLABLE_XFREE_P_P paramStr
						 );

S4Err P2K_GetAlgorithm(P2K_ContextRef ctx, P2K_Algorithm *algorithm);

bool P2K_AlgorithmIsAvailable(P2K_Algorithm algorithm);

S4Err P2K_GetAvailableAlgorithms(P2K_Algorithm __NULLABLE_XFREE_P_P outAlgorithms,
								 size_t* __S4_NULLABLE outCount);

S4Err P2K_GetName(P2K_Algorithm algorithm, __CONST_CHAR_P_P p2kName);

S4Err P2K_DecodePassword( 	const uint8_t 	 *password,
						 size_t  		password_len,
						 const char		*paramStr,
						 void *outKey, 	size_t bufSize, size_t *keySize
						 );

S4Err P2K_DecryptKeyFromPassPhrase(  uint8_t * __S4_NONNULL inData,
								   size_t inLen,
								   const uint8_t* __S4_NONNULL passphrase,
								   size_t           passphraseLen,
								   uint8_t __NULLABLE_XFREE_P_P outAllocKey,
								   size_t* __S4_NULLABLE 		outKeySize);

S4Err P2K_EncryptKeyToPassPhrase( const void* __S4_NONNULL key,
								 size_t 			keyLen,
								 Cipher_Algorithm cipherAlgorithm,
								 const uint8_t* __S4_NONNULL passphrase,
								 size_t           passphraseLen,
								 P2K_Algorithm 	passPhraseAlgorithm,
								 uint8_t __NULLABLE_XFREE_P_P outAllocData,
								 size_t* __S4_NULLABLE 		outSize);



#ifdef __clang__
#pragma mark - lower level P2K APIs
#endif

S4Err PASS_TO_KEY(   const uint8_t  *password,
				  unsigned long  password_len,
				  uint8_t       *salt,
				  unsigned long  salt_len,
				  unsigned int   rounds,
				  uint8_t        *key_buf,
				  unsigned long  key_len );

S4Err PASS_TO_KEY_SETUP(
						unsigned long  password_len,
						unsigned long  key_len,
						uint8_t        *salt,
						unsigned long  salt_len,
						uint32_t       *rounds_out);


enum ARGON2_Algorithm_
{
	// this needs to map to (argon2_type) from Argon2.h
	kARGON2_Algorithm_Argon2d             = 0,  //	Argon2_d = 0,
	kARGON2_Algorithm_Argon2i             = 1,  // 	Argon2_i = 1,
	kARGON2_Algorithm_Argon2id            = 2,	//	Argon2_id = 2

	kARGON2_Algorithm_Invalid           =  kEnumMaxValue,

	ENUM_FORCE( ARGON2_Algorithm_ )
};

ENUM_TYPEDEF( ARGON2_Algorithm_, ARGON2_Algorithm   );

S4Err PASS_TO_KEY_ARGON2(ARGON2_Algorithm algorithm,
						 const uint8_t  *password,
						 unsigned long  password_len,
						 uint8_t		*salt,
						 unsigned long	salt_len,
						 uint32_t	 	t_cost,
						 uint32_t	 	m_cost,
						 uint32_t 	 	parallelism,
						 uint8_t        *key_buf,
						 unsigned long  key_len );



S4_ASSUME_NONNULL_END

#endif /* s4p2k_h */
