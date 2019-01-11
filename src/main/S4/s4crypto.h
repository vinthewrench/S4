//
//  s4crypto.h
//  S4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef s4crypto_h
#define s4crypto_h

#include "s4pubtypes.h"

S4_ASSUME_NONNULL_BEGIN

#define S4_BUILD_NUMBER               7
#define S4_SHORT_VERSION_STRING       "2.1.0"


#ifdef __clang__
#pragma mark - init
#endif


S4Err S4_Init(void);

S4Err S4_GetErrorString( S4Err err,  char outString[__S4_NONNULL 256]);

S4Err S4_GetVersionString(char outString[__S4_NONNULL 256]);

#ifdef __clang__
#pragma mark - RNG function wrappers
#endif

S4Err RNG_GetBytes(	  void *         out,
                      size_t         outLen
                      );

S4Err RNG_GetPassPhrase( size_t         bits,
                           char __NULLABLE_XFREE_P_P outPassPhrase );

#ifdef __clang__
#pragma mark - HASH function wrappers
#endif


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

S4Err HASH_DO(HASH_Algorithm algorithm, const void *in, size_t inlen, size_t outLen, void *out);

S4Err HASH_NormalizePassPhrase(const uint8_t    *passphrase,
							   size_t           passphraseLen,
							   const uint8_t    *salt,
							   size_t           saltLen,
							   uint8_t __NULLABLE_XFREE_P_P outAllocData,
							   size_t* __S4_NULLABLE outSize);

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



#ifdef __clang__
#pragma mark - Shamir Secret Sharing
#endif

typedef struct SHARES_Context *      SHARES_ContextRef;

#define	kInvalidSHARES_ContextRef		((SHARES_ContextRef) NULL)

#define SHARES_ContextRefIsValid( ref )		( (ref) != kInvalidSHARES_ContextRef )


#define kS4ShareInfo_HashBytes      8

typedef struct SHARES_ShareInfo
{
    uint8_t         threshold;                              /* Number of shares needed to combine */
    uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
    uint8_t			shareHash[kS4ShareInfo_HashBytes];      /* Share data Hash - AKA serial number */
    
    size_t          shareSecretLen;
    uint8_t         shareSecret[64];                        /* the actual share secret */
} SHARES_ShareInfo;


S4Err SHARES_Init( const void       *key,
                  size_t           keyLen,
                  uint32_t         totalShares,
                  uint32_t         threshold,
                  SHARES_ContextRef __NULLABLE_REF_POINTER ctx);

void  SHARES_Free(SHARES_ContextRef  ctx);

S4Err  SHARES_GetShareInfo( SHARES_ContextRef  ctx,
                            uint32_t            shareNumber,
                            SHARES_ShareInfo   __NULLABLE_XFREE_P_P shareInfo,
                            size_t              *shareInfoLen);

S4Err  SHARES_CombineShareInfo( uint32_t            numberShares,
							   SHARES_ShareInfo* __S4_NONNULL   sharesInfoIn[__S4_NONNULL],
                               void                     *outData,
                               size_t                   bufSize,
                               size_t                   *outDataLen);

S4Err SHARES_GetShareHash( const uint8_t *key,
                          size_t         keyLenIn,
                          uint32_t       thresholdIn,
                          uint8_t        *mac_buf,
                          unsigned long  mac_len);

#ifdef __clang__
#pragma mark - Hash word Encoding
#endif

/* given a 8 bit word.  return the  PGP word null terminated
 as defined by  http://en.wikipedia.org/wiki/PGP_word_list
 */


char* PGPWordOdd(uint8_t in);
char* PGPWordEven(uint8_t in);


#ifdef __clang__
#pragma mark - zbase32 encoding
#endif


/* Z-base-32 as defined by
  http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
*/


/*
 * Decode bits of encoded using z-base-32 and write the result into
 * decoded. If 8 is not a factor of bits, pad the output with zero bits
 * until a full byte is written.
 *
 * Returns the number of bytes written, or -1 if a byte that is not the
 * ASCII representation of a valid z-base-32 character is read.
 */
int zbase32_decode(uint8_t *decoded,
                   const uint8_t *encoded,
                   unsigned int bits);

/*
 * Encode bits of input into z-base-32, and write the result into encoded.
 *
 * Returns the number of bytes written.
 */
int zbase32_encode(uint8_t *encoded,
                   const uint8_t *input,
                   unsigned int bits);

S4_ASSUME_NONNULL_END

#endif /* s4crypto_h */
