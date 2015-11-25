//
//  c4crypto.h
//  C4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef c4crypto_h
#define c4crypto_h

#include "c4pubtypes.h"

#define C4_BUILD_NUMBER               1
#define C4_SHORT_VERSION_STRING		"1.0.0"


#ifdef __clang__
#pragma mark - init
#endif


C4Err C4_Init();

C4Err C4_GetErrorString( C4Err err,  size_t	bufSize, char *outString);

C4Err C4_GetVersionString(size_t	bufSize, char *outString);

#ifdef __clang__
#pragma mark - PBKDF2 function wrappers
#endif


C4Err PASS_TO_KEY(   const uint8_t  *password,
                     unsigned long  password_len,
                     uint8_t       *salt,
                     unsigned long  salt_len,
                     unsigned int   rounds,
                     uint8_t        *key_buf,
                     unsigned long  key_len );

C4Err PASS_TO_KEY_SETUP(
                           unsigned long  password_len,
                           unsigned long  key_len,
                           uint8_t        *salt,
                           unsigned long  salt_len,
                           uint32_t       *rounds_out);


#ifdef __clang__
#pragma mark - RNG function wrappers
#endif

C4Err RNG_GetBytes(
                      void *         out,
                      size_t         outLen
                      );

C4Err RNG_GetPassPhrase(
                           size_t         bits,
                           char **         outPassPhrase );

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
 
    
    kHASH_Algorithm_Invalid           =  kEnumMaxValue,
    
    ENUM_FORCE( HASH_Algorithm_ )
};


ENUM_TYPEDEF( HASH_Algorithm_, HASH_Algorithm   );

C4Err HASH_Init(HASH_Algorithm algorithm, HASH_ContextRef * ctx);

C4Err HASH_Update(HASH_ContextRef ctx, const void *data, size_t dataLength);

C4Err HASH_Final(HASH_ContextRef  ctx, void *hashOut);

C4Err HASH_GetSize(HASH_ContextRef  ctx, size_t *hashSize);

void HASH_Free(HASH_ContextRef  ctx);

C4Err HASH_Export(HASH_ContextRef ctx, void *outData, size_t bufSize, size_t *datSize);
C4Err HASH_Import(void *inData, size_t bufSize, HASH_ContextRef * ctx);

C4Err HASH_DO(HASH_Algorithm algorithm, const unsigned char *in, unsigned long inlen, unsigned long outLen, uint8_t *out);

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

C4Err MAC_Init(MAC_Algorithm     mac,
                  HASH_Algorithm    hash,
                  const void        *macKey,
                  size_t            macKeyLen,
                  MAC_ContextRef    *ctx);

C4Err MAC_Update(MAC_ContextRef  ctx,
                    const void      *data,
                    size_t          dataLength);

C4Err MAC_Final(MAC_ContextRef   ctx,
                   void             *macOut,
                   size_t           *resultLen);

void MAC_Free(MAC_ContextRef  ctx);

C4Err MAC_HashSize( MAC_ContextRef  ctx,
                      size_t         * bytes);

C4Err  MAC_KDF(MAC_Algorithm     mac,
                         HASH_Algorithm    hash,
                         uint8_t*        K,
                         unsigned long   Klen,
                         const char*    label,
                         const uint8_t* context,
                         unsigned long   contextLen,
                         uint32_t        hashLen,
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
    
    kCipher_Algorithm_Invalid           =  kEnumMaxValue,
    
    ENUM_FORCE( Cipher_Algorithm_ )
};


ENUM_TYPEDEF( Cipher_Algorithm_, Cipher_Algorithm   );

C4Err Cipher_GetSize(Cipher_Algorithm  algorithm, size_t *bitsOut);

C4Err ECB_Encrypt(Cipher_Algorithm algorithm,
                  const void *	key,
                  const void *	in,
                  size_t         bytesIn,
                  void *         out );

C4Err ECB_Decrypt(Cipher_Algorithm algorithm,
                  const void *	key,
                  const void *	in,
                  size_t         bytesIn,
                  void *         out );

typedef struct CBC_Context *      CBC_ContextRef;

#define	kInvalidCBC_ContextRef		((CBC_ContextRef) NULL)

#define CBC_ContextRefIsValid( ref )		( (ref) != kInvalidCBC_ContextRef )


C4Err CBC_Init(Cipher_Algorithm cipher,
                  const void *key,
                  const void *iv,
                  CBC_ContextRef * ctxOut);

C4Err CBC_Encrypt(CBC_ContextRef ctx,
                     const void *	in,
                     size_t         bytesIn,
                     void *         out );

C4Err CBC_Decrypt(CBC_ContextRef ctx,
                     const void *	in,
                     size_t         bytesIn,
                     void *         out );

void CBC_Free(CBC_ContextRef  ctx);

/* higher level CBC encode/decod with padding */

C4Err CBC_EncryptPAD(Cipher_Algorithm algorithm,
                     uint8_t *key, size_t key_len,
                     const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t **outData, size_t *outSize);



C4Err CBC_DecryptPAD(Cipher_Algorithm algorithm,
                     uint8_t *key, size_t key_len,
                     const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t **outData, size_t *outSize);


#ifdef __clang__
#pragma mark -  tweakable block cipher functions
#endif


typedef struct TBC_Context *      TBC_ContextRef;

#define	kInvalidTBC_ContextRef		((TBC_ContextRef) NULL)

#define TBC_ContextRefIsValid( ref )		( (ref) != kInvalidTBC_ContextRef )


C4Err TBC_Init(Cipher_Algorithm algorithm,
               const void *key,
               TBC_ContextRef * ctx);

C4Err TBC_SetTweek(TBC_ContextRef ctx,
                  const void *	tweek);

C4Err TBC_Encrypt(TBC_ContextRef ctx,
                  const void *	in,
                  void *         out );

C4Err TBC_Decrypt(TBC_ContextRef ctx,
                  const void *	in,
                  void *         out );

void TBC_Free(TBC_ContextRef  ctx);


#ifdef __clang__
#pragma mark - ECC function wrappers
#endif


typedef struct ECC_Context *      ECC_ContextRef;

#define	kInvalidECC_ContextRef		((ECC_ContextRef) NULL)

#define ECC_ContextRefIsValid( ref )		( (ref) != kInvalidECC_ContextRef )

C4Err ECC_Init(ECC_ContextRef * ctx);

void ECC_Free(ECC_ContextRef  ctx);

C4Err ECC_Generate(ECC_ContextRef  ctx,
                      size_t          keysize );

bool    ECC_isPrivate(ECC_ContextRef  ctx );

C4Err ECC_Export(ECC_ContextRef  ctx,
                    int             exportPrivate,
                    void            *outData,
                    size_t          bufSize,
                    size_t          *datSize);

C4Err ECC_Import_Info( void *in, size_t inlen,
                         bool *isPrivate,
                         bool *isANSIx963,
                         size_t *keySizeOut  );

C4Err ECC_CurveName( ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *outDataLen);

C4Err ECC_Import(ECC_ContextRef  ctx,   void *in, size_t inlen );

C4Err ECC_Import_ANSI_X963(ECC_ContextRef  ctx,   void *in, size_t inlen );

C4Err ECC_Export_ANSI_X963(ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *datSize);

C4Err ECC_PubKeyHash( ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *outDataLen);

C4Err ECC_SharedSecret (ECC_ContextRef privCtx,
                           ECC_ContextRef  pubCtx,
                           void *outZ,
                           size_t bufSize,
                           size_t *datSize);

C4Err ECC_KeySize( ECC_ContextRef  ctx, size_t * bits);

C4Err ECC_Encrypt(ECC_ContextRef  pubCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen);
C4Err ECC_Decrypt(ECC_ContextRef  privCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen);

C4Err ECC_Verify(ECC_ContextRef  pubCtx, void *sig, size_t sigLen,  void *hash, size_t hashLen);

C4Err ECC_Sign(ECC_ContextRef  privCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen);



#ifdef __clang__
#pragma mark - Shamir Secret Sharing
#endif

typedef struct SHARES_Context *      SHARES_ContextRef;

#define	kInvalidSHARES_ContextRef		((SHARES_ContextRef) NULL)

#define SHARES_ContextRefIsValid( ref )		( (ref) != kInvalidSHARES_ContextRef )


#define kC4ShareInfo_HashBytes      8

typedef struct SHARES_ShareInfo
{
    uint8_t         threshold;                              /* Number of shares needed to combine */
    uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
    uint8_t			shareHash[kC4ShareInfo_HashBytes];      /* Share data Hash - AKA serial number */
    
    size_t          shareSecretLen;
    uint8_t         shareSecret[64];                        /* the actual share secret */
} SHARES_ShareInfo;


C4Err SHARES_Init( const void       *key,
                  size_t           keyLen,
                  uint32_t         totalShares,
                  uint32_t         threshold,
                  SHARES_ContextRef *ctx);

void  SHARES_Free(SHARES_ContextRef  ctx);

C4Err  SHARES_GetShareInfo( SHARES_ContextRef  ctx,
                            uint32_t            shareNumber,
                            SHARES_ShareInfo    **shareInfo,
                            size_t              *shareInfoLen);

C4Err  SHARES_CombineShareInfo( uint32_t            numberShares,
                               SHARES_ShareInfo*        sharesInfoIn[],
                               void                     *outData,
                               size_t                   bufSize,
                               size_t                   *outDataLen);

#ifdef __clang__
#pragma mark - Hash word Encoding
#endif


/* given a 32 bit word.  take the  upper 20 bits and return 2 PGP words null terminated
 as defined by  http://en.wikipedia.org/wiki/PGP_word_list
 */


void PGPWordEncode(uint32_t in, char* out, size_t *outLen);

/* given a 64 bit word.  take the upper 32 bits and  return 4 PGP words null terminated
 as defined by http://en.wikipedia.org/wiki/PGP_word_list
 */


void PGPWordEncode64(uint64_t in, char* out, size_t *outLen);


#endif /* c4crypto_h */
