//
//  c4keys.h
//  C4
//
//  Created by vincent Moscaritolo on 11/10/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef c4Keys_h
#define c4Keys_h

#include "c4pubtypes.h"

#ifdef __clang__
#pragma mark - Key import Export.
#endif



#define kC4KeyPBKDF2_SaltBytes      8
#define kC4KeyPBKDF2_HashBytes      8

#define kC4Key_KeyIDBytes                     16
#define kC4KeyPublic_Encrypted_BufferMAX      256
#define kC4KeyPublic_Encrypted_HashBytes      8

typedef struct C4KeyContext *      C4KeyContextRef;

#define	kInvalidC4KeyContextRef		((C4KeyContextRef) NULL)

#define C4KeyContextRefIsValid( ref )		( (ref) != kInvalidC4KeyContextRef )


enum C4KeyPropertyType_
{
    C4KeyPropertyType_Invalid       = 0,
    C4KeyPropertyType_UTF8String    = 1,
    C4KeyPropertyType_Binary        = 2,
    C4KeyPropertyType_Time          = 3,
    C4KeyPropertyType_Numeric       = 4,
    
    ENUM_FORCE( C4KeyPropertyType_ )
};

ENUM_TYPEDEF( C4KeyPropertyType_, C4KeyPropertyType   );

extern char *const kC4KeyProp_KeyType;
extern char *const kC4KeyProp_KeySuite;
extern char *const kC4KeyProp_KeyData;
extern char *const kC4KeyProp_KeyID;
extern char *const kC4KeyProp_KeyIDString;

typedef struct C4KeyProperty  C4KeyProperty;

struct C4KeyProperty
{
    uint8_t             *prop;
    C4KeyPropertyType   type;
    uint8_t             *value;
    size_t              valueLen;
    
    C4KeyProperty      *next;
};

enum C4KeyType_
{
    kC4KeyType_Symmetric           = 1,
    kC4KeyType_Tweekable           = 2,
    kC4KeyType_PBKDF2              = 3,
    kC4KeyType_PublicEncrypted      = 4,
    kC4KeyType_Share                = 5,
    
    kC4KeyType_Invalid           =  kEnumMaxValue,
    
    ENUM_FORCE( C4KeyType_ )
};

ENUM_TYPEDEF( C4KeyType_, C4KeyType   );

typedef struct C4KeySymmetric_
{
    Cipher_Algorithm    symAlgor;
    size_t              keylen;
    uint8_t        		symKey[64];
    
}C4KeySymmetric;


typedef struct C4KeyTBC_
{
    Cipher_Algorithm    tbcAlgor;
    size_t              keybits;
    uint64_t            key[16];
    
}C4KeyTBC;


typedef struct C4KeyPBKDF2_
{
    C4KeyType              keyAlgorithmType;
    Cipher_Algorithm       cipherAlgor;

    uint8_t             keyHash[kC4KeyPBKDF2_HashBytes];
    uint8_t             salt[kC4KeyPBKDF2_SaltBytes];
    uint32_t            rounds;
 Cipher_Algorithm       encyptAlgor;
    uint8_t             encrypted[256];
    size_t              encryptedLen;
    
    // FOR PASSCODE SHARED KEYS
    uint8_t         threshold;                              /* Number of shares needed to combine */
    uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
    uint8_t			shareHash[kC4ShareInfo_HashBytes];      /* Share data Hash - AKA serial number */

    
}C4KeyPBKDF2;

typedef struct C4KeyPublic_Encrypted_
{
    C4KeyType               keyAlgorithmType;
    Cipher_Algorithm        cipherAlgor;
    
    uint8_t             keyHash[kC4KeyPublic_Encrypted_HashBytes];
    
    size_t              keysize;
     uint8_t            keyID[kC4Key_KeyIDBytes];
    
    uint8_t             encrypted[kC4KeyPublic_Encrypted_BufferMAX];
    size_t              encryptedLen;
    
    // FOR PUBLIC ENCRYPTED SHARED KEYS
    uint8_t         threshold;                              /* Number of shares needed to combine */
    uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
    uint8_t			shareHash[kC4ShareInfo_HashBytes];      /* Share data Hash - AKA serial number */
    
}C4KeyPublic_Encrypted;


typedef struct C4KeyContext    C4KeyContext;

struct C4KeyContext
{
    
#define kC4KeyContextMagic		0x43346B79
    uint32_t            magic;
    C4KeyType           type;
    C4KeyProperty       *propList;  // we use this to tag additional properties
   
    union {
        C4KeySymmetric      sym;
        C4KeyTBC            tbc;
        C4KeyPBKDF2         pbkdf2;
    C4KeyPublic_Encrypted   publicKeyEncoded;
        SHARES_ShareInfo    share;
    };
    
};


C4Err C4Key_NewSymmetric(Cipher_Algorithm       algorithm,
                         const void             *key,
                         C4KeyContextRef    *ctx);

C4Err C4Key_NewTBC(     Cipher_Algorithm       algorithm,
                   const void          *key,
                   C4KeyContextRef     *ctx);

C4Err C4Key_NewShare(    SHARES_ShareInfo   *share,
                         C4KeyContextRef    *ctx);

void C4Key_Free(C4KeyContextRef ctx);


C4Err C4Key_Copy(C4KeyContextRef ctx, C4KeyContextRef *ctxOut);

C4Err C4Key_SetProperty( C4KeyContextRef ctx,
                        const char *propName, C4KeyPropertyType propType,
                        void *data,  size_t  datSize);

C4Err C4Key_GetProperty( C4KeyContextRef ctx,
                        const char *propName,
                        C4KeyPropertyType *outPropType, void *outData, size_t bufSize, size_t *datSize);

C4Err SCKeyGetAllocatedProperty( C4KeyContextRef ctx,
                                const char *propName,
                                C4KeyPropertyType *outPropType, void **outData, size_t *datSize);

/*
 C4Key_SerializeToPubKey is limited to TBC keys <= 512 bits since ECC is limited to SHA-512
 */

C4Err C4Key_SerializeToPubKey(C4KeyContextRef       ctx,
                                  ECC_ContextRef    ecc,
                                  uint8_t          **outData,
                                  size_t           *outSize);

C4Err C4Key_SerializeToPassPhrase(C4KeyContextRef  ctx,
                                  const uint8_t    *passphrase,
                                  size_t           passphraseLen,
                                  uint8_t          **outData,
                                  size_t           *outSize);

C4Err C4Key_SerializeToShares(C4KeyContextRef       ctx,
                              uint32_t              totalShares,
                              uint32_t              threshold,
                              SHARES_ContextRef     *outShares,
                              uint8_t               **outData,
                              size_t                *outSize);

C4Err C4Key_DeserializeKeys( uint8_t *inData, size_t inLen,
                                    size_t           *outCount,
                                    C4KeyContextRef  *ctxArray[]);


C4Err C4Key_VerifyPassPhrase(   C4KeyContextRef  ctx,
                                const uint8_t    *passphrase,
                                size_t           passphraseLen);


C4Err C4Key_DecryptFromPassPhrase(   C4KeyContextRef  passCtx,
                                 const uint8_t     *passphrase,
                                 size_t             passphraseLen,
                                 C4KeyContextRef       *symCtx);

C4Err C4Key_DecryptFromPubKey( C4KeyContextRef      encodedCtx,
                                ECC_ContextRef      eccPriv,
                                C4KeyContextRef     *symCtx);


#endif /* c4Keys_h */
