//
//  s4keys.h
//  S4
//
//  Created by vincent Moscaritolo on 11/10/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef s4Keys_h
#define s4Keys_h

#include "s4pubtypes.h"

#ifdef __clang__
#pragma mark - Key import Export.
#endif



#define kS4KeyPBKDF2_SaltBytes      8
#define kS4KeyPBKDF2_HashBytes      8

#define kS4Key_KeyIDBytes                     16
#define kS4KeyPublic_Encrypted_BufferMAX      256
#define kS4KeyPublic_Encrypted_HashBytes      8

#define kS4KeyPublic_MAX_PrivKeyLen 256

#define kS4KeySymmetric_Encrypted_BufferMAX      256

typedef struct S4KeyContext *      S4KeyContextRef;

#define	kInvalidS4KeyContextRef		((S4KeyContextRef) NULL)

#define S4KeyContextRefIsValid( ref )		( (ref) != kInvalidS4KeyContextRef )


enum S4KeyPropertyType_
{
    S4KeyPropertyType_Invalid       = 0,
    S4KeyPropertyType_UTF8String    = 1,
    S4KeyPropertyType_Binary        = 2,
    S4KeyPropertyType_Time          = 3,
    S4KeyPropertyType_Numeric       = 4,
    
    ENUM_FORCE( S4KeyPropertyType_ )
};

ENUM_TYPEDEF( S4KeyPropertyType_, S4KeyPropertyType   );

enum S4KeyPropertyExtendedType_
{
    S4KeyPropertyExtendedType_None        = 0,
    S4KeyPropertyExtended_Signable    = 1 << 0,
    
    ENUM_FORCE( S4KeyPropertyExtendedType_ )
};

ENUM_TYPEDEF( S4KeyPropertyExtendedType_, S4KeyPropertyExtendedType   );

extern char *const kS4KeyProp_KeyType;
extern char *const kS4KeyProp_KeySuite;
extern char *const kS4KeyProp_HashAlgorithm;
extern char *const kS4KeyProp_KeyData;
extern char *const kS4KeyProp_KeyID;
extern char *const kS4KeyProp_KeyIDString;
extern char *const kS4KeyProp_Mac;      // Key HASH (kS4KeyPublic_Encrypted_HashBytes)

extern char *const kS4KeyProp_StartDate;
extern char *const kS4KeyProp_ExpireDate;
extern char *const kS4KeyProp_EncryptedKey;
extern char *const kS4KeyProp_Encoding;
extern char *const kS4KeyProp_Signature;
extern char *const kS4KeyProp_SignedBy;
extern char *const kS4KeyProp_SignedProperties;
extern char *const kS4KeyProp_SignableProperties;
extern char *const kS4KeyProp_SignedDate;
extern char *const kS4KeyProp_SigExpire;
extern char *const kS4KeyProp_SigID;

typedef struct S4KeySigItem  S4KeySigItem;

typedef struct S4KeyProperty  S4KeyProperty;

struct S4KeyProperty
{
    uint8_t             *prop;
    S4KeyPropertyType   type;
    S4KeyPropertyExtendedType extended;
    uint8_t             *value;
    size_t              valueLen;
    
    S4KeyProperty      *next;
};

enum S4KeyType_
{
    kS4KeyType_Symmetric           = 1,
    kS4KeyType_Tweekable           = 2,
    kS4KeyType_PBKDF2              = 3,
    kS4KeyType_PublicEncrypted      = 4,
    kS4KeyType_SymmetricEncrypted   = 5,
    kS4KeyType_Share                = 6,
    
    kS4KeyType_PublicKey            = 7,
    
    kS4KeyType_Signature            = 8,
    
    kS4KeyType_Invalid           =  kEnumMaxValue,
    
    ENUM_FORCE( S4KeyType_ )
};

ENUM_TYPEDEF( S4KeyType_, S4KeyType   );

typedef struct S4KeySymmetric_
{
    Cipher_Algorithm    symAlgor;
    size_t              keylen;
    uint8_t        		symKey[64];
    
}S4KeySymmetric;


typedef struct S4KeyTBC_
{
    Cipher_Algorithm    tbcAlgor;
    size_t              keybits;
    uint64_t            key[16];
    
}S4KeyTBC;


typedef struct S4KeyPBKDF2_
{
    S4KeyType              keyAlgorithmType;
    Cipher_Algorithm       cipherAlgor;
    
    uint8_t             keyHash[kS4KeyPBKDF2_HashBytes];
    uint8_t             salt[kS4KeyPBKDF2_SaltBytes];
    uint32_t            rounds;
    Cipher_Algorithm       encyptAlgor;
    uint8_t             encrypted[256];
    size_t              encryptedLen;
    
    // FOR PASSCODE SHARED KEYS
    uint8_t         threshold;                              /* Number of shares needed to combine */
    uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
    uint8_t			shareHash[kS4ShareInfo_HashBytes];      /* Share data Hash - AKA serial number */
    
    
}S4KeyPBKDF2;

typedef struct S4KeyPublic_Encrypted_
{
    S4KeyType               keyAlgorithmType;
    Cipher_Algorithm        cipherAlgor;
    
    uint8_t             keyHash[kS4KeyPublic_Encrypted_HashBytes];
    
    size_t              keysize;
    uint8_t            keyID[kS4Key_KeyIDBytes];
    
    uint8_t             encrypted[kS4KeyPublic_Encrypted_BufferMAX];
    size_t              encryptedLen;
    
    // FOR PUBLIC ENCRYPTED SHARED KEYS
    uint8_t         threshold;                              /* Number of shares needed to combine */
    uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
    uint8_t			shareHash[kS4ShareInfo_HashBytes];      /* Share data Hash - AKA serial number */
    
}S4KeyPublic_Encrypted;

typedef struct S4KeyPublic_
{
    Cipher_Algorithm    cipherAlgor;            /*  kCipher_Algorithm_ECC384, kCipher_Algorithm_ECC414 */
    bool                isPrivate;
    
    uint8_t             keyID[kS4Key_KeyIDBytes];
    uint8_t             keyHash[kS4KeyPublic_Encrypted_HashBytes];
    
    uint8_t             pubKey[256];
    size_t              pubKeyLen;
    
    uint8_t             *privKey;
    size_t              privKeyLen;
    
    ECC_ContextRef      ecc;
    
    
}S4KeyPublic;

typedef struct S4KeySym_Encrypted_
{
    S4KeyType               keyAlgorithmType;
    Cipher_Algorithm        cipherAlgor;
    
    Cipher_Algorithm        encryptingAlgor;
    
    uint8_t             keyHash[kS4KeyPublic_Encrypted_HashBytes];
    
    size_t              keysize;
    uint8_t            keyID[kS4Key_KeyIDBytes];
    
    uint8_t             encrypted[kS4KeySymmetric_Encrypted_BufferMAX];
    size_t              encryptedLen;
    
    
}S4KeySym_Encrypted;


typedef struct  S4KeySig_
{
    uint8_t            sigID[kS4Key_KeyIDBytes];        // random ID to identify signature
    uint8_t            issuerID[kS4Key_KeyIDBytes];        // signing key ID
    
    time_t             signDate;
    time_t             expirationTime;                  // seconds after signDate
    uint8_t            *signature;
    size_t             signatureLen;
    HASH_Algorithm     hashAlgorithm;
    char**             propNameList;                   // pointer to array of strings
    
}S4KeySig;


struct S4KeySigItem
{
    S4KeySigItem      *next;
    S4KeySig          sig;
};


typedef struct S4KeyContext    S4KeyContext;

struct S4KeyContext
{
    
#define kS4KeyContextMagic		0x43346B79
    uint32_t            magic;
    S4KeyType           type;
    S4KeyProperty       *propList;  // we use this to tag additional properties
    S4KeySigItem        *sigList;   // list of signatures
    
    union {
        S4KeySymmetric      sym;
        S4KeyTBC            tbc;
        S4KeyPBKDF2         pbkdf2;
        S4KeyPublic_Encrypted   publicKeyEncoded;
        S4KeySym_Encrypted  symKeyEncoded;
        SHARES_ShareInfo    share;
        
        S4KeyPublic         pub;
        S4KeySig            sig;
    };
    
};


S4Err S4Key_NewKey(Cipher_Algorithm       algorithm,
                   S4KeyContextRef    *ctx);

S4Err S4Key_NewSymmetric(Cipher_Algorithm       algorithm,
                         const void             *key,
                         S4KeyContextRef    *ctx);

S4Err S4Key_NewTBC(     Cipher_Algorithm       algorithm,
                   const void          *key,
                   S4KeyContextRef     *ctx);

S4Err S4Key_NewShare(    SHARES_ShareInfo   *share,
                     S4KeyContextRef    *ctx);

S4Err S4Key_NewPublicKey(Cipher_Algorithm       algorithm,
                         S4KeyContextRef    *ctx);

S4Err S4Key_Import_ECC_Context(ECC_ContextRef ecc, S4KeyContextRef*pubKeyCtx);

void S4Key_Free(S4KeyContextRef ctx);

S4Err S4Key_Clone_ECC_Context(S4KeyContextRef pubKeyCtx,  ECC_ContextRef *ecc);


S4Err S4Key_Copy(S4KeyContextRef ctx, S4KeyContextRef *ctxOut);

S4Err S4Key_SetProperty( S4KeyContextRef ctx,
                        const char *propName, S4KeyPropertyType propType,
                        void *data,  size_t  datSize);

S4Err S4Key_SetPropertyExtended ( S4KeyContextRef ctx,
                                 const char *propName, S4KeyPropertyType propType,
                                 S4KeyPropertyExtendedType  extendedPropType,
                                 void *data,  size_t  datSize);

S4Err S4Key_GetProperty( S4KeyContextRef ctx,
                        const char *propName,
                        S4KeyPropertyType *outPropType, void *outData, size_t bufSize, size_t *datSize);

S4Err S4Key_GetProperty( S4KeyContextRef ctx,
                        const char *propName,
                        S4KeyPropertyType *outPropType, void *outData, size_t bufSize, size_t *datSize);

S4Err S4Key_GetAllocatedProperty( S4KeyContextRef ctx,
                                const char *propName,
                                S4KeyPropertyType *outPropType, void **outData, size_t *datSize);


S4Err S4Key_GetExtendedProperty( S4KeyContextRef ctx,
                                const char *propName,
                                S4KeyPropertyExtendedType *outPropType);

S4Err S4Key_RemoveProperty( S4KeyContextRef ctx,
                           const char *propName);

/*
 using S4Key_SerializeToS4Key with public passkey is  limited to TBC keys <= 512 bits
 since ECC is limited to SHA-512
 */

S4Err S4Key_SerializeToS4Key(S4KeyContextRef  ctx,
                             S4KeyContextRef  passKeyCtx,
                             uint8_t          **outData,
                             size_t           *outSize);


S4Err S4Key_SerializeToPassPhrase(S4KeyContextRef  ctx,
                                  const uint8_t    *passphrase,
                                  size_t           passphraseLen,
                                  uint8_t          **outData,
                                  size_t           *outSize);

S4Err S4Key_SerializeToShares(S4KeyContextRef       ctx,
                              uint32_t              totalShares,
                              uint32_t              threshold,
                              SHARES_ContextRef     *outShares,
                              uint8_t               **outData,
                              size_t                *outSize);

S4Err S4Key_SerializePubKey(S4KeyContextRef  ctx,
                            uint8_t          **outData,
                            size_t           *outSize);

S4Err S4Key_DeserializeKeys( uint8_t *inData, size_t inLen,
                            size_t           *outCount,
                            S4KeyContextRef  *ctxArray[]);


S4Err S4Key_VerifyPassPhrase(   S4KeyContextRef  ctx,
                             const uint8_t    *passphrase,
                             size_t           passphraseLen);


S4Err S4Key_DecryptFromPassPhrase(   S4KeyContextRef  passCtx,
                                  const uint8_t     *passphrase,
                                  size_t             passphraseLen,
                                  S4KeyContextRef       *symCtx);

S4Err S4Key_DecryptFromS4Key( S4KeyContextRef      encodedCtx,
                             S4KeyContextRef       passKeyCtx,
                             S4KeyContextRef       *outKeyCtx);

S4Err S4Key_SignHash( S4KeyContextRef      pubKeyCtx,
                     void *hash, size_t hashLen,
                     void *outSig, size_t bufSize, size_t *outSigLen);

S4Err S4Key_VerifyHash( S4KeyContextRef  ctx,
                       void *hash, size_t hashLen,
                       void *sig,  size_t sigLen);

S4Err S4Key_SignKey(    S4KeyContextRef      signingCtx,
                        S4KeyContextRef      pubCtx,
                        long                 sigExpireTime  // seconds to sig expire or LONG_MAX
                    );


S4Err S4Key_VerfiyKeySig( S4KeyContextRef      pubCtx,
                          S4KeyContextRef      sigingKeyCtx,
                          S4KeyContextRef      sigCtx);

S4Err S4Key_GetKeySignatures( S4KeyContextRef      ctx,
                             size_t           *outCount,
                             S4KeyContextRef  *ctxArray[]);

bool S4Key_CompareKeyID(uint8_t* keyID1, uint8_t* keyID2);

S4Err S4Key_NewSignature(   S4KeyContextRef       pubCtx,
                            void                   *hashData,       // hashed data to be signed
                            size_t                 hashDataLen,
                            HASH_Algorithm         hashAlgorithm,
                            long                   sigExpireTime,
                            S4KeyContextRef        *ctxOut);

S4Err S4Key_SerializeSignature( S4KeyContextRef      sigCtx,
                               uint8_t          **outData,
                               size_t           *outSize);


S4Err S4Key_VerifySignature( S4KeyContextRef      sigCtx,
                             S4KeyContextRef      sigingKeyCtx,
                            void                   *hash,
                            size_t                 hashLen );


#endif /* s4Keys_h */
