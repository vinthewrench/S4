//
//  s4keys.h
//  S4
//
//  Created by vincent Moscaritolo on 11/10/15.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

#ifndef s4Keys_h
#define s4Keys_h


#include "s4pubtypes.h"

#ifdef __clang__
#pragma mark - Key import Export.
#endif

S4_ASSUME_NONNULL_BEGIN

#define kS4KeyPBKDF2_SaltBytes      8
#define kS4KeyESK_HashBytes      	8
#define kS4Key_KeyIDBytes                     16
#define kS4KeyPublic_Encrypted_BufferMAX      256

#define kS4KeyPublic_MAX_PrivKeyLen 256

#define kS4KeySymmetric_Encrypted_BufferMAX      256

typedef struct S4KeyContext *      S4KeyContextRef;

#define	kInvalidS4KeyContextRef		((S4KeyContextRef) NULL)

#define S4KeyContextRefIsValid( ref )		( (ref) != kInvalidS4KeyContextRef )


enum S4KeyPropertyType_
{
    S4KeyPropertyType_Invalid       = 0,
    S4KeyPropertyType_UTF8String ,
    S4KeyPropertyType_Binary,
    S4KeyPropertyType_Time,
    S4KeyPropertyType_Numeric,
	S4KeyPropertyType_Array,

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
extern char *const kS4KeyProp_Mac;      // Key HASH (kS4KeyESK_HashBytes)

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
extern char *const kS4KeyProp_p2kParams;
extern char *const kS4KeyProp_EncodedObject;

extern char *const kS4KeyProp_ShareOwner;
extern char *const kS4KeyProp_ShareID;

typedef struct S4KeySigItem  S4KeySigItem;

typedef struct S4KeyProperty  S4KeyProperty;

typedef struct S4KeyProperty  *S4KeyPropertyRef;



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
	kS4KeyType_P2K_ESK            	= 10,		// session key encypted to passcode
	kS4KeyType_Share_ESK          	= 11,	// session key encypted to split key

    kS4KeyType_Invalid           =  kEnumMaxValue,
    
    ENUM_FORCE( S4KeyType_ )
};

ENUM_TYPEDEF( S4KeyType_, S4KeyType   );


S4Err S4Key_NewKey(Cipher_Algorithm       algorithm,
				   S4KeyContextRef  __NULLABLE_REF_POINTER ctx);

S4Err S4Key_NewSymmetric(Cipher_Algorithm       algorithm,
						 const void             *key,
						 S4KeyContextRef   __NULLABLE_REF_POINTER ctx);

S4Err S4Key_NewTBC(     Cipher_Algorithm       algorithm,
				   const void          *key,
				   S4KeyContextRef    __NULLABLE_REF_POINTER ctx);


S4Err S4Key_NewPublicKey(Cipher_Algorithm       algorithm,
						 S4KeyContextRef __NULLABLE_REF_POINTER ctx);

S4Err S4Key_Import_ECC_Context(ECC_ContextRef ecc,
							   S4KeyContextRef __NULLABLE_REF_POINTER pubKeyCtx);

void S4Key_Free(S4KeyContextRef ctx);

S4Err S4Key_Clone_ECC_Context(S4KeyContextRef pubKeyCtx,
							  ECC_ContextRef __NULLABLE_REF_POINTER ecc);


S4Err S4Key_Copy(S4KeyContextRef ctx,
				 S4KeyContextRef __NULLABLE_REF_POINTER ctxOut);

S4Err S4Key_SetProperty( S4KeyContextRef ctx,
                        const char *propName, S4KeyPropertyType propType,
                        void *data,  size_t  datSize);

S4Err S4Key_SetPropertyExtended ( S4KeyContextRef ctx,
                                 const char *propName, S4KeyPropertyType propType,
                                 S4KeyPropertyExtendedType  extendedPropType,
                                 void *data,  size_t  datSize);

S4Err S4Key_GetProperty( S4KeyContextRef ctx,
                        const char *propName,
                        S4KeyPropertyType * __S4_NULLABLE outPropType,
						void *__S4_NULLABLE outData, size_t bufSize,
						size_t *__S4_NULLABLE datSize);

S4Err S4Key_GetAllocatedProperty( S4KeyContextRef ctx,
								 const char *propName,
								 S4KeyPropertyType * __S4_NULLABLE outPropType,
								 void __NULLABLE_XFREE_P_P outAllocData,
								 size_t * __S4_NULLABLE datSize);


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
                             uint8_t      	__NULLABLE_XFREE_P_P outAllocData ,
                             size_t* 		 outSize);


S4Err S4Key_SerializeToPassPhrase(S4KeyContextRef  ctx,
                                  const uint8_t    *passphrase,
                                  size_t           passphraseLen,
                                  uint8_t         __NULLABLE_XFREE_P_P outAllocData,
                                  size_t           *outSize)
DEPRECATED_MSG_ATTRIBUTE("Use S4Key_SerializeToPassCode  instead.");


S4Err S4Key_SerializeToShares(S4KeyContextRef     __S4_NONNULL ctx,
                              uint32_t              totalShares,
                              uint32_t              threshold,
							  S4KeyContextRef __NULLABLE_REF_POINTER shareArray[__S4_NULLABLE],
							  uint8_t __NULLABLE_XFREE_P_P outAllocData,
                              size_t                *outSize);

S4Err S4Key_SerializeSharePart(S4KeyContextRef   	ctx,
							   uint8_t               __NULLABLE_XFREE_P_P outAllocData,
							   size_t                *__S4_NULLABLE outSize);

S4Err S4Key_SerializePubKey(S4KeyContextRef  ctx,
                            uint8_t          __NULLABLE_XFREE_P_P outAllocData,
							size_t           *outSize);

// returns an array of S4KeyContextRef- one for each key found.

S4Err S4Key_DeserializeKeys( uint8_t *inData, size_t inLen,
                            size_t           *outCount,
                            S4KeyContextRef  __NULLABLE_REF_POINTER ctxArray[__S4_NULLABLE]);


// same as S4Key_DeserializeKeys but this will return error if one than one key wa found.

S4Err S4Key_DeserializeKey( uint8_t *inData, size_t inLen,
						   S4KeyContextRef   __NULLABLE_REF_POINTER ctxOut);

S4Err S4Key_VerifyPassPhrase(   S4KeyContextRef  ctx,
                             const uint8_t    *passphrase,
                             size_t           passphraseLen);


S4Err S4Key_DecryptFromPassPhrase(   S4KeyContextRef  passCtx,
                                  const uint8_t     *passphrase,
                                  size_t             passphraseLen,
                                  S4KeyContextRef   __NULLABLE_REF_POINTER symCtx);

S4Err S4Key_DecryptFromS4Key( S4KeyContextRef      encodedCtx,
                             S4KeyContextRef       passKeyCtx,
                             S4KeyContextRef       __NULLABLE_REF_POINTER outKeyCtx);

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
							 S4KeyContextRef  __NULLABLE_REF_POINTER ctxArray[__S4_NULLABLE]);

bool S4Key_CompareKeyID(uint8_t* keyID1, uint8_t* keyID2);

S4Err S4Key_NewSignature(   S4KeyContextRef       pubCtx,
                            void                   *hashData,       // hashed data to be signed
                            size_t                 hashDataLen,
                            HASH_Algorithm         hashAlgorithm,
                            long                   sigExpireTime,
                            S4KeyContextRef       __NULLABLE_REF_POINTER ctxOut);

S4Err S4Key_SerializeSignature( S4KeyContextRef      sigCtx,
                               uint8_t          __NULLABLE_XFREE_P_P outAllocData,
                               size_t           *outSize);


S4Err S4Key_VerifySignature( S4KeyContextRef      sigCtx,
                             S4KeyContextRef      sigingKeyCtx,
                            void                   *hash,
                            size_t                 hashLen );

S4Err S4Key_SerializeToPassCode(S4KeyContextRef  ctx,
								const uint8_t* __S4_NONNULL passcode,
								size_t           passcodeLen,
								P2K_Algorithm 	p2kAlgorithm,
								uint8_t __NULLABLE_XFREE_P_P outAllocData,
								size_t* __S4_NULLABLE 		outSize);



S4Err S4Key_DecryptFromPassCode(S4KeyContextRef  __S4_NONNULL	 passCtx,
								const uint8_t* __S4_NONNULL 	passcode,
								size_t           				passcodeLen,
								S4KeyContextRef __NULLABLE_REF_POINTER ctxOut);

S4Err S4Key_VerifyPassCode(   S4KeyContextRef  __S4_NONNULL passCtx,
						   const uint8_t* 		__S4_NONNULL 	passcode,
						   size_t           				passcodeLen);


S4Err S4Key_RecoverKeyFromShares(   S4KeyContextRef  __S4_NONNULL shareCtx,
								 	S4KeyContextRef __NONNULL_ARRAY shares,
								 	uint32_t       	numShares,
								  S4KeyContextRef __NULLABLE_REF_POINTER ctxOut);


S4_ASSUME_NONNULL_END
#endif /* s4Keys_h */
