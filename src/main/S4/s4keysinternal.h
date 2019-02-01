//
//  s4keysinternal.h
//  S4
//
//  Created by vinnie on 1/26/19.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

/**
 * @file s4keysinternal.h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Key Management data structure internals
 *
 */

#ifndef s4keysinternal_h
#define s4keysinternal_h

#include "s4keys.h"
S4_ASSUME_NONNULL_BEGIN

struct S4KeyProperty
{
	uint8_t             *prop;
	S4KeyPropertyType   type;
	S4KeyPropertyExtendedType extended;
	uint8_t             *value;
	size_t              valueLen;

	S4KeyProperty      *next;
};


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

	uint8_t             keyHash[kS4KeyESK_HashBytes];
	uint8_t             salt[kS4KeyPBKDF2_SaltBytes];
	uint32_t            rounds;
	Cipher_Algorithm       encyptAlgor;
	uint8_t             encrypted[256];
	size_t              encryptedLen;

}S4KeyPBKDF2;

typedef struct S4KeyESK_
{
	S4KeyType              keyAlgorithmType;
	Cipher_Algorithm       cipherAlgor;
	const char*			   p2kParams;

	uint8_t             	keyHash[kS4KeyESK_HashBytes];

	Cipher_Algorithm	   objectAlgor;  // the type of object we have encoded

	uint8_t             iv[256];
	size_t              ivLen;

	uint8_t             esk[256];
	size_t              eskLen;

	uint8_t             *encrypted;
	size_t              encryptedLen;

	// for SHARE encoded keys
	uint8_t         threshold;                              /* Number of shares needed to combine */
	uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
	uint8_t			shareOwner[kS4ShareInfo_HashBytes];      /* Share owner  - serial number */

	uint8_t         totalShares;                      	/* Number of shares needed to combine */
	uint8_t		 	__NULLABLE_XFREE_P_P shareIDList; 	/* pointer null terminated  array of data
														 Share data Hash - AKA serial number */

}S4KeyESK;


typedef struct S4KeyPublic_Encrypted_
{
	S4KeyType               keyAlgorithmType;
	Cipher_Algorithm        cipherAlgor;

	uint8_t             keyHash[kS4KeyESK_HashBytes];

	size_t              keysize;
	uint8_t            keyID[kS4Key_KeyIDBytes];

	uint8_t             encrypted[kS4KeyPublic_Encrypted_BufferMAX];
	size_t              encryptedLen;

}S4KeyPublic_Encrypted;

typedef struct S4KeyPublic_
{
	ECC_Algorithm		eccAlgor;
	bool                isPrivate;

	uint8_t             keyID[kS4Key_KeyIDBytes];
	uint8_t             keyHash[kS4KeyESK_HashBytes];

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

	uint8_t             keyHash[kS4KeyESK_HashBytes];
	uint8_t            keyID[kS4Key_KeyIDBytes];

	uint8_t             encrypted[kS4KeySymmetric_Encrypted_BufferMAX];
	size_t              encryptedLen;
}S4KeySym_Encrypted;

typedef struct S4KeyShareItem_
{
	uint8_t			shareOwner[kS4ShareInfo_HashBytes];      /* Share owner  - serial number */
	uint8_t			shareID[kS4ShareInfo_HashBytes];     	 /* Share ID -serial number */
	uint8_t         threshold;                              /* Number of shares needed to combine */
	uint8_t			xCoordinate;                            /* X coordinate of share  AKA the share index */
	size_t          shareSecretLen;
	uint8_t         shareSecret[kS4ShareInfo_MaxSecretBytes];                        /* the actual share secret */
}S4KeyShareItem;

typedef struct  S4KeySig_
{
	uint8_t            sigID[kS4Key_KeyIDBytes];        // random ID to identify signature
	uint8_t            issuerID[kS4Key_KeyIDBytes];        // signing key ID

	time_t             signDate;
	time_t             expirationTime;                  // seconds after signDate
	uint8_t            *signature;
	size_t             signatureLen;
	HASH_Algorithm     hashAlgorithm;
	char	__NULLABLE_XFREE_P_P propNameList;                   // pointer to array of strings

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
		S4KeyShareItem    	share;
		S4KeyPublic         pub;
		S4KeySig            sig;
		S4KeyESK            esk;
	};
};

S4_ASSUME_NONNULL_END
#endif /* s4keysinternal_h */
