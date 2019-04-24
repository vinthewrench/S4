//
//  s4Key.c
//  S4
//
//  Created by vincent Moscaritolo on 11/9/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//


#include <ctype.h>
#include <sys/types.h>

#ifndef __USE_BSD
#define __USE_BSD
#include <time.h>
#undef __USE_BSD
#endif

#include <math.h>

#if defined(ANDROID)
#include "timegm.c"
#endif

#include "s4internal.h"

// Libraries

#include "jsmn.h"
#include "yajl_parse.h"
#include "yajl_gen.h"
#include "yajl_parser.h"


#ifdef __clang__
#pragma mark - YAJL memory management
#endif


#define CKYJAL  if((stat != yajl_gen_status_ok)) {\
printf("ERROR %d (%d)  %s:%d \n",  err, stat, __FILE__, __LINE__); \
err = kS4Err_CorruptData; \
goto done; }


static void yajlFree(void * ctx, void * ptr)
{
	XFREE(ptr);
}

static void * yajlMalloc(void * ctx, size_t sz)
{
	return XMALLOC(sz);
}

static void * yajlRealloc(void * ctx, void * ptr, size_t sz)
{
	
	return XREALLOC(ptr, sz);
}


#define CMP2(b1, l1, b2, l2)							\
(((l1) == (l2)) && (memcmp((void *)(b1), (void *)(b2), (l1)) == 0))

#define STRCMP2(s1, s2) \
(CMP2((s1), strlen(s1), (s2), strlen(s2)))


#define kS4KeyProtocolVersion  0x01

#define K_KEYTYPE           "keyType"
#define K_KEYSUITE          "keySuite"
#define K_KEYDATA           "keyData"
#define K_HASHALGORITHM     "hashAlgorithm"

#define K_INDEX             "index"
#define K_THRESHLOLD        "threshold"
#define K_TOTALSHARES       "totalShares"
#define K_SHAREHASH         "sharehash"

#define K_PROP_SHAREID	        "shareID"
#define K_PROP_SHAREONWER	    "shareOwner"

#define K_SHAREIDS          "shareIDs"
#define K_PUBKEY            "pubKey"
#define K_PRIVKEY           "privKey"

#define K_KEYSUITE_AES128     "AES-128"
#define K_KEYSUITE_AES192     "AES-192"
#define K_KEYSUITE_AES256     "AES-256"
#define K_KEYSUITE_2FISH256   "Twofish-256"
#define K_KEYSUITE_3FISH256   "ThreeFish-256"
#define K_KEYSUITE_3FISH512   "ThreeFish-512"
#define K_KEYSUITE_3FISH1024  "ThreeFish-1024"
#define K_KEYSUITE_SPLIT      "Shamir"

#define K_HASHALGORITHM_SHA256    "SHA-256"
#define K_HASHALGORITHM_SHA512    "SHA-512"
#define K_HASHALGORITHM_SKEIN256  "SKEIN-256"
#define K_HASHALGORITHM_SKEIN512  "SKEIN-512"

#define K_KEYSUITE_ECC384     "ecc384"
#define K_KEYSUITE_ECC414     "Curve41417"

#define K_PROP_VERSION          "version"
#define K_PROP_ENCODING         "encoding"
#define K_PROP_SALT             "salt"
#define K_PROP_ROUNDS           "rounds"
#define K_PROP_MAC              "mac"
#define K_PROP_ENCRYPTED        "encrypted"
#define K_PROP_KEYID            "keyID"
#define K_PROP_KEYIDSTR         "keyID-String"

#define K_PROP_STARTDATE        "start-date"
#define K_PROP_EXPIREDATE       "expire-date"
#define K_SIGNATURE             "signature"
#define K_SIGNATURES            "signatures"
#define K_SIGN_BYID             "issuer"
#define K_SIGPROPS              "signed-properties"
#define K_PROP_SIGNED_DATE      "issue-date"
#define K_PROP_SIGEXPIRE        "sig-expire"
#define K_SIGNABLE_PROPS        "signable-properties"
#define K_SIGID                 "sigID"
#define K_PROP_ENCODED_OBJECT 	"encodedObject"
#define K_PROP_P2K_PARAMS       "p2k-params"
#define K_ESK                	"esk"
#define K_IV   	 				"iv"


char *const kS4KeyProp_KeyType          = K_KEYTYPE;
char *const kS4KeyProp_KeySuite         = K_KEYSUITE;
char *const kS4KeyProp_HashAlgorithm    = K_HASHALGORITHM;

char *const kS4KeyProp_KeyData          = K_KEYDATA;
char *const kS4KeyProp_KeyID            = K_PROP_KEYID;
char *const kS4KeyProp_KeyIDString      = K_PROP_KEYIDSTR;
char *const kS4KeyProp_Mac              = K_PROP_MAC;
char *const kS4KeyProp_StartDate        = K_PROP_STARTDATE;
char *const kS4KeyProp_ExpireDate       = K_PROP_EXPIREDATE;
char *const kS4KeyProp_EncryptedKey     = K_PROP_ENCRYPTED;
char *const kS4KeyProp_Encoding         = K_PROP_ENCODING;
char *const kS4KeyProp_SigID            = K_SIGID;

char *const kS4KeyProp_Signature        = K_SIGNATURE;
char *const kS4KeyProp_SignedBy         = K_SIGN_BYID;
char *const kS4KeyProp_SignedProperties = K_SIGPROPS;
char *const kS4KeyProp_SignedDate        = K_PROP_SIGNED_DATE;
char *const kS4KeyProp_SigExpire         = K_PROP_SIGEXPIRE;

char *const kS4KeyProp_SignableProperties  = K_SIGNABLE_PROPS;
char *const kS4KeyProp_p2kParams       		= K_PROP_P2K_PARAMS;
char *const kS4KeyProp_EncodedObject   		= K_PROP_ENCODED_OBJECT;

char *const kS4KeyProp_ShareOwner   	 = K_PROP_SHAREONWER;
char *const kS4KeyProp_ShareID       	 = K_PROP_SHAREID;
char *const kS4KeyProp_ShareIndex      = K_INDEX;
char *const kS4KeyProp_ShareThreshold  = K_THRESHLOLD;
char *const kS4KeyProp_ShareTotal  	  = K_TOTALSHARES;

static char *const kS4KeyProp_Version      = K_PROP_VERSION;

static char *const kS4KeyProp_Encoding_SYM_AES128    = K_KEYSUITE_AES128;
static char *const kS4KeyProp_Encoding_SYM_AES256    = K_KEYSUITE_AES256;
static char *const kS4KeyProp_Encoding_SYM_2FISH256    = K_KEYSUITE_2FISH256;

static char *const kS4KeyProp_Encoding_PBKDF2_AES256    = "pbkdf2-AES256";
static char *const kS4KeyProp_Encoding_PBKDF2_2FISH256  = "pbkdf2-Twofish-256";

static char *const kS4KeyProp_Encoding_P2K = 			"p2k";

static char *const kS4KeyProp_Encoding_SPLIT_AES256    = "Shamir-AES256";
static char *const kS4KeyProp_Encoding_SPLIT_2FISH256  = "Shamir-Twofish-256";

static char *const kS4KeyProp_Encoding_PUBKEY_ECC384   =  "ECC-384";
static char *const kS4KeyProp_Encoding_PUBKEY_ECC414   =  "Curve41417";

static char *const kS4KeyProp_Encoding_Signature       = "Signature";

static char *const kS4KeyProp_Salt              = K_PROP_SALT;
static char *const kS4KeyProp_Rounds            = K_PROP_ROUNDS;
static char *const kS4KeyProp_IV = 				K_IV;
static char *const kS4KeyProp_ESK =				K_ESK;

static char *const kS4KeyProp_ShareHash       = K_SHAREHASH;
static char *const kS4KeyProp_ShareIDs        = K_SHAREIDS;

static char *const kS4KeyProp_PubKey            = K_PUBKEY;
static char *const kS4KeyProp_PrivKey           = K_PRIVKEY;

static char *const kS4KeyProp_Signatures    = K_SIGNATURES;

static const char *kRfc339Format = "%Y-%m-%dT%H:%M:%SZ";

typedef struct S4KeyPropertyInfo_
{
	char      *const name;
	S4KeyPropertyType type;
	bool              readOnly;
	bool              signable;
} S4KeyPropertyInfo;


static S4KeyPropertyInfo sPropertyTable[] = {
	
	{ K_PROP_VERSION,           S4KeyPropertyType_Numeric,  true,  false},
	{ K_KEYTYPE,                S4KeyPropertyType_Numeric,  true,  false},
	{ K_KEYSUITE,               S4KeyPropertyType_Numeric,  true,  true},
	{ K_KEYDATA,                S4KeyPropertyType_Binary,  true,  true},
	{ K_HASHALGORITHM,          S4KeyPropertyType_Numeric,  true,  false},
	
	{ K_PROP_ENCODING,          S4KeyPropertyType_UTF8String,  true,  true},
	{ K_PROP_SALT,              S4KeyPropertyType_Binary,  true,  true},
	{ K_PROP_ROUNDS,            S4KeyPropertyType_Numeric,  true,  true},
	{ K_PROP_MAC,               S4KeyPropertyType_Binary,  true,  true},
	{ K_PROP_ENCRYPTED,         S4KeyPropertyType_Binary,  true,  true},
	{ K_PROP_KEYID,             S4KeyPropertyType_Binary,  true,  true},
	{ K_PROP_KEYIDSTR,          S4KeyPropertyType_UTF8String,  true,  true},
	
	{ K_SHAREHASH,              S4KeyPropertyType_Binary,  true,  true},
	{ K_INDEX,                  S4KeyPropertyType_Numeric,  true,  true},
	{ K_THRESHLOLD,             S4KeyPropertyType_Numeric,  true,  true},
	{ K_TOTALSHARES,             S4KeyPropertyType_Numeric,  true,  true},
	
	{ K_SIGN_BYID,              S4KeyPropertyType_Binary,   true,  false},
	{ K_PROP_EXPIREDATE,        S4KeyPropertyType_Time,     false,  true},
	{ K_PROP_STARTDATE,         S4KeyPropertyType_Time,     false,  true},
	{ K_PROP_SIGNED_DATE,       S4KeyPropertyType_Time,     true,  false},
	{ K_PROP_SIGEXPIRE,         S4KeyPropertyType_Time,     true,  false},
	{ K_SIGID,                  S4KeyPropertyType_Binary,  false,  false},
	{ K_ESK,                  	S4KeyPropertyType_Binary,  false,  false},
	{ K_IV,                  	S4KeyPropertyType_Binary,  false,  false},
	{ K_PROP_P2K_PARAMS,    	S4KeyPropertyType_UTF8String,  true,  true},
	{ K_PROP_ENCODED_OBJECT, 	S4KeyPropertyType_Numeric,  	true,  true},
	
	{ K_PROP_SHAREID,       	S4KeyPropertyType_Binary,  true,  true},
	{ K_PROP_SHAREONWER,      	S4KeyPropertyType_Binary,  true,  true},
	
	{ NULL,                     S4KeyPropertyType_Invalid,  true,  true},
};


#ifdef __clang__
#pragma mark - fwd declare
#endif

static void sCloneSignatures(S4KeyContext *src, S4KeyContext *dest );
static char** sDeepStrDup( char** list);
static S4Err sGetSignablePropertyNames(S4KeyContext *ctx,  char ***namesOut, size_t* countOut );
static S4Err sCalulateKeyDigest( S4KeyContextRef  keyCtx,
										  char**            optionalPropNamesList,
										  HASH_Algorithm    hashAlgorithm,
										  time_t            signDate,
										  long              sigExpireTime,
										  uint8_t* hashBuf, size_t *hashBytes );

static S4Err sP2K_EncryptKeyToPassPhrase( const void 		*keyIn,
													  size_t 			keyInLen,
													  Cipher_Algorithm cipherAlgorithm,
													  const uint8_t    *passphrase,
													  size_t           passphraseLen,
													  P2K_Algorithm 	p2kAlgor,
													  S4KeyPropertyRef  propList,
													  uint8_t __NULLABLE_XFREE_P_P outAllocData,
													  size_t* __S4_NULLABLE 		outSize);

static S4KeyType sGetKeyType(Cipher_Algorithm algorithm);
static int sGetKeyLength(S4KeyType keyType, int32_t algorithm);
static time_t parseRfc3339(const unsigned char *s, size_t stringLen);
static S4Err sParseKeySuiteString(const unsigned char * stringVal,  size_t stringLen,
											 S4KeyType *keyTypeOut, Cipher_Algorithm *algorithmOut);
static S4Err sParseEncodingString(const unsigned char * stringVal,  size_t stringLen,
											 S4KeyContextRef keyP);

#ifdef __clang__
#pragma mark - Key utilities.
#endif

static char *cipher_algor_table(Cipher_Algorithm algor)
{
	switch (algor )
	{
		case kCipher_Algorithm_AES128: 		return (K_KEYSUITE_AES128);
		case kCipher_Algorithm_AES192: 		return (K_KEYSUITE_AES192);
		case kCipher_Algorithm_AES256: 		return (K_KEYSUITE_AES256);
		case kCipher_Algorithm_2FISH256:    return (K_KEYSUITE_2FISH256);
			
		case kCipher_Algorithm_3FISH256:    return (K_KEYSUITE_3FISH256);
		case kCipher_Algorithm_3FISH512:    return (K_KEYSUITE_3FISH512);
		case kCipher_Algorithm_3FISH1024:   return (K_KEYSUITE_3FISH1024);
			
		case kCipher_Algorithm_ECC384:      return (K_KEYSUITE_ECC384);
		case kCipher_Algorithm_ECC414:      return (K_KEYSUITE_ECC414);
			
		case kCipher_Algorithm_SharedKey: 		return (K_KEYSUITE_SPLIT);
			
			
		default:				return (("Invalid"));
	}
}


static char *hash_algor_table(HASH_Algorithm algor)
{
	switch (algor )
	{
		case kHASH_Algorithm_SHA256:		return (K_HASHALGORITHM_SHA256);
		case kHASH_Algorithm_SHA512:		return (K_HASHALGORITHM_SHA512);
		case kHASH_Algorithm_SKEIN256:		return (K_HASHALGORITHM_SKEIN256);
		case kHASH_Algorithm_SKEIN512:		return (K_HASHALGORITHM_SKEIN512);
		default:				return (("Invalid"));
	}
}


static bool sS4KeyContextIsValid( const S4KeyContextRef  ref)
{
	bool       valid	= false;
	
	valid	= IsntNull( ref ) && ref->magic	 == kS4KeyContextMagic;
	
	return( valid );
}

#define validateS4KeyContext( s )		\
ValidateParam( sS4KeyContextIsValid( s ) )

static S4Err sPASSPHRASE_HASH( const uint8_t  *key,
										unsigned long  key_len,
										uint8_t       *salt,
										unsigned long  salt_len,
										uint32_t        roundsIn,
										uint8_t        *mac_buf,
										unsigned long  mac_len)
{
	S4Err           err = kS4Err_NoErr;
	
	MAC_ContextRef  macRef     = kInvalidMAC_ContextRef;
	
	uint32_t        rounds = roundsIn;
	uint8_t         L[4];
	char*           label = "passphrase-hash";
	
	L[0] = (salt_len >> 24) & 0xff;
	L[1] = (salt_len >> 16) & 0xff;
	L[2] = (salt_len >> 8) & 0xff;
	L[3] = salt_len & 0xff;
	
	err = MAC_Init(kMAC_Algorithm_SKEIN,
						kHASH_Algorithm_SKEIN256,
						key, key_len, &macRef); CKERR
	
	MAC_Update(macRef,  "\x00\x00\x00\x01",  4);
	MAC_Update(macRef,  label,  strlen(label));
	
	err = MAC_Update( macRef, salt, salt_len); CKERR;
	MAC_Update(macRef,  L,  4);
	
	err = MAC_Update( macRef, &rounds, sizeof(rounds)); CKERR;
	MAC_Update(macRef,  "\x00\x00\x00\x04",  4);
	
	size_t mac_len_SZ = (size_t)mac_len;
	err = MAC_Final( macRef, mac_buf, &mac_len_SZ); CKERR;
	
done:
	
	MAC_Free(macRef);
	
	return err;
}

static S4Err sP2K_PASSPHRASE_HASH( const uint8_t  *key,
											 unsigned long  key_len,
											 const char 	 *p2kParamsStr,
											 uint8_t        *mac_buf,
											 unsigned long  mac_len)
{
	S4Err           err = kS4Err_NoErr;
	
	MAC_ContextRef  macRef     = kInvalidMAC_ContextRef;
	
	uint8_t         L[4];
	char*           label = "passphrase-hash";
	
	size_t p2kParamsLen = strlen(p2kParamsStr);
	
	L[0] = (p2kParamsLen >> 24) & 0xff;
	L[1] = (p2kParamsLen >> 16) & 0xff;
	L[2] = (p2kParamsLen >> 8) & 0xff;
	L[3] = p2kParamsLen & 0xff;
	
	err = MAC_Init(kMAC_Algorithm_SKEIN,
						kHASH_Algorithm_SKEIN256,
						key, key_len, &macRef); CKERR
	
	MAC_Update(macRef,  "\x00\x00\x00\x01",  4);
	MAC_Update(macRef,  label,  strlen(label));
	
	MAC_Update(macRef,  L,  4);
	err = MAC_Update( macRef, p2kParamsStr, p2kParamsLen); CKERR;
	
	size_t mac_len_SZ = (size_t)mac_len;
	err = MAC_Final( macRef, mac_buf, &mac_len_SZ); CKERR;
	
done:
	
	MAC_Free(macRef);
	
	return err;
}

static S4Err sKEY_HASH( const uint8_t  *key,
							  unsigned long  key_len,
							  S4KeyType     keyTypeIn,
							  int           keyAlgorithmIn,
							  uint8_t        *mac_buf,
							  unsigned long  mac_len)
{
	S4Err           err = kS4Err_NoErr;
	
	MAC_ContextRef  macRef     = kInvalidMAC_ContextRef;
	
	uint32_t        keyType = keyTypeIn;
	uint32_t        algorithm = keyAlgorithmIn;
	
	char*           label = "key-hash";
	
	err = MAC_Init(kMAC_Algorithm_SKEIN,
						kHASH_Algorithm_SKEIN256,
						key, key_len, &macRef); CKERR
	
	MAC_Update(macRef,  "\x00\x00\x00\x01",  4);
	MAC_Update(macRef,  label,  strlen(label));
	
	err = MAC_Update( macRef, &keyType, sizeof(keyType)); CKERR;
	MAC_Update(macRef,  "\x00\x00\x00\x04",  4);
	
	err = MAC_Update( macRef, &algorithm, sizeof(algorithm)); CKERR;
	MAC_Update(macRef,  "\x00\x00\x00\x04",  4);
	
	size_t mac_len_SZ = (size_t)mac_len;
	err = MAC_Final( macRef, mac_buf, &mac_len_SZ); CKERR;
	
done:
	
	MAC_Free(macRef);
	
	return err;
}

S4KeyType sGetKeyType(Cipher_Algorithm algorithm)
{
	S4KeyType keyType = kS4KeyType_Invalid;
	
	switch(algorithm)
	{
		case kCipher_Algorithm_AES128:
		case kCipher_Algorithm_AES192:
		case kCipher_Algorithm_AES256:
		case kCipher_Algorithm_2FISH256:
			keyType = kS4KeyType_Symmetric;
			break;
			
		case kCipher_Algorithm_3FISH256:
		case kCipher_Algorithm_3FISH512:
		case kCipher_Algorithm_3FISH1024:
			keyType = kS4KeyType_Tweekable;
			break;
			
		case kCipher_Algorithm_SharedKey:
			keyType = kS4KeyType_Share;
			break;
			
		case kCipher_Algorithm_ECC384: // kCipher_Algorithm_NISTP384:
		case kCipher_Algorithm_ECC414: //  kCipher_Algorithm_ECC41417:
			keyType = kS4KeyType_PublicKey;
			break;
			
		default:;
	}
	return keyType;
}

int sGetKeyLength(S4KeyType keyType, int32_t algorithm)
{
	int          keylen = 0;
	
	switch(keyType)
	{
		case kS4KeyType_Symmetric:
			
			switch(algorithm)
		{
			case kCipher_Algorithm_AES128:
				keylen = 16;
				break;
				
			case kCipher_Algorithm_AES192:
				keylen = 24;
				break;
				
			case kCipher_Algorithm_AES256:
				keylen = 32;
				break;
				
			case kCipher_Algorithm_2FISH256:
				keylen = 32;
				break;
				
			default:;
		}
			
			break;
			
		case kS4KeyType_Tweekable:
			switch(algorithm)
		{
			case kCipher_Algorithm_3FISH256:
				keylen = 32;
				break;
				
			case kCipher_Algorithm_3FISH512:
				keylen = 64;
				break;
				
			case kCipher_Algorithm_3FISH1024:
				keylen = 128;
				break;
				
			default:;
		}
			break;
			
		default:;
	}
	
	
	return keylen;
	
}

static S4KeyPropertyInfo* sInfoForPropertyName( const char *propName,
															  size_t  propNameLen )
{
	S4KeyPropertyInfo  *found = NULL;
	
	for(S4KeyPropertyInfo* propInfo = sPropertyTable;  propInfo->name;  propInfo++)
	{
		if(CMP2(propName, propNameLen, propInfo->name, strlen(propInfo->name)))
		{
			found = propInfo;
			break;
		}
	}
	
	return found;
	
}




static yajl_gen_status sGenPropStrings(S4KeyPropertyRef propList, yajl_gen g)
{
	S4Err           err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	S4KeyProperty *prop = propList;
	while(prop)
	{
		stat = yajl_gen_string(g, prop->prop, strlen((char *)(prop->prop))) ; CKYJAL;
		switch(prop->type)
		{
			case S4KeyPropertyType_UTF8String:
				stat = yajl_gen_string(g, prop->value, prop->valueLen) ; CKYJAL;
				break;
				
			case S4KeyPropertyType_Binary:
			{
				size_t propLen =  prop->valueLen*4;
				uint8_t     *propBuf =  XMALLOC(propLen);
				
				base64_encode(prop->value, prop->valueLen, propBuf, &propLen);
				stat = yajl_gen_string(g, propBuf, (size_t)propLen) ; CKYJAL;
				XFREE(propBuf);
			}
				break;
				
			case S4KeyPropertyType_Time:
			{
				uint8_t     tempBuf[32];
				size_t      tempLen;
				time_t      gTime;
				struct      tm *nowtm;
				
				COPY(prop->value, &gTime, sizeof(gTime));
				nowtm = gmtime(&gTime);
				tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
				stat = yajl_gen_string(g, tempBuf, tempLen) ; CKYJAL;
			}
				break;
				
			case S4KeyPropertyType_Numeric:
			{
				uint 		num;
				uint8_t     tempBuf[32];
				
				COPY(prop->value,&num, sizeof(num));
				sprintf((char *)tempBuf, "%d", num);
				stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
			}
				break;
				
			default:
				yajl_gen_string(g, (uint8_t *)"NULL", 4) ;
				break;
		}
		
		prop = prop->next;
	}
	
done:
	return err;
}
static yajl_gen_status sGenSignatureStrings(S4KeyContextRef ctx, yajl_gen g)

{
	S4Err               err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	uint8_t             tempBuf[1024];
	size_t              tempLen;
	
	char*               hashAlgorString = "Invalid";
	
	S4KeySigItem *sigItem = ctx->sigList;
	if(sigItem)
	{
		stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Signatures, strlen(kS4KeyProp_Signatures)) ; CKYJAL;
		stat = yajl_gen_array_open(g); CKYJAL;
		while(sigItem)
		{
			
			stat = yajl_gen_map_open(g); CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SigID, strlen(kS4KeyProp_SigID)) ; CKYJAL;
			tempLen = sizeof(tempBuf);
			base64_encode(sigItem->sig.sigID, kS4Key_KeyIDBytes, tempBuf, &tempLen);
			stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_HashAlgorithm, strlen(kS4KeyProp_HashAlgorithm)) ; CKYJAL
			hashAlgorString = hash_algor_table(sigItem->sig.hashAlgorithm);
			stat = yajl_gen_string(g, (uint8_t *)hashAlgorString, strlen(hashAlgorString)) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Signature, strlen(kS4KeyProp_Signature)) ; CKYJAL;
			
			tempLen = sizeof(tempBuf);
			base64_encode(sigItem->sig.signature, sigItem->sig.signatureLen, tempBuf, &tempLen);
			stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedBy, strlen(kS4KeyProp_SignedBy)) ; CKYJAL;
			tempLen = sizeof(tempBuf);
			base64_encode(sigItem->sig.issuerID, kS4Key_KeyIDBytes, tempBuf, &tempLen);
			stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedDate, strlen(kS4KeyProp_SignedDate)) ; CKYJAL;
			struct tm *nowtm;
			nowtm = gmtime(&sigItem->sig.signDate);
			tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
			stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
			
			if(sigItem->sig.expirationTime != LONG_MAX)
			{
				stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SigExpire, strlen(kS4KeyProp_SigExpire)) ; CKYJAL;
				stat = yajl_gen_integer(g, sigItem->sig.expirationTime) ; CKYJAL;
			}
			
			if(sigItem->sig.propNameList)
			{
				stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedProperties, strlen(kS4KeyProp_SignedProperties)) ; CKYJAL;
				stat = yajl_gen_array_open(g);
				for(char** itemName = sigItem->sig.propNameList ;*itemName; itemName++)
				{
					stat = yajl_gen_string(g, (uint8_t *)*itemName, strlen(*itemName)) ; CKYJAL;
					
				}
				stat = yajl_gen_array_close(g);
				
			}
			stat = yajl_gen_map_close(g); CKYJAL;
			
			sigItem = sigItem->next;
		}
		stat = yajl_gen_array_close(g); CKYJAL;
		
	}
	
done:
	return err;
	
}

static yajl_gen_status sGenSignablePropString(S4KeyContextRef ctx, yajl_gen g)

{
	S4Err               err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	size_t      propListEntries = 0;
	char**       propList = NULL;
	
	err = sGetSignablePropertyNames(ctx, &propList, &propListEntries); CKERR;
	
	if(propListEntries > 0)
	{
		stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignableProperties,
									  strlen(kS4KeyProp_SignableProperties)) ; CKYJAL;
		stat = yajl_gen_array_open(g);  CKYJAL;
		for(size_t i = 0  ; i < propListEntries; i++)
		{
			stat = yajl_gen_string(g, (uint8_t *)propList[i], strlen(propList[i])) ; CKYJAL;
			
		}
		stat = yajl_gen_array_close(g);  CKYJAL;
		
	}
	
done:
	
	for(int i = 0; propList[i]; i++)
		XFREE(propList[i]);
	
	XFREE(propList);
	
	return err;
}


static time_t parseRfc3339(const unsigned char *s, size_t stringLen)
{
	struct tm tm;
	time_t t;
	const unsigned char *p = s;
	
	if(stringLen < strlen("YYYY-MM-DDTHH:MM:SSZ"))
		return 0;
	
	memset(&tm, 0, sizeof tm);
	
	/* YYYY- */
	if (!isdigit(s[0]) || !isdigit(s[1]) ||  !isdigit(s[2]) || !isdigit(s[3]) || s[4] != '-')
		return 0;
	tm.tm_year = (((s[0] - '0') * 10 + s[1] - '0') * 10 +  s[2] - '0') * 10 + s[3] - '0' - 1900;
	s += 5;
	
	/* mm- */
	if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != '-')
		return 0;
	tm.tm_mon = (s[0] - '0') * 10 + s[1] - '0';
	if (tm.tm_mon < 1 || tm.tm_mon > 12)
		return 0;
	--tm.tm_mon;	/* 0-11 not 1-12 */
	s += 3;
	
	/* ddT */
	if (!isdigit(s[0]) || !isdigit(s[1]) || toupper(s[2]) != 'T')
		return 0;
	tm.tm_mday = (s[0] - '0') * 10 + s[1] - '0';
	s += 3;
	
	/* HH: */
	if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != ':')
		return 0;
	tm.tm_hour = (s[0] - '0') * 10 + s[1] - '0';
	s += 3;
	
	/* MM: */
	if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != ':')
		return 0;
	tm.tm_min = (s[0] - '0') * 10 + s[1] - '0';
	s += 3;
	
	/* SS */
	if (!isdigit(s[0]) || !isdigit(s[1]))
		return 0;
	tm.tm_sec = (s[0] - '0') * 10 + s[1] - '0';
	s += 2;
	
	if (*s == '.') {
		do
			++s;
		while (isdigit(*s));
	}
	
	if (toupper(s[0]) == 'Z' &&  ((s-p == stringLen -1) ||  s[1] == '\0'))
		tm.tm_gmtoff = 0;
	else if (s[0] == '+' || s[0] == '-')
	{
		char tzsign = *s++;
		
		/* HH: */
		if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != ':')
			return 0;
		tm.tm_gmtoff = ((s[0] - '0') * 10 + s[1] - '0') * 3600;
		s += 3;
		
		/* MM */
		if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != '\0')
			return 0;
		tm.tm_gmtoff += ((s[0] - '0') * 10 + s[1] - '0') * 60;
		
		if (tzsign == '-')
			tm.tm_gmtoff = -tm.tm_gmtoff;
	} else
		return 0;
	
	t = timegm(&tm);
	if (t < 0)
		return 0;
	return t;
	
	//  	return t - tm.tm_gmtoff;
	
}

static S4Err sParseHashAlgorithmString(const unsigned char * stringVal,  size_t stringLen, HASH_Algorithm *algorithmOut)
{
	
	S4Err            err = kS4Err_NoErr;
	HASH_Algorithm    hashAlgor = kHASH_Algorithm_Invalid;
	
	if(CMP2(stringVal, stringLen, K_HASHALGORITHM_SHA256, strlen(K_HASHALGORITHM_SHA256)))
	{
		hashAlgor = kHASH_Algorithm_SHA256;
	}
	else if(CMP2(stringVal, stringLen, K_HASHALGORITHM_SHA512, strlen(K_HASHALGORITHM_SHA512)))
	{
		hashAlgor = kHASH_Algorithm_SHA512;
	}
	else if(CMP2(stringVal, stringLen, K_HASHALGORITHM_SKEIN256, strlen(K_HASHALGORITHM_SKEIN256)))
	{
		hashAlgor = kHASH_Algorithm_SKEIN256;
	}
	else if(CMP2(stringVal, stringLen, K_HASHALGORITHM_SKEIN512, strlen(K_HASHALGORITHM_SKEIN512)))
	{
		hashAlgor = kHASH_Algorithm_SKEIN512;
	}
	
	*algorithmOut = hashAlgor;
	
	return err;
	
}


void sFreeKeySigContents(S4KeySig* sig)
{
	if(sig->propNameList)
	{
		char**   itemName = sig->propNameList;
		for(;*itemName; itemName++)  XFREE(*itemName);
		XFREE(sig->propNameList);
	}
	
	if (sig->signature)
		XFREE(sig->signature);
}

#ifdef __clang__
#pragma mark - property list parse.
#endif

typedef struct s4String    			s4String;
typedef struct s4Data    			s4Data;
typedef struct s4TokenNumArray 		s4TokenNumArray;
typedef struct JSONParseContext 	JSONParseContext;

struct s4String
{
	const uint8_t 	*str;
	size_t 			len;
};

struct s4Data
{
	void 			*data;
	size_t 			len;
};

struct s4TokenNumArray
{
	int 			*tokenNums;
	size_t 			count;
};

struct JSONParseContext
{
	uint8_t 	*jsonData;		// pointer to orignial data
	jsmntok_t 	*tokens;			// array of tokenized pointers
	int			tokenCount;			// max tokens
	int		 	dictCount;			// number of dictionaries found.
	int			dicts[];			// offset into tokens for each dictionary.
};


static void sFreeParseContext(JSONParseContext* pctx)
{
	if(pctx)
	{
		if(pctx->tokens)
			XFREE(pctx->tokens);
		
		XFREE(pctx);
	}
}


static S4Err sGetTokenValueType(JSONParseContext* pctx, int toknum, jsmntype_t *typeOut)
{
	S4Err           	err = kS4Err_NoErr;
	
	ValidateParam(pctx);
	ValidateParam(toknum < pctx->tokenCount);
	
	jsmntok_t token = pctx->tokens[toknum];
	
	if(typeOut)
		*typeOut = token.type;
	
done:
	return err;
	
}

static S4Err sGetTokenValueLong(JSONParseContext* pctx, int toknum, long *valueOut)
{
	S4Err           	err = kS4Err_NoErr;
	
	ValidateParam(pctx);
	ValidateParam(toknum < pctx->tokenCount);
	
	jsmntok_t token = pctx->tokens[toknum];
	
	ValidateParam(token.type == JSMN_PRIMITIVE);
	
	char* tokenString = (char*) pctx->jsonData + token.start;
	
	long value = 0;
	
	if((tokenString[0] >= '0' && tokenString[0] <= '9')
		|| tokenString[0] == '-' )
	{
		value =  (long) yajl_parse_integer((uint8_t*)tokenString, token.end - token.start);
	}
	else if(tokenString[0] == 't')
	{
		value = 1;					// boolean true
	}
	else if(tokenString[0] == 'f')
	{
		value = 0; 				// boolean false
	}
	else if(tokenString[0] == 'n')
	{
		value = 0; 	 // null
	}
	else
		RETERR(kS4Err_BadParams);
	
	if(valueOut)
		*valueOut = value;
	
done:
	return err;
	
}

static S4Err sGetTokenValueByte(JSONParseContext* pctx, int toknum, uint8_t *valueOut)
{
	
	S4Err	err = kS4Err_NoErr;
	long  	value	= 0;
	
	err = sGetTokenValueLong(pctx, toknum, &value); CKERR;
	
	if(value > UINT8_MAX)
		RETERR(kS4Err_BadParams);
	
	if(valueOut)
		*valueOut = (uint8_t) value;
	
done:
	return err;
	
}

static S4Err sGetTokenValueUint(JSONParseContext* pctx, int toknum, uint *valueOut)
{
	
	S4Err	err = kS4Err_NoErr;
	long  	value	= 0;
	
	err = sGetTokenValueLong(pctx, toknum, &value); CKERR;
	
	if(value > UINT_MAX)
		RETERR(kS4Err_BadParams);
	
	if(valueOut)
		*valueOut = (uint) value;
	
done:
	return err;
	
}







static S4Err sGetTokenValueStringPtr(JSONParseContext* pctx,
												 int toknum,
												 s4String *outStr)
{
	S4Err           	err = kS4Err_NoErr;
	
	ValidateParam(pctx);
	ValidateParam(toknum < pctx->tokenCount);
	
	jsmntok_t token = pctx->tokens[toknum];
	
	ValidateParam(token.type == JSMN_STRING && token.size == 0);
	
	if(outStr)
	{
		outStr->str = pctx->jsonData + token.start;
		outStr->len = token.end -token.start;
	}
	
done:
	return err;
	
}

static S4Err sFindTokenKeyInDictionaryToken(JSONParseContext* pctx,
														  int dictTokenNum,
														  char *const keyIn, int* tokNumOut)
{
	S4Err           	err = kS4Err_NoErr;
	int foundToken = -1;
	
	ValidateParam(pctx);
	jsmntok_t dictToken = pctx->tokens[dictTokenNum];
	int maxKeys = dictToken.size;
	size_t next = 0;
	int keysChecked = 0;
	
	// skip to the next token.
	for(int toknum  =dictTokenNum +1; toknum < pctx->tokenCount & keysChecked < maxKeys; )
	{
		jsmntok_t keyToken = pctx->tokens[toknum++];
		char* keyName = (char*) pctx->jsonData + keyToken.start;
		size_t keyLen = keyToken.end-keyToken.start;
		
		// skip to next token until we find a start that is after the current end
		if(keyToken.start < next)
			continue;
		
		// there needs to be a value
		if(toknum > pctx->tokenCount)
			RETERR(kS4Err_UnknownError);
		
		//  the next Token is the value
		jsmntok_t valueToken = pctx->tokens[toknum];
		
		// this must be a key
		if(keyToken.type != JSMN_STRING ||  keyToken.size == 0)
			RETERR(kS4Err_UnknownError);
		
		// this  must have a value
		switch (valueToken.type)
		{
			case JSMN_STRING:
			case JSMN_PRIMITIVE:
			case JSMN_ARRAY:
				next = valueToken.end;
				break;
				
			case JSMN_OBJECT:	// ignore these - *typically a dictionary
				next = valueToken.end;
				break;
				
			default:
				RETERR(kS4Err_CorruptData);
				break;
		}
		
		if(CMP2(keyName, keyLen, keyIn, strlen(keyIn)))
		{
			foundToken = toknum;			// found it
			break;
		}
		
		toknum++;
	}
	
	if(foundToken == -1)
		err = kS4Err_KeyNotFound;
	else
	{
		if(tokNumOut)
			*tokNumOut =  foundToken;
	}
	
done:
	
	return err;
}

static S4Err sGetTokenArrayTokenNums(JSONParseContext* pctx,
												 int dictTokenNum,
												 char *const keyIn,
												 s4TokenNumArray *outArray)

{	S4Err           	err = kS4Err_NoErr;
	
	ValidateParam(pctx);
	
	int count = 0;
	int *tokenNumArray = NULL;
	
	int keyNum;
	if(IsntS4Err(sFindTokenKeyInDictionaryToken(pctx, dictTokenNum, keyIn, &keyNum)))
	{
		jsmntok_t keyToken = pctx->tokens[keyNum];
		
		ValidateParam(keyToken.type == JSMN_ARRAY);
		count = keyToken.size;
		
		/* Allocate  space for token */
		tokenNumArray  = XMALLOC(sizeof(*tokenNumArray) * count); CKNULL(tokenNumArray);
		
		size_t next = 0;
		int tokensAdded = 0;
		
		// skip to the next token.
		for(int toknum = keyNum + 1;  toknum < pctx->tokenCount & tokensAdded < count; )
		{
			jsmntok_t valueToken = pctx->tokens[toknum];
			
			// skip to next token until we find a start that is after the current end
			if(valueToken.start < next)
			{
				toknum++;
				continue;
			}
			
			tokenNumArray[tokensAdded++] = toknum;
			next = valueToken.end;
			toknum++;
		}
	}
	
	if(outArray)
	{
		outArray->count = count;
		outArray->tokenNums = tokenNumArray;
	}
	else
		XFREE(tokenNumArray);
	
done:
	
	if(IsS4Err(err))
	{
		if(tokenNumArray)
			XFREE(tokenNumArray);
	}
	
	return err;
}


static S4Err sGetKeysInDictionaryToken(JSONParseContext* pctx,
													int dictTokenNum,
													s4TokenNumArray *outArray )
{
	S4Err  err = kS4Err_NoErr;
	
	jsmntok_t dictToken = pctx->tokens[dictTokenNum];
	int maxKeys = dictToken.size;
	size_t next = 0;
	
	int *tokenNumArray = NULL;
	size_t keyCount = 0;
	size_t keyAlloc = 10;
	
	/* Allocate some keys as a start */
	tokenNumArray  = XMALLOC(sizeof(*tokenNumArray) * keyAlloc); CKNULL(tokenNumArray);
	
	// skip to the next token.
	for(int toknum  =dictTokenNum +1 ; toknum < pctx->tokenCount & keyCount < maxKeys;)
	{
		int keyTokenNum = toknum;
		jsmntok_t keyToken = pctx->tokens[toknum++];
		//		const uint8_t* keyName =  pctx->jsonData + keyToken.start;
		//		size_t keyLen = keyToken.end-keyToken.start;
		
		// skip to next token until we find a start that is after the current end
		if(keyToken.start < next)
			continue;
		
		// there needs to be a value
		if(toknum > pctx->tokenCount)
			RETERR(kS4Err_UnknownError);
		
		//  the next Token is the value
		jsmntok_t valueToken = pctx->tokens[toknum];
		
		// this must be a key
		if(keyToken.type != JSMN_STRING ||  keyToken.size == 0)
			RETERR(kS4Err_UnknownError);
		
		next = valueToken.end;
		
		if(keyCount	>= keyAlloc)
		{
			int moreKeys = 10;
			tokenNumArray = XREALLOC(tokenNumArray, sizeof(*tokenNumArray) * (keyAlloc + moreKeys)); CKNULL(tokenNumArray);
			keyAlloc += moreKeys;
		}
		
		tokenNumArray[keyCount++] = keyTokenNum;
		toknum++;
	}
	
	if(outArray)
	{
		outArray->count = keyCount;
		outArray->tokenNums = tokenNumArray;
	}
	else
		XFREE(tokenNumArray);
	
done:
	
	if(IsS4Err(err))
	{
		if(tokenNumArray)
			XFREE(tokenNumArray);
	}
	
	return err;
}

static S4Err sGetFilteredPropertiesKeys(JSONParseContext* pctx,
													 int dictTokenNum,
													 char* filterKeys[],
													 s4TokenNumArray *outArray )
{
	S4Err           	err = kS4Err_NoErr;
	
	s4TokenNumArray allKeys = {NULL, 0};	// freeable
	s4TokenNumArray foundKeys = {NULL, 0};	// freeable
	
	err = sGetKeysInDictionaryToken(pctx,dictTokenNum, &allKeys); CKERR;
	
	for(int i = 0; i < allKeys.count; i++)
	{
		bool found = false;
		
		int keyNum = allKeys.tokenNums[i];
		jsmntok_t keyToken = pctx->tokens[keyNum];
		char* keyName = (char*) pctx->jsonData + keyToken.start;
		size_t keyLen = keyToken.end-keyToken.start;
		
		if(filterKeys)
		{
			for(int i = 0; filterKeys[i]; i++)
			{
				if(CMP2(keyName, keyLen, filterKeys[i], strlen(filterKeys[i])))
				{
					found = true;
					break;
				}
			}
		}
		
		if(!found)
		{
			// lazy allocate the found tokens array
			if(!foundKeys.tokenNums)
			{
				foundKeys.tokenNums  = XMALLOC(sizeof(*foundKeys.tokenNums) * allKeys.count); CKNULL(foundKeys.tokenNums);
			}
			
			// add the found items into the foundKeys array
			foundKeys.tokenNums[foundKeys.count++] = keyNum;
		}
	}
	
	if(outArray)
	{
		*outArray = foundKeys;
	}
	else
		if(foundKeys.tokenNums)
			XFREE(foundKeys.tokenNums);
	
done:
	
	if(IsS4Err(err))
	{
		if(allKeys.tokenNums)
			XFREE(allKeys.tokenNums);
	}
	
	return err;
}


static S4Err sGetTokenLong(JSONParseContext* pctx,
									int dictTokenNum,
									char *const keyIn,
									long *valueOut)
{
	S4Err  err = kS4Err_KeyNotFound;
	
	int tokenNum;
	long  value;
	
	jsmntype_t type = JSMN_UNDEFINED;
	
	if(IsntS4Err(sFindTokenKeyInDictionaryToken(pctx, dictTokenNum, keyIn, &tokenNum)))
	{
		err = sGetTokenValueType(pctx, tokenNum, &type); CKERR;
		ValidateParam(type == JSMN_PRIMITIVE);
		err = sGetTokenValueLong(pctx, tokenNum, &value);
		
		if(valueOut)
			*valueOut = value;
	}
	
done:
	return err;
}

static S4Err sGetTokenByte(JSONParseContext* pctx,
									int dictTokenNum,
									char *const keyIn,
									uint8_t *valueOut)
{
	S4Err  err = kS4Err_KeyNotFound;
	
	int tokenNum;
	uint8_t  value;
	
	jsmntype_t type = JSMN_UNDEFINED;
	
	if(IsntS4Err(sFindTokenKeyInDictionaryToken(pctx, dictTokenNum, keyIn, &tokenNum)))
	{
		err = sGetTokenValueType(pctx, tokenNum, &type); CKERR;
		ValidateParam(type == JSMN_PRIMITIVE);
		err = sGetTokenValueByte(pctx, tokenNum, &value);
		
		if(valueOut)
			*valueOut = value;
	}
	
done:
	return err;
}

static S4Err sGetTokenStringPtr(JSONParseContext* pctx,
										  int dictTokenNum,
										  char *const keyIn,
										  s4String *outStr)
{
	S4Err  err = kS4Err_KeyNotFound;
	
	int tokenNum;
	
	if(IsntS4Err(sFindTokenKeyInDictionaryToken(pctx, dictTokenNum, keyIn, &tokenNum)))
	{
		jsmntype_t type = JSMN_UNDEFINED;
		
		err = sGetTokenValueType(pctx, tokenNum, &type); CKERR;
		ValidateParam(type == JSMN_STRING);
		err = sGetTokenValueStringPtr(pctx, tokenNum, outStr);
	}
	
done:
	return err;
}


static S4Err sGetTokenBase64Data(JSONParseContext* pctx,
											int dictTokenNum,
											char *const keyIn,
											s4Data *outData)
{
	S4Err  err = kS4Err_KeyNotFound;
	
	int tokenNum;
	s4String	string =  {NULL, 0};	// non allocated strings, dont free
	
	uint8_t * data = NULL;
	size_t dataLen = 0;
	
	jsmntype_t type = JSMN_UNDEFINED;
	
	if(IsntS4Err(sFindTokenKeyInDictionaryToken(pctx, dictTokenNum, keyIn, &tokenNum)))
	{
		err = sGetTokenValueType(pctx, tokenNum, &type); CKERR;
		ValidateParam(type == JSMN_STRING);
		err = sGetTokenValueStringPtr(pctx, tokenNum, &string); CKERR;
		
		dataLen =  (3 * string.len) / 4 +2;	// alloc enough to decode
		data = XMALLOC(dataLen); CKNULL(data);
		
		ValidateParam(base64_decode(string.str, string.len, data, &dataLen) == CRYPT_OK);
		
		if(outData)
		{
			outData->len = dataLen;
			outData->data = data;
		}
		else
			XFREE(data);
	}
	
done:
	if(IsS4Err(err))
	{
		if(data)
			XFREE(data);
	}
	
	return err;
}



static S4Err sGetTokenTimeData(JSONParseContext* pctx,
										 int dictTokenNum,
										 char *const keyIn,
										 time_t *outTime)
{
	S4Err  err = kS4Err_KeyNotFound;
	
	int tokenNum;
	s4String	string =  {NULL, 0};	// non allocated strings, dont free
	
	jsmntype_t type = JSMN_UNDEFINED;
	
	if(IsntS4Err(sFindTokenKeyInDictionaryToken(pctx, dictTokenNum, keyIn, &tokenNum)))
	{
		err = sGetTokenValueType(pctx, tokenNum, &type); CKERR;
		ValidateParam(type == JSMN_STRING);
		err = sGetTokenValueStringPtr(pctx, tokenNum, &string);CKERR;
		time_t t = parseRfc3339(string.str, string.len);
		
		if(outTime)
			*outTime = t;
	}
	
done:
	
	return err;
}

static S4KeyProperty* sFindTokeninPropertyList(S4KeyPropertyRef propList,
															  JSONParseContext* pctx, int toknum )
{
	S4KeyProperty* prop = propList;
	
	
	jsmntok_t token = pctx->tokens[toknum];
	char* keyName = (char*) pctx->jsonData + token.start;
	size_t keyLen = token.end-token.start;
	
	while(prop)
	{
		if(CMP2(prop->prop, strlen((char *)(prop->prop)), keyName, keyLen))
		{
			break;
		}else
			prop = prop->next;
	}
	
	return prop;
	
}

static S4Err sJSONParseSignature(JSONParseContext* pctx,
											int sigTokenNum,
											S4KeySig *sigP )
{
	S4Err  err = kS4Err_NoErr;
	
	ValidateParam(sigP);
	
	long 		longVal = 0;
	s4String	string 		=  {NULL, 0};	// non allocated strings, dont free
	
	s4Data		sigID 		= {NULL, 0};
	s4Data		issuerID 	= {NULL, 0};
	s4Data		signature 	= {NULL, 0};
	s4TokenNumArray signedProps = {NULL, 0};	// freeable
	
	ZERO(sigP, sizeof(S4KeySig));
	
	// sigID
	err = sGetTokenBase64Data(pctx,sigTokenNum ,kS4KeyProp_SigID,  &sigID); CKERR;
	ASSERTERR(sigID.len == kS4Key_KeyIDBytes ,  kS4Err_BadParams);
	COPY(sigID.data, sigP->sigID, sigID.len);
	
	// issuerID
	err = sGetTokenBase64Data(pctx,sigTokenNum ,kS4KeyProp_SignedBy,  &issuerID); CKERR;
	ASSERTERR(issuerID.len == kS4Key_KeyIDBytes ,  kS4Err_BadParams);
	COPY(issuerID.data, sigP->issuerID, issuerID.len);
	
	// signDate
	err = sGetTokenTimeData(pctx,sigTokenNum ,kS4KeyProp_SignedDate,  &sigP->signDate); CKERR;
	
	if(IsntS4Err(sGetTokenLong(pctx, sigTokenNum, kS4KeyProp_SigExpire, &longVal)))
		sigP->expirationTime = (uint32_t)longVal;
	else
		sigP->expirationTime = LONG_MAX;
	
	// signature
	err = sGetTokenBase64Data(pctx,sigTokenNum ,kS4KeyProp_Signature,  &signature);CKERR;
	sigP->signature = signature.data;
	signature.data = NULL;  // do this to prevent dealloc later
	sigP->signatureLen = signature.len;
	
	// hash Algorthm
	err = sGetTokenStringPtr(pctx,sigTokenNum ,kS4KeyProp_HashAlgorithm, &string); CKERR;
	err = sParseHashAlgorithmString(string.str,  string.len, &sigP->hashAlgorithm);CKERR;
	
	if(IsntS4Err( sGetTokenArrayTokenNums(pctx,sigTokenNum, kS4KeyProp_SignedProperties, &signedProps))
		&& signedProps.count > 0)
	{
		char** props = XMALLOC(sizeof(char*)*  signedProps.count + 1); CKNULL(props);
		int i = 0;
		for(; i < signedProps.count; i++)
		{
			int signedPropsTokenNum = signedProps.tokenNums[i];
			err = sGetTokenValueStringPtr(pctx, signedPropsTokenNum, &string); CKERR;
			props[i] = strndup((char *)string.str, string.len);
		}
		props[i] = NULL;
		
		sigP->propNameList  = props;
	}
	
done:
	
	if(signedProps.tokenNums)
		XFREE(signedProps.tokenNums);
	
	if(sigID.data)
		XFREE(sigID.data);
	
	if(issuerID.data)
		XFREE(issuerID.data);
	
	return err;
	
}


static S4Err sJSONParseSignaturesToS4Key(JSONParseContext* pctx,
													  int dictTokenNum,
													  S4KeyContextRef  keyP )
{
	S4Err  err = kS4Err_NoErr;
	
	s4TokenNumArray signatures = {NULL, 0};	// freeable
	
	//kS4KeyProp_Signatures
	
	S4KeySigItem	*sigList 	= NULL;
	
	if(IsntS4Err( sGetTokenArrayTokenNums(pctx,dictTokenNum, kS4KeyProp_Signatures,&signatures )))
	{
		
		S4KeySigItem **prev = &sigList;
		
		for(int i = 0; i < signatures.count; i++)
		{
			int sigTokenNum = signatures.tokenNums[i];
			
			S4KeySigItem *sigItem  = XMALLOC(sizeof(S4KeySigItem)); CKNULL(sigItem);
			ZERO(sigItem, sizeof(S4KeySigItem));
			err = sJSONParseSignature(pctx,sigTokenNum, &sigItem->sig); CKERR;
			*prev = sigItem;
			prev = &sigItem->next;
		}
	}
	
	keyP->sigList = sigList;
	
done:
	
	if(signatures.tokenNums)
		XFREE(signatures.tokenNums);
	
	return err;
}

static  void sJSONVUnescapeValue( uint8_t* inData, size_t inLen, uint8_t **outData, size_t *outLen)
{
	size_t beg = 0;
	size_t end = 0;
	uint8_t* outP = XMALLOC(inLen);
	size_t length = 0;
	
	*outData = outP;
	
	while (end < inLen) {
		if (inData[end] == '\\')
		{
			COPY(inData + beg, outP,  end - beg );
			outP += (end - beg);
			length += (end - beg);
			
			const char * unescaped = "?";
			size_t unescapedLen = 0;
			
			char c = inData[++end];
			switch (c) {
				case 'r': unescaped = "\r"; break;
				case 'n': unescaped = "\n"; break;
				case '\\': unescaped = "\\"; break;
				case '/': unescaped = "/"; break;
				case '"': unescaped = "\""; break;
				case 'f': unescaped = "\f"; break;
				case 'b': unescaped = "\b"; break;
				case 't': unescaped = "\t"; break;
				default: ;
			}
			
			unescapedLen = strlen(unescaped);
			COPY(unescaped, outP, unescapedLen);
			outP += unescapedLen;
			length += unescapedLen;
			beg = ++end;
		}
		else {
			end++;
		}
	}
	if(end-beg > 0)
	{
		COPY(inData + beg, outP,  end - beg );
		outP += (end - beg);
		length += (end - beg);
		
	}
	
	*outLen = length;
}


static S4Err sJSONParsePropertiesToS4Key(JSONParseContext* pctx,
													  int dictTokenNum,
													  S4KeyContextRef  keyP )
{
	S4Err  err = kS4Err_NoErr;
	s4TokenNumArray signable = {NULL, 0};	// freeable
	s4TokenNumArray properties = {NULL, 0};	// freeable
	
	char* builtInKeys[] =
	{
		kS4KeyProp_Version,
		kS4KeyProp_Encoding,
		kS4KeyProp_PubKey,
		kS4KeyProp_PrivKey,
		kS4KeyProp_KeySuite,
		kS4KeyProp_Mac,
		kS4KeyProp_EncryptedKey,
		kS4KeyProp_KeyID,
		kS4KeyProp_EncodedObject,
		kS4KeyProp_EncryptedKey,
		kS4KeyProp_ESK,
		kS4KeyProp_IV,
		kS4KeyProp_p2kParams,
		kS4KeyProp_Rounds,
		kS4KeyProp_Salt,
		kS4KeyProp_SignableProperties,
		kS4KeyProp_Signatures,
		// signature properties
		kS4KeyProp_SigID,
		kS4KeyProp_SignedBy,
		kS4KeyProp_HashAlgorithm,
		kS4KeyProp_SignedDate,
		kS4KeyProp_SigExpire,
		kS4KeyProp_Signature,
		kS4KeyProp_SignedProperties,
		// Share Keys props
		kS4KeyProp_ShareIndex,
		kS4KeyProp_ShareThreshold,
		kS4KeyProp_ShareHash,
		kS4KeyProp_ShareOwner,
		kS4KeyProp_ShareID,
		kS4KeyProp_ShareTotal,
		NULL,
	};
	
	// get a list of Other (not built in) proprties;
	if(IsntS4Err( sGetFilteredPropertiesKeys(pctx, dictTokenNum, builtInKeys, &properties)))
	{
		for(int i = 0; i < properties.count; i++)
		{
			int toknum = properties.tokenNums[i];
			jsmntok_t keyToken = pctx->tokens[toknum];
			char* keyName = (char*) pctx->jsonData + keyToken.start;
			size_t keyLen = keyToken.end-keyToken.start;
			
			//  the next Token is the value
			jsmntok_t valueToken = pctx->tokens[toknum+1];
			
			s4Data value  =  {NULL, 0};	// non allocated strings, dont free
			value.data = pctx->jsonData + valueToken.start;
			value.len = valueToken.end -valueToken.start;
			
			S4KeyPropertyInfo* pInfo = sInfoForPropertyName(keyName,keyLen);
			// typecheck the property
			if(pInfo)
			{
				bool valid_type =
				(valueToken.type == JSMN_STRING
				 &&  ( pInfo->type == S4KeyPropertyType_UTF8String
						||  pInfo->type == S4KeyPropertyType_Binary
						||	pInfo->type == S4KeyPropertyType_Time))
				|| ((valueToken.type == JSMN_PRIMITIVE)
					 && (pInfo->type == S4KeyPropertyType_Numeric));
				
				if(!valid_type)
					RETERR(kS4Err_BadParams);
			}
			
			// is it already in the property list?
			S4KeyProperty* prop = sFindTokeninPropertyList(keyP->propList, pctx,toknum);
			if(!prop)
			{
				prop = XMALLOC(sizeof(S4KeyProperty));
				ZERO(prop,sizeof(S4KeyProperty));
				prop->prop = (uint8_t *)strndup(keyName, keyLen);
				prop->next = keyP->propList;
				keyP->propList = prop;
			}
			
			// if it's already there, we have a double?  call it an error/
			if(prop->value)
				RETERR(kS4Err_BadParams);
			
			if(valueToken.type == JSMN_PRIMITIVE)
			{
				uint  num = 0;
				err = sGetTokenValueUint(pctx, toknum+1, &num); CKERR;
				prop->value = XMALLOC(sizeof(num));
				prop->type = S4KeyPropertyType_Numeric;
				COPY(&num, prop->value, sizeof(num) );
				prop->valueLen = sizeof(num);
			}
			else if(valueToken.type == JSMN_STRING)
			{
				if(pInfo && pInfo->type == S4KeyPropertyType_Binary)
				{
					uint8_t * data = NULL;
					size_t dataLen = 0;
					
					dataLen =  (3 * value.len) / 4 +2;	// alloc enough to decode
					data = XMALLOC(dataLen); CKNULL(data);
					ValidateParam(base64_decode(value.data, value.len, data, &dataLen) == CRYPT_OK);
					prop->value = data;
					prop->valueLen = dataLen;
					prop->type = S4KeyPropertyType_Binary;
				}
				else if(pInfo &&  pInfo->type == S4KeyPropertyType_Time)
				{
					time_t t = parseRfc3339(value.data, value.len);
					prop->value = XMALLOC(sizeof(time_t));
					prop->type = S4KeyPropertyType_Time;
					COPY(&t, prop->value, sizeof(time_t) );
					prop->valueLen = sizeof(time_t);
				}
				else // treat it like a string
				{
					prop->type = S4KeyPropertyType_UTF8String;
					sJSONVUnescapeValue((uint8_t*)value.data, value.len, &prop->value, &prop->valueLen);
					//                 prop->value = XMALLOC(value.len);
					//					COPY(value.data, prop->value, value.len );
					//					prop->valueLen = value.len;
				}
			}
		}
		
		// update any signable properties with signable flag
		if(IsntS4Err( sGetTokenArrayTokenNums(pctx,dictTokenNum, kS4KeyProp_SignableProperties,&signable )))
			for(int i = 0; i < signable.count; i++)
			{
				int toknum = signable.tokenNums[i];
				S4KeyProperty* prop = sFindTokeninPropertyList(keyP->propList, pctx,toknum);
				if(prop)
				{
					prop->extended |= S4KeyPropertyExtended_Signable;
				}
			}
	}
	
done:
	if(signable.tokenNums)
		XFREE(signable.tokenNums);
	
	if(properties.tokenNums)
		XFREE(properties.tokenNums);
	
	
	return err;
	
}


static S4Err sJSONParseDictionaryToS4Key(JSONParseContext* pctx,
													  int dictNum,
													  S4KeyContextRef   *ctxOut)
{
	S4Err  err = kS4Err_KeyNotFound;
	
	s4String	string =  {NULL, 0};	// non allocated strings, dont free
	long 		longVal = 0;
	
	// these are typically allocated  must free
	s4Data		encrypted 	= {NULL, 0};
	s4Data		mac 		= {NULL, 0};
	s4Data		shareID 	= {NULL, 0};
	s4Data		keyID 		= {NULL, 0};
	s4Data		iv 			= {NULL, 0};
	s4Data		esk 		= {NULL, 0};
	s4Data		pubKey 		= {NULL, 0};
	s4Data		privKey 	= {NULL, 0};
	s4Data		salt 		= {NULL, 0};
	
	s4TokenNumArray array = {NULL, 0};	// freeable
	
	S4KeyContextRef		keyP = kInvalidS4KeyContextRef;
	S4KeyType   		keyType = kS4KeyType_Invalid;
	Cipher_Algorithm	cipherAlgorithm = kCipher_Algorithm_Invalid;
	bool 				isPrivateKey = false;
	int 				dictTokenNum  = pctx->dicts[dictNum]; // the JSMN_OBJECT for this dictionary
	
	// check the packet version
	{
		err = sGetTokenLong(pctx, dictTokenNum, kS4KeyProp_Version, &longVal); CKERR;
		ASSERTERR(longVal == kS4KeyProtocolVersion ,  kS4Err_BadParams);
	}
	
	// determine the type of JSON packet we got
	
	// create a key context
	keyP = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyP);
	ZERO(keyP, sizeof(S4KeyContext));
	keyP->magic = kS4KeyContextMagic;
	
	
	// do we have an encoding?
	if(IsntS4Err( sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_Encoding, &string)))
	{
		err = sParseEncodingString(string.str, string.len,  keyP); CKERR;
	}
	// maybe it's a public key .. they dont have encodings.
	
	if(IsntS4Err( sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_PubKey, &string)))
	{
		keyP->type = kS4KeyType_PublicKey;
	}
	else if(IsntS4Err( sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_PrivKey, &string)))
	{
		keyP->type = kS4KeyType_SymmetricEncrypted;
		isPrivateKey = true;
	}
	
	// get an keysuite if it's available.
	if(IsntS4Err( sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_KeySuite, &string)))
	{
		err = sParseKeySuiteString(string.str, string.len, &keyType, &cipherAlgorithm); CKERR;
		
		if(keyType == kS4KeyType_Share)
			keyP->type	= kS4KeyType_Share;
	}
	
	// create a key context
	
	switch (keyP->type)
	{
			// symmetric encypted key
		case kS4KeyType_SymmetricEncrypted:
		{
			keyP->symKeyEncoded.keyAlgorithmType = keyType;
			keyP->symKeyEncoded.cipherAlgor = cipherAlgorithm;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_Mac,  &mac);CKERR;
			ASSERTERR(mac.len == kS4KeyESK_HashBytes ,  kS4Err_BadParams);
			COPY(mac.data, keyP->symKeyEncoded.keyHash, mac.len);
			
			if(isPrivateKey)
			{
				err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_PrivKey,  &privKey); CKERR;
				if(privKey.data && privKey.len != 0)
				{
					ASSERTERR(privKey.len <= kS4KeySymmetric_Encrypted_BufferMAX ,  kS4Err_BadParams);
					COPY(privKey.data, keyP->symKeyEncoded.encrypted, privKey.len);
					keyP->symKeyEncoded.encryptedLen = privKey.len;
				}
				// keyID is required
				err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_KeyID,  &keyID); CKERR;
				ASSERTERR(keyID.len == kS4Key_KeyIDBytes ,  kS4Err_BadParams);
				COPY(keyID.data, keyP->symKeyEncoded.keyID, keyID.len);
			}
			else
			{
				err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_EncryptedKey,  &encrypted);CKERR;
				ASSERTERR(encrypted.len <= kS4KeySymmetric_Encrypted_BufferMAX ,  kS4Err_BadParams);
				COPY(encrypted.data, keyP->symKeyEncoded.encrypted, encrypted.len);
				keyP->symKeyEncoded.encryptedLen = encrypted.len;
				
				// KEYID is optional for other kinds.
				if(IsntS4Err( sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_KeyID,  &keyID)))
				{
					ASSERTERR(keyID.len == kS4Key_KeyIDBytes ,  kS4Err_BadParams);
					COPY(keyID.data, keyP->symKeyEncoded.keyID, keyID.len);
				}
			}
		}
			break;
			
		case kS4KeyType_Share_ESK:
		{
			Cipher_Algorithm	objectAlgorithm = kCipher_Algorithm_Invalid;
			keyP->esk.keyAlgorithmType = kS4KeyType_Share;
			
			// recapture the encoding string
			err = sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_KeySuite, &string); CKERR;
			err = sParseKeySuiteString(string.str, string.len, NULL, &objectAlgorithm); CKERR;
			keyP->esk.objectAlgor = objectAlgorithm;
			
			size_t  	cipherSizeInBits = 0;
			size_t   	cipherSizeInBytes = 0;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_EncryptedKey,  &encrypted);CKERR;
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_Mac,  &mac);CKERR;
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_ShareOwner,  &shareID);CKERR;
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_IV,  &iv);CKERR;
			
			// do some parameter checking
			ASSERTERR(mac.len == kS4KeyESK_HashBytes ,  kS4Err_BadParams);
			ASSERTERR(shareID.len == kS4ShareInfo_HashBytes ,  kS4Err_BadParams);
			
			// check the encypted object
			err = Cipher_GetKeySize(objectAlgorithm, &cipherSizeInBits); CKERR;
			cipherSizeInBytes = cipherSizeInBits / 8;
			// AES192 is padded
			if(objectAlgorithm == kCipher_Algorithm_AES192)
				cipherSizeInBytes = 32;
			ASSERTERR(encrypted.len == cipherSizeInBytes ,  kS4Err_BadParams);
			
			// check the ESK IV algotithm
			err = Cipher_GetKeySize(keyP->esk.cipherAlgor, &cipherSizeInBits); CKERR;
			cipherSizeInBytes = cipherSizeInBits / 8;
			ASSERTERR(iv.len == cipherSizeInBytes ,  kS4Err_BadParams);
			
			COPY(mac.data, keyP->esk.keyHash, mac.len);
			COPY(shareID.data, keyP->esk.shareOwner, mac.len);
			COPY(iv.data, keyP->esk.iv, iv.len);
			keyP->esk.ivLen = iv.len;
			
			keyP->esk.encrypted = encrypted.data;  encrypted.data = NULL;
			keyP->esk.encryptedLen = encrypted.len;
			
			err = sGetTokenByte(pctx, dictTokenNum, kS4KeyProp_ShareThreshold, &keyP->esk.threshold); CKERR;
			err = sGetTokenByte(pctx, dictTokenNum, kS4KeyProp_ShareTotal, &keyP->esk.totalShares); CKERR;
			
			// copy all the shareIDs
			if(IsntS4Err( sGetTokenArrayTokenNums(pctx,dictTokenNum, kS4KeyProp_ShareIDs,&array )))
			{
				uint8_t** shareIDs = XMALLOC(sizeof(char*) *  (array.count + 1)); CKNULL(shareIDs);
				int i = 0;
				for(; i < array.count; i++)
				{
					int toknum = array.tokenNums[i];
					err = sGetTokenValueStringPtr(pctx, toknum, &string); CKERR;
					size_t dataLen =  (3 * string.len) / 4 +2;	// alloc enough to decode
					void* data = XMALLOC(dataLen); CKNULL(data);
					ValidateParam(base64_decode(string.str, string.len, data, &dataLen) == CRYPT_OK);
					ASSERTERR(dataLen == kS4ShareInfo_HashBytes ,  kS4Err_BadParams);
					shareIDs[i]= data;
				}
				shareIDs[i] = NULL;
				keyP->esk.shareIDList = shareIDs;
			}
		}
			break;
			
		case kS4KeyType_P2K_ESK:
		{
			size_t  	cipherSizeInBits = 0;
			size_t   	cipherSizeInBytes = 0;
			
			// do some parameter checking
			err = Cipher_GetKeySize(cipherAlgorithm, &cipherSizeInBits); CKERR;
			cipherSizeInBytes = cipherSizeInBits / 8;
			
			keyP->esk.keyAlgorithmType = kS4KeyType_Symmetric;
			keyP->esk.cipherAlgor = cipherAlgorithm;
			
			if(IsntS4Err( sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_EncodedObject, &string)))
			{
				err = sParseKeySuiteString(string.str, string.len, &keyType, &cipherAlgorithm); CKERR;
				keyP->esk.objectAlgor = cipherAlgorithm;
			}
			else
				keyP->esk.objectAlgor =  kCipher_Algorithm_Unknown;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_Mac,  &mac);CKERR;
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_ESK,  &esk);CKERR;
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_IV,  &iv);CKERR;
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_EncryptedKey,  &encrypted);CKERR;
			
			ASSERTERR(iv.len == cipherSizeInBytes ,  kS4Err_BadParams);
			ASSERTERR(esk.len == cipherSizeInBytes ,  kS4Err_BadParams);
			ASSERTERR(mac.len == kS4KeyESK_HashBytes ,  kS4Err_BadParams);
			
			COPY(mac.data, keyP->esk.keyHash, mac.len);
			
			COPY(iv.data, keyP->esk.iv, iv.len);
			keyP->esk.ivLen = iv.len;
			
			COPY(esk.data, keyP->esk.esk, esk.len);
			keyP->esk.eskLen = esk.len;
			
			keyP->esk.encrypted = encrypted.data;
			encrypted.data = NULL;  // do this to prevent dealloc later
			keyP->esk.encryptedLen = encrypted.len;
			
			// we need the p2kParms as a null terminated string
			err = sGetTokenStringPtr(pctx,dictTokenNum,kS4KeyProp_p2kParams, &string);CKERR;
			keyP->esk.p2kParams =strndup((char*) string.str, string.len);
		}
			break;
			
		case kS4KeyType_PublicEncrypted:
		{
			keyP->publicKeyEncoded.keyAlgorithmType = keyType;
			keyP->publicKeyEncoded.cipherAlgor = cipherAlgorithm;
			
			err = sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_Encoding, &string); CKERR;
			err = sParseKeySuiteString(string.str, string.len, &keyType, &cipherAlgorithm); CKERR;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_Mac,  &mac);CKERR;
			ASSERTERR(mac.len == kS4KeyESK_HashBytes ,  kS4Err_BadParams);
			COPY(mac.data, keyP->publicKeyEncoded.keyHash, mac.len);
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_EncryptedKey,  &encrypted);CKERR;
			ASSERTERR(encrypted.len <= kS4KeyPublic_Encrypted_BufferMAX ,  kS4Err_BadParams);
			COPY(encrypted.data, keyP->publicKeyEncoded.encrypted, encrypted.len);
			keyP->publicKeyEncoded.encryptedLen = encrypted.len;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_KeyID,  &keyID); CKERR;
			ASSERTERR(keyID.len == kS4Key_KeyIDBytes ,  kS4Err_BadParams);
			COPY(keyID.data, keyP->publicKeyEncoded.keyID, keyID.len);
		}
			break;
			
		case kS4KeyType_PublicKey:
		{
			keyP->pub.eccAlgor = (ECC_Algorithm) cipherAlgorithm;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_KeyID,  &keyID); CKERR;
			ASSERTERR(keyID.len == kS4Key_KeyIDBytes ,  kS4Err_BadParams);
			COPY(keyID.data, keyP->pub.keyID, keyID.len);
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_PubKey,  &pubKey); CKERR;
			ASSERTERR(pubKey.len <= sizeof(keyP->pub.pubKey) ,  kS4Err_BadParams);
			COPY(pubKey.data, keyP->pub.pubKey, pubKey.len);
			keyP->pub.pubKeyLen = pubKey.len;
			keyP->pub.isPrivate = 0;
			
			// create an decoded copy of the public key
			err = ECC_Import_ANSI_X963(keyP->pub.pubKey, keyP->pub.pubKeyLen,
												&keyP->pub.ecc);CKERR;
			
			// verify that the keyID matches the actual key
			uint8_t	keyID[kS4Key_KeyIDBytes];
			size_t  keyIDLen = 0;
			err = ECC_PubKeyHash(keyP->pub.ecc, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
			
			ASSERTERR(CMP(keyID, keyP->pub.keyID, kS4Key_KeyIDBytes), kS4Err_BadIntegrity);
		}
			break;
			
		case kS4KeyType_PBKDF2:
		{
			keyP->pbkdf2.keyAlgorithmType = keyType;
			keyP->pbkdf2.cipherAlgor = cipherAlgorithm;
			
			err = sGetTokenLong(pctx, dictTokenNum, kS4KeyProp_Rounds, &longVal); CKERR;
			keyP->pbkdf2.rounds = (uint32_t)longVal;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_Salt,  &salt); CKERR;
			ASSERTERR(salt.len == kS4KeyPBKDF2_SaltBytes ,  kS4Err_BadParams);
			COPY(salt.data, keyP->pbkdf2.salt, salt.len);
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_Mac,  &mac);CKERR;
			ASSERTERR(mac.len == kS4KeyESK_HashBytes ,  kS4Err_BadParams);
			COPY(mac.data, keyP->pbkdf2.keyHash, mac.len);
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_EncryptedKey,  &encrypted);CKERR;
			ASSERTERR(encrypted.len <= kS4KeyPublic_Encrypted_BufferMAX ,  kS4Err_BadParams);
			COPY(encrypted.data, keyP->pbkdf2.encrypted, encrypted.len);
			keyP->pbkdf2.encryptedLen = encrypted.len;
			
		}
			break;
			
		case kS4KeyType_Share:
		{
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_ShareID,  &shareID);CKERR;
			ASSERTERR(shareID.len == kS4ShareInfo_HashBytes ,  kS4Err_BadParams);
			COPY(shareID.data, keyP->share.shareID, shareID.len);
			XFREE(shareID.data); shareID.data = NULL;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_ShareOwner,  &shareID);CKERR;
			ASSERTERR(shareID.len == kS4ShareInfo_HashBytes ,  kS4Err_BadParams);
			COPY(shareID.data, keyP->share.shareOwner, shareID.len);
			XFREE(shareID.data); shareID.data = NULL;
			
			err = sGetTokenByte(pctx, dictTokenNum, kS4KeyProp_ShareIndex, &keyP->share.xCoordinate); CKERR;
			err = sGetTokenByte(pctx, dictTokenNum, kS4KeyProp_ShareThreshold, &keyP->share.threshold); CKERR;
			
			err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_EncryptedKey,  &encrypted);CKERR;
			ASSERTERR(encrypted.len <= sizeof(keyP->share.shareSecret) ,  kS4Err_BadParams);
			COPY(encrypted.data, keyP->share.shareSecret, encrypted.len);
			keyP->share.shareSecretLen = encrypted.len;
		}
			break;
			
		case kS4KeyType_Signature:
		{
			err = sJSONParseSignature(pctx,dictTokenNum, &keyP->sig); CKERR;
		}
			break;
			
			
		case kS4KeyType_Symmetric:
		case kS4KeyType_Tweekable:
			//you will never import these
			RETERR(kS4Err_LazyProgrammer);
			
			break;
			
		default:
			RETERR(kS4Err_BadParams);
			
			break;
	}
	
	// parse any additional properties
	err = sJSONParsePropertiesToS4Key(pctx,dictTokenNum, keyP); CKERR;
	
	// parse any key signatures
	err = sJSONParseSignaturesToS4Key(pctx,dictTokenNum, keyP); CKERR;
	
	if(ctxOut)
		*ctxOut = keyP;
	
done:
	
	if(IsS4Err(err))
	{
		if(S4KeyContextRefIsValid(keyP))
			S4Key_Free(keyP);
	}
	
	if(array.tokenNums)
		XFREE(array.tokenNums);
	
	if(mac.data)
		XFREE(mac.data);
	
	if(iv.data)
		XFREE(iv.data);
	
	if(shareID.data)
		XFREE(shareID.data);
	
	if(esk.data)
		XFREE(esk.data);
	
	if(encrypted.data)
		XFREE(encrypted.data);
	
	if(keyID.data)
		XFREE(keyID.data);
	
	if(pubKey.data)
		XFREE(pubKey.data);
	
	if(privKey.data)
		XFREE(pubKey.data);
	
	if(salt.data)
		XFREE(salt.data);
	
	return err;
}

//
//static int dump(const char *js, jsmntok_t *t, size_t count, int indent) {
//
//	if (count == 0) {
//		return 0;
//	}
//
//	int i, j, k;
//
//	printf("(%d, %d) ",  t->start, t->end );
//
//	if (t->type == JSMN_PRIMITIVE) {
//		printf("%.*s", t->end - t->start, js+t->start);
//		return 1;
//	} else if (t->type == JSMN_STRING) {
//		printf("'%.*s'", t->end - t->start, js+t->start);
//		return 1;
//	} else if (t->type == JSMN_OBJECT) {
//		printf("\n");
//		j = 0;
//		for (i = 0; i < t->size; i++) {
//			for (k = 0; k < indent; k++) printf("  ");
//			j += dump(js, t+1+j, count-j, indent+1);
//			printf(": ");
//			j += dump(js, t+1+j, count-j, indent+1);
//			printf("\n");
//		}
//		return j+1;
//	} else if (t->type == JSMN_ARRAY) {
//		j = 0;
//		printf("\n");
//		for (i = 0; i < t->size; i++) {
//			for (k = 0; k < indent-1; k++) printf("  ");
//			printf("   - ");
//			j += dump(js, t+1+j, count-j, indent+1);
//			printf("\n");
//		}
//		return j+1;
//	}
//	return 0;
//}
//



static S4Err sParseJSON(uint8_t *inData, size_t inLen,
								JSONParseContext **parseCtxOut)
{
	S4Err           	err = kS4Err_NoErr;
	JSONParseContext	*pctx = NULL;
	jsmn_parser 		pHand = {0};
	jsmntok_t 			*tokens = NULL;
	int		 			dictCount = 0;		// number of dictionaries found.
	
	/* Prepare parser */
	jsmn_init(&pHand);
	
	/* Allocate some tokens as a start */
	size_t allocTokens = 10;
	tokens  = XMALLOC(sizeof(jsmntok_t) * allocTokens); CKNULL(tokens);
	ZERO(tokens , sizeof(jsmntok_t) ); // Zero the first token
	
	// loop until we process all tokens
	for(;;)
	{
		int status = 0;
		status = jsmn_parse(&pHand, (const char *) inData, inLen,
								  tokens, (unsigned int) allocTokens);
		
		if (status == JSMN_ERROR_NOMEM)	// we need more token memory.
		{
			allocTokens = allocTokens * 2;	// double the tokens
			tokens = XREALLOC(tokens, sizeof(jsmntok_t) * allocTokens); CKNULL(tokens);
			continue;
		}
		else if(status < 0)
		{
			RETERR(kS4Err_CorruptData);
		}
		else // tokens found
		{
			break;
		}
	}
	
	// check the first Token.
	switch (tokens[0].type)
	{
		case JSMN_OBJECT:	// found one dict
			dictCount = 1;
			break;
			
		case JSMN_ARRAY:	// found multiple dictionaries
			dictCount = tokens[0].size;
			break;
			
		default:
			RETERR(kS4Err_CorruptData);
			break;
	}
	
	// allocate a JSONParseContext
	pctx = XMALLOC(sizeof(JSONParseContext) + (sizeof(int) * dictCount));
	CKNULL(pctx);
	
	pctx->jsonData 	= inData;
	pctx->tokens 	= tokens;
	pctx->dictCount = dictCount;
	pctx->tokenCount = pHand.toknext;
	
	if(dictCount == 0)
	{
		// no error but do nothing
	}
	else if(dictCount == 1)
	{
		pctx->dicts[0] = 0;
	}
	else // find the offset of each dictionary
	{
		size_t next = 0;
		int dictNum = 0;
		
		for(int toknum = 1; toknum < pHand.toknext && dictNum < dictCount;  )
		{
			jsmntok_t token = tokens[toknum];
			
			// skip to next token until we find a start that is after the current end
			if(token.start < next)
			{
				toknum++;
				continue;
			}
			
			if(token.type == JSMN_OBJECT)
			{
				pctx->dicts[dictNum++] = toknum;
				next = token.end;
			}
			else
			{
				RETERR(kS4Err_CorruptData);
			}
			
			toknum++;
		}
	}
	
	//	dump(inData, tokens, pHand.toknext, 0 );
	
	
	if(parseCtxOut)
		*parseCtxOut = pctx;
	
done:
	if(IsS4Err(err))
	{
		if(tokens)
			XFREE(tokens);
		if(pctx)
			XFREE(pctx);
	}
	
	return err;
}


#ifdef __clang__
#pragma mark - property Lists.
#endif


static S4KeyProperty* sFindPropertyInList(S4KeyPropertyRef propList, const char *propName )
{
	S4KeyProperty* prop = propList;
	while(prop)
	{
		if(CMP2(prop->prop, strlen((char *)(prop->prop)), propName, strlen(propName)))
		{
			break;
		}else
			prop = prop->next;
	}
	
	
	return prop;
}

static void sInsertPropertyInList(S4KeyPropertyRef *propList, const char *propName,
											 S4KeyPropertyType propType,
											 S4KeyPropertyExtendedType  extendedPropType,
											 void *data,  size_t  datSize)
{
	S4KeyProperty* prop = sFindPropertyInList(*propList,propName);
	if(!prop)
	{
		prop = XMALLOC(sizeof(S4KeyProperty));
		ZERO(prop,sizeof(S4KeyProperty));
		prop->prop = (uint8_t *)strndup(propName, strlen(propName));
		prop->next = *propList;
		*propList = prop;
	}
	
	if(prop->value) XFREE(prop->value);
	prop->value = XMALLOC(datSize);
	prop->type = propType;
	prop->extended = extendedPropType;
	COPY(data, prop->value, datSize );
	prop->valueLen = datSize;
};

static void sClonePropertiesLists(S4KeyPropertyRef srcList, S4KeyPropertyRef *destList )
{
	S4KeyProperty* sprop = NULL;
	S4KeyProperty** lastProp = destList;
	
	for(sprop = srcList; sprop; sprop = sprop->next)
	{
		S4KeyProperty* newProp =  XMALLOC(sizeof(S4KeyProperty));
		ZERO(newProp,sizeof(S4KeyProperty));
		newProp->prop = (uint8_t *)strndup((char *)(sprop->prop), strlen((char *)(sprop->prop)));
		newProp->type = sprop->type;
		newProp->extended = sprop->extended;
		newProp->value = XMALLOC(sprop->valueLen);
		COPY(sprop->value, newProp->value, sprop->valueLen );
		newProp->valueLen = sprop->valueLen;
		*lastProp = newProp;
		lastProp = &newProp->next;
	}
	*lastProp = NULL;
	
}

static void sFreePropertyList(S4KeyPropertyRef propList)
{
	if(propList)
	{
		S4KeyProperty *prop = propList;
		
		while(prop)
		{
			S4KeyProperty *nextProp = prop->next;
			
			if(prop->prop)
				XFREE(prop->prop);
			
			if(prop->value)
			{
				if(prop->type == S4KeyPropertyType_Array)
				{
					S4KeyProperty * p = (S4KeyProperty*) prop->value;
					while(p)
					{
						S4KeyProperty * nextP = p->next;
						if(p->value)
							XFREE(p->value);
						XFREE(p);
						p = nextP;
					}
				}
				else
				{
					XFREE(prop->value);
				}
			}
			
			if(prop != propList)
				XFREE(prop);
			prop = nextProp;
		}
		
	}
}


static S4Err sDeleteProperty(S4KeyContext *ctx,  const char *propName, bool *needsSigning )
{
	S4Err   err = kS4Err_NoErr;
	
	S4KeyProperty* prop = sFindPropertyInList(ctx->propList,propName);
	
	if(!prop)
		RETERR(kS4Err_PropertyNotFound);
	
	if(needsSigning)
		*needsSigning = (prop->extended && S4KeyPropertyExtended_Signable) == S4KeyPropertyExtended_Signable;
	
	if(ctx->propList == prop) // front of list
	{
		ctx->propList = prop->next;
	}
	else
	{
		for(S4KeyProperty* p = ctx->propList; p ; p = p->next)
			if(p->next == prop)
			{
				p->next = prop->next;
				break;
			}
	}
	
	XFREE(prop->prop);
	XFREE(prop->value);
	XFREE(prop);
	
done:
	return err;
}


static int cmpPropNames(const void *p1, const void *p2){
	return strcasecmp(* (char * const *) p1, * (char * const *) p2);
}


#ifdef __clang__
#pragma mark - Key property management.
#endif

static S4Err sGetSignablePropertyNames(S4KeyContext *ctx,  char ***namesOut, size_t* countOut )
{
	S4Err               err = kS4Err_NoErr;
	
	const size_t alloc_quantum = 8;
	
	S4KeyProperty* prop = ctx->propList;
	size_t count = 0;
	size_t allocCount = alloc_quantum;
	char** names =  NULL;
	
	validateS4KeyContext(ctx);
	
	names = XMALLOC( sizeof(char*) * (allocCount + 1));
	names[0] = NULL;
	
	if(prop)
	{
		switch (ctx->type)
		{
			case kS4KeyType_Share:
				names[count++] = strdup(kS4KeyProp_KeySuite);
				names[count++] = strdup(kS4KeyProp_ShareOwner);
				names[count++] = strdup(kS4KeyProp_ShareID);
				names[count++] = strdup(kS4KeyProp_ShareIndex);
				names[count++] = strdup(kS4KeyProp_ShareThreshold);
				names[count++] = strdup(kS4KeyProp_EncryptedKey);
				break;
				
			case kS4KeyType_PublicKey:
				names[count++] = strdup(kS4KeyProp_KeySuite);
				names[count++] = strdup(kS4KeyProp_KeyID);
				names[count++] = strdup(kS4KeyProp_PubKey);
				break;
				
			case kS4KeyType_Signature:
				names[count++] = strdup(kS4KeyProp_SigID);
				names[count++] = strdup(kS4KeyProp_SignedBy);
				names[count++] = strdup(kS4KeyProp_Signature);
				names[count++] = strdup(kS4KeyProp_SignedDate);
				names[count++] = strdup(kS4KeyProp_SigExpire);
				break;
				
				// add in more names here for other types of keys.
			default:
				names[count++] = strdup(kS4KeyProp_KeySuite);
				names[count++] = strdup(kS4KeyProp_KeyID);
				names[count++] = strdup(kS4KeyProp_p2kParams);
				names[count++] = strdup(kS4KeyProp_Mac);
				names[count++] = strdup(kS4KeyProp_EncryptedKey);
				
				break;
		}
	}
	
	
	//
	//        // add in built in properites
	//        names[count++] = strdup(kS4KeyProp_KeySuite);
	//        names[count++] = strdup(kS4KeyProp_KeyID);
	//     }
	
	//    switch (ctx->type)
	//    {
	//        case kS4KeyType_PublicKey:
	//            names[count++] = strdup(kS4KeyProp_PubKey);
	//            break;
	//
	//        default:
	//    // add in more names here for other types of keys.
	//            break;
	//    }
	
	while(prop)
	{
		if(count > allocCount)
		{
			allocCount += alloc_quantum;
			names =  XREALLOC(names, allocCount * sizeof(char*) );
		}
		
		names[count] = strdup((char*) prop->prop );
		count++;
		prop = prop->next;
	}
	
	// put a null termination on list
	if(count > allocCount)
	{
		allocCount += alloc_quantum;
		names =  XREALLOC(names, allocCount * sizeof(char*) );
	}
	names[count] = NULL;
	
	if(names)
	{
		qsort(names, count, sizeof(char *), cmpPropNames);
	}
	
	if(namesOut)
	{
		*namesOut = names;
	}
	else
	{
		for(int i = 0; i < count; i++)
			XFREE(names[i]);
		
		XFREE(names);
	}
	
	if(countOut) *countOut = count;
	
done:
	return err;
	
}


EXPORT_FUNCTION S4Err S4Key_SetProperty( S4KeyContextRef ctx,
													 const char *propName, S4KeyPropertyType propType,
													 void *data,  size_t  datSize)
{
	return S4Key_SetPropertyExtended(ctx, propName,propType, S4KeyPropertyExtendedType_None, data,datSize);
}

EXPORT_FUNCTION S4Err S4Key_SetPropertyExtended ( S4KeyContextRef ctx,
																 const char *propName, S4KeyPropertyType propType,
																 S4KeyPropertyExtendedType  extendedPropType,
																 void *data,  size_t  datSize)
{
	
	S4Err               err = kS4Err_NoErr;
	S4KeyPropertyInfo  *propInfo = NULL;
	bool found = false;
	
	validateS4KeyContext(ctx);
	
	for(propInfo = sPropertyTable; propInfo->name; propInfo++)
	{
		if(CMP2(propName, strlen(propName), propInfo->name, strlen(propInfo->name)))
		{
			if(propInfo->readOnly)
				RETERR(kS4Err_BadParams);
			
			if(propType != propInfo->type)
				RETERR(kS4Err_BadParams);
			
			if(propInfo->signable)
				extendedPropType |= S4KeyPropertyExtended_Signable;
			
			found = true;
			break;
		}
	}
	
	// if you get this far, you can insert a property
	sInsertPropertyInList(&ctx->propList, propName, propType,extendedPropType, data, datSize);CKERR;
	
	if((ctx->type == kS4KeyType_PublicKey)
		&& ECC_isPrivate(ctx->pub.ecc)
		&& (extendedPropType && S4KeyPropertyExtended_Signable) == S4KeyPropertyExtended_Signable)
	{
		//  re-sign key  when new property is added
		err = S4Key_SignKey(ctx,ctx, LONG_MAX); CKERR;
	}
	
done:
	return err;
	
}



static S4Err s4Key_GetPropertyInternal( S4KeyContextRef ctx,
													const char *propName,
													S4KeyPropertyType *outPropType,
													S4KeyPropertyExtendedType *outExtendedProp,
													void *outData, size_t bufSize, size_t *datSize, bool doAlloc,
													uint8_t** allocBuffer)
{
	S4Err               err = kS4Err_NoErr;
	S4KeyPropertyInfo   *propInfo   = NULL;
	S4KeyProperty*      otherProp   = NULL;
	S4KeyPropertyType   propType    = S4KeyPropertyType_Invalid;
	S4KeyPropertyExtendedType extendedProp =  S4KeyPropertyExtendedType_None;
	bool                found       = false;
	
	size_t          actualLength = 0;
	uint8_t*        buffer = NULL;
	
	if(datSize)
		*datSize = 0;
	
	// write code here to process internal properties
	for(propInfo = sPropertyTable;propInfo->name; propInfo++)
	{
		if(CMP2(propName, strlen(propName), propInfo->name, strlen(propInfo->name)))
		{
			propType = propInfo->type;
			
			if(propInfo->signable)
				extendedProp |= S4KeyPropertyExtended_Signable;
			
			found = true;
			
			if(STRCMP2(propName, kS4KeyProp_KeyType))
			{
				actualLength =  sizeof(S4KeyType);
			}
			else if(STRCMP2(propName, kS4KeyProp_KeySuite))
			{
				actualLength =  sizeof(uint32_t);
			}
			else if(STRCMP2(propName, kS4KeyProp_HashAlgorithm))
			{
				actualLength =  sizeof(uint32_t);
			}
			else if(STRCMP2(propName, kS4KeyProp_EncodedObject))
			{
				actualLength =  sizeof(uint32_t);
			}
			else if(STRCMP2(propName, kS4KeyProp_Encoding))
			{
				actualLength =  sizeof(uint32_t);
			}
			else if(STRCMP2(propName, kS4KeyProp_ShareIndex))
			{
				actualLength =  sizeof(uint32_t);
			}
			else if(STRCMP2(propName, kS4KeyProp_ShareThreshold))
			{
				actualLength =  sizeof(uint32_t);
			}
			else if(STRCMP2(propName, kS4KeyProp_ShareTotal))
			{
				actualLength =  sizeof(uint32_t);
			}
			else if(STRCMP2(propName, kS4KeyProp_ShareID))
			{
				actualLength = kS4ShareInfo_HashBytes;
			}
			else if(STRCMP2(propName, kS4KeyProp_ShareOwner))
			{
				actualLength = kS4ShareInfo_HashBytes;
			}
			else if(STRCMP2(propName, kS4KeyProp_p2kParams))
			{
				switch (ctx->type) {
					case kS4KeyType_P2K_ESK:
						actualLength = ctx->esk.p2kParams?strlen(ctx->esk.p2kParams):0;
						break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			else if(STRCMP2(propName, kS4KeyProp_KeyData))
			{
				switch (ctx->type) {
					case kS4KeyType_Symmetric:
						actualLength = ctx->sym.keylen;
						break;
						
					case kS4KeyType_Tweekable:
						actualLength = ctx->tbc.keybits >> 3 ;
						break;
						
					case kS4KeyType_PublicEncrypted:
						actualLength = ctx->publicKeyEncoded.encryptedLen;
						break;
						
					case kS4KeyType_P2K_ESK:
						actualLength = ctx->esk.encryptedLen;
						break;

					case kS4KeyType_Share:
						actualLength = ctx->share.shareSecretLen;
						break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			
			else if(STRCMP2(propName, kS4KeyProp_SigID))
			{
				switch (ctx->type) {
					case kS4KeyType_Signature:
						actualLength = sizeof(ctx->sig.sigID);
						break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			else if(STRCMP2(propName, kS4KeyProp_SignedBy))
			{
				switch (ctx->type) {
					case kS4KeyType_Signature:
						actualLength = sizeof(ctx->sig.issuerID);
						break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			else if(STRCMP2(propName, kS4KeyProp_SignedDate))
			{
				switch (ctx->type) {
					case kS4KeyType_Signature:
						actualLength = sizeof(ctx->sig.signDate);
						break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			else if(STRCMP2(propName, kS4KeyProp_SigExpire))
			{
				switch (ctx->type) {
					case kS4KeyType_Signature:
						actualLength = sizeof(ctx->sig.expirationTime);
						break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			else if(STRCMP2(propName, kS4KeyProp_KeyID))
			{
				switch (ctx->type) {
					case kS4KeyType_PublicEncrypted:
						actualLength = sizeof(ctx->publicKeyEncoded.keyID);
						break;
						
					case kS4KeyType_SymmetricEncrypted:
						actualLength = sizeof(ctx->symKeyEncoded.keyID);
						break;
						
					case kS4KeyType_PublicKey:
						actualLength = sizeof(ctx->pub.keyID);
						break;
						
					case kS4KeyType_Symmetric:
						actualLength = kS4Key_KeyIDBytes;
						break;
						
					case kS4KeyType_Tweekable:
						actualLength = kS4Key_KeyIDBytes;
						break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			
			else if(STRCMP2(propName, kS4KeyProp_Mac))
			{
				switch (ctx->type) {
					case kS4KeyType_Symmetric:
					case kS4KeyType_Tweekable:
					case kS4KeyType_Share:
					case kS4KeyType_PublicEncrypted:
						actualLength = kS4KeyESK_HashBytes;
						break;
						
						//                     case kS4KeyType_PublicEncrypted:
						//                        actualLength = sizeof(ctx->publicKeyEncoded.keyID);
						//                        break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			else if(STRCMP2(propName, kS4KeyProp_KeyIDString))
			{
				switch (ctx->type) {
						
					case kS4KeyType_SymmetricEncrypted:
						actualLength = (((sizeof(ctx->symKeyEncoded.keyID) + 2) / 3) * 4) + 1;
						break;
						
					case kS4KeyType_PublicEncrypted:
						actualLength = (((sizeof(ctx->publicKeyEncoded.keyID) + 2) / 3) * 4) + 1;
						break;
						
					case kS4KeyType_PublicKey:
						actualLength = (((sizeof(ctx->pub.keyID) + 2) / 3) * 4) + 1;
						break;
						
					case kS4KeyType_Symmetric:
						actualLength =  (((kS4Key_KeyIDBytes + 2) / 3) * 4) + 1; ;
						break;
						
					case kS4KeyType_Tweekable:
						actualLength =  (((kS4Key_KeyIDBytes + 2) / 3) * 4) + 1; ;
						break;
						
					default:
						RETERR(kS4Err_BadParams);
				}
			}
			else
				found = false;
			
			break;
			
		}
	}
	
	if(!found)
	{
		otherProp = sFindPropertyInList(ctx->propList,propName);
		if(otherProp)
		{
			actualLength = (unsigned long)(otherProp->valueLen);
			propType = otherProp->type;
			extendedProp = otherProp->extended;
			found = true;
		}
	}
	
	if(!found)
		RETERR(kS4Err_PropertyNotFound);
	
	
	if(!actualLength)
		goto done;
	
	if(doAlloc)
	{
		buffer = XMALLOC(actualLength + sizeof('\0')); CKNULL(buffer);
		*allocBuffer = buffer;
	}
	else
	{
		if(outData)
			actualLength = (actualLength < (unsigned long)bufSize) ? actualLength : (unsigned long)bufSize;
		buffer = outData;
	}
	
	if(buffer)
	{
		if(STRCMP2(propName, kS4KeyProp_KeyType))
		{
			COPY(&ctx->type, buffer, actualLength);
		}
		else if(STRCMP2(propName, kS4KeyProp_HashAlgorithm))
		{
			switch (ctx->type) {
				case kS4KeyType_Signature:
					COPY(&ctx->sig.hashAlgorithm , buffer, actualLength);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
					
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_KeySuite))
		{
			switch (ctx->type) {
				case kS4KeyType_Symmetric:
					COPY(&ctx->sym.symAlgor , buffer, actualLength);
					break;
					
				case kS4KeyType_Tweekable:
					COPY(&ctx->tbc.tbcAlgor , buffer, actualLength);
					break;
					
				case kS4KeyType_PublicKey:
					COPY(&ctx->pub.eccAlgor , buffer, actualLength);
					break;
					
				case kS4KeyType_PublicEncrypted:
					COPY(&ctx->publicKeyEncoded.cipherAlgor , buffer, actualLength);
					break;
					
				case kS4KeyType_P2K_ESK:
				case kS4KeyType_Share_ESK:
					COPY(&ctx->esk.cipherAlgor , buffer, actualLength);
					break;
					
				case kS4KeyType_PBKDF2:
				default:
					RETERR(kS4Err_BadParams);
					
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_Encoding))
		{
			switch (ctx->type) {
				case kS4KeyType_PublicEncrypted:
				{
					Cipher_Algorithm  algor = kCipher_Algorithm_Invalid;
					
					switch(ctx->publicKeyEncoded.keysize)
					{
						case 384: algor = kCipher_Algorithm_ECC384; break;
						case 414: algor = kCipher_Algorithm_ECC414 ; break;
						default: algor = kCipher_Algorithm_Invalid;
					}
					COPY(&algor , buffer, actualLength);
					
				}
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_EncodedObject))
		{
			switch (ctx->type) {
				case kS4KeyType_P2K_ESK:
				case kS4KeyType_Share_ESK:
				{
					Cipher_Algorithm  algor = ctx->esk.objectAlgor;
					COPY(&algor , buffer, actualLength);
				}
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_p2kParams))
		{
			switch (ctx->type) {
				case kS4KeyType_P2K_ESK:
					COPY(ctx->esk.p2kParams , buffer, actualLength);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_KeyData))
		{
			switch (ctx->type) {
				case kS4KeyType_Symmetric:
					COPY(&ctx->sym.symKey , buffer, actualLength);
					break;
					
				case kS4KeyType_Tweekable:
					COPY(&ctx->tbc.key , buffer, actualLength);
					break;
					
				case kS4KeyType_PublicEncrypted:
					COPY(&ctx->publicKeyEncoded.encrypted , buffer, actualLength);
					break;
					
				case kS4KeyType_P2K_ESK:
					COPY(&ctx->esk.encrypted , buffer, actualLength);
					break;
					
				case kS4KeyType_Share:
					COPY(&ctx->share.shareSecret , buffer, actualLength);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		
		
		else if(STRCMP2(propName, kS4KeyProp_SigID))
		{
			switch (ctx->type) {
					
				case kS4KeyType_Signature:
					COPY(&ctx->sig.sigID , buffer, actualLength);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
					
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_SignedBy))
		{
			switch (ctx->type) {
					
				case kS4KeyType_Signature:
					COPY(&ctx->sig.issuerID , buffer, actualLength);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
					
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_SignedDate))
		{
			switch (ctx->type) {
				case kS4KeyType_Signature:
					
					COPY(&ctx->sig.signDate, buffer, actualLength);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		
		else if(STRCMP2(propName, kS4KeyProp_SigExpire))
		{
			switch (ctx->type) {
				case  kS4KeyType_Signature:
					
					COPY(&ctx->sig.expirationTime, buffer, actualLength);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_KeyID))
		{
			switch (ctx->type) {
					
				case kS4KeyType_SymmetricEncrypted:
					COPY(&ctx->symKeyEncoded.keyID , buffer, actualLength);
					break;
					
				case kS4KeyType_PublicEncrypted:
					COPY(&ctx->publicKeyEncoded.keyID , buffer, actualLength);
					break;
					
				case kS4KeyType_PublicKey:
					COPY(&ctx->pub.keyID , buffer, actualLength);
					break;
					
				case kS4KeyType_Symmetric:
					// calculate a keyID for the sym key
					err =  sKEY_HASH(ctx->sym.symKey,  ctx->sym.keylen, ctx->type,
										  ctx->sym.symAlgor,  buffer, actualLength );
					
					break;
					
				case kS4KeyType_Tweekable:
					// calculate a keyID for the TBC key
					err =  sKEY_HASH((uint8_t*)ctx->tbc.key,  ctx->tbc.keybits >> 3, ctx->type,
										  ctx->tbc.tbcAlgor,  buffer, actualLength );
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_Mac))
		{
			uint8_t     keyHash[kS4KeyESK_HashBytes] = {0};
			
			switch (ctx->type) {
				case kS4KeyType_Symmetric:
					err =  sKEY_HASH(ctx->sym.symKey, ctx->tbc.keybits >> 3, ctx->type,
										  ctx->sym.symAlgor, keyHash, kS4KeyESK_HashBytes );
					
					COPY(keyHash , buffer, kS4KeyESK_HashBytes);
					break;
					
				case kS4KeyType_Tweekable:
					err =  sKEY_HASH((uint8_t*)ctx->tbc.key, ctx->sym.keylen >> 3, ctx->type,
										  ctx->tbc.tbcAlgor, keyHash, kS4KeyESK_HashBytes );
					
					COPY(keyHash , buffer, kS4KeyESK_HashBytes);
					break;
					
				case kS4KeyType_Share:
					actualLength = kS4KeyESK_HashBytes;
					
					err =  sKEY_HASH(ctx->share.shareSecret, (int)ctx->share.shareSecretLen, ctx->type,
										  kCipher_Algorithm_SharedKey, keyHash, kS4KeyESK_HashBytes );
					
					COPY(keyHash , buffer, kS4KeyESK_HashBytes);
					break;
					
				case kS4KeyType_PublicEncrypted:
					COPY(ctx->publicKeyEncoded.keyHash , buffer, kS4KeyESK_HashBytes);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		
		else if(STRCMP2(propName, kS4KeyProp_ShareOwner))
		{
			switch (ctx->type) {
				case kS4KeyType_Share_ESK:
					COPY(ctx->esk.shareOwner , buffer, kS4ShareInfo_HashBytes);
					break;
					
				case kS4KeyType_Share:
					COPY(ctx->share.shareOwner , buffer, kS4ShareInfo_HashBytes);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_ShareID))
		{
			switch (ctx->type) {
				case kS4KeyType_Share:
					COPY(ctx->share.shareID , buffer, kS4ShareInfo_HashBytes);
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		
		else if(STRCMP2(propName, kS4KeyProp_ShareIndex))
		{
			switch (ctx->type) {
				case kS4KeyType_Share:
				{
					uint32_t index = ctx->share.xCoordinate;
					COPY(&index , buffer, actualLength);
				}
					break;
					
				case kS4KeyType_Share_ESK:
				{
					uint32_t index = ctx->esk.xCoordinate;
					COPY(&index , buffer, actualLength);
				}
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_ShareThreshold))
		{
			switch (ctx->type) {
				case kS4KeyType_Share:
				{
					uint32_t threshold = ctx->share.threshold;
					COPY(&threshold , buffer, actualLength);
				}
					break;
					
				case kS4KeyType_Share_ESK:
				{
					uint32_t threshold = ctx->esk.threshold;
					COPY(&threshold , buffer, actualLength);
				}
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(STRCMP2(propName, kS4KeyProp_ShareTotal))
		{
			switch (ctx->type) {
				case kS4KeyType_Share_ESK:
				{
					uint32_t totalShares = ctx->esk.totalShares;
					COPY(&totalShares , buffer, actualLength);
				}
					
					break;
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		
		else if(STRCMP2(propName, kS4KeyProp_KeyIDString))
		{
			switch (ctx->type) {
					
				case kS4KeyType_SymmetricEncrypted:
					err = base64_encode(ctx->symKeyEncoded.keyID, sizeof(ctx->symKeyEncoded.keyID), buffer, &actualLength); CKERR;
					actualLength++;
					buffer[actualLength]= '\0';
					break;
					
					
				case kS4KeyType_PublicEncrypted:
					err = base64_encode(ctx->publicKeyEncoded.keyID, sizeof(ctx->publicKeyEncoded.keyID), buffer, &actualLength); CKERR;
					actualLength++;
					buffer[actualLength]= '\0';
					break;
					
				case kS4KeyType_PublicKey:
					err = base64_encode(ctx->pub.keyID, sizeof(ctx->pub.keyID), buffer, &actualLength); CKERR;
					actualLength++;
					buffer[actualLength]= '\0';
					break;
					
				case kS4KeyType_Symmetric:
				{
					uint8_t keyID[kS4Key_KeyIDBytes];
					
					err =  sKEY_HASH(ctx->sym.symKey,  ctx->sym.keylen, ctx->type,
										  ctx->sym.symAlgor,  keyID, kS4Key_KeyIDBytes );CKERR;
					
					err = base64_encode(keyID, kS4Key_KeyIDBytes , buffer, &actualLength); CKERR;
					actualLength++;
					buffer[actualLength]= '\0';
				}
					break;
					
				case kS4KeyType_Tweekable:
				{
					uint8_t keyID[kS4Key_KeyIDBytes];
					
					err =  sKEY_HASH((uint8_t*)ctx->tbc.key,  ctx->tbc.keybits >> 3, ctx->type,
										  ctx->tbc.tbcAlgor,  keyID, kS4Key_KeyIDBytes );CKERR;
					
					err = base64_encode(keyID, kS4Key_KeyIDBytes , buffer, &actualLength); CKERR;
					actualLength++;
					buffer[actualLength]= '\0';
				}
					break;
					
					
				default:
					RETERR(kS4Err_BadParams);
			}
		}
		else if(otherProp && buffer)
		{
			COPY(otherProp->value,  buffer, actualLength);
		}
	}
	
	
	if(outExtendedProp)
		*outExtendedProp = extendedProp;
	
	if(outPropType)
		*outPropType = propType;
	
	if(datSize)
		*datSize = actualLength;
	
	
done:
	return err;
	
	
}

EXPORT_FUNCTION S4Err S4Key_GetExtendedProperty( S4KeyContextRef ctx,
																const char *propName,
																S4KeyPropertyExtendedType *outPropType)
{
	S4Err               err = kS4Err_NoErr;
	
	validateS4KeyContext(ctx);
	ValidateParam(outPropType);
	
	err =  s4Key_GetPropertyInternal(ctx, propName, NULL, outPropType, NULL, 0, 0, false, NULL);
	
	return err;
	
}



EXPORT_FUNCTION S4Err S4Key_GetProperty( S4KeyContextRef ctx,
													 const char *propName,
													 S4KeyPropertyType *outPropType, void *outData, size_t bufSize, size_t *datSize)
{
	S4Err               err = kS4Err_NoErr;
	
	validateS4KeyContext(ctx);
	//    ValidateParam(outData);
	
	if ( IsntNull( outData ) )
	{
		ZERO( outData, bufSize );
	}
	
	err =  s4Key_GetPropertyInternal(ctx, propName, outPropType, NULL, outData, bufSize, datSize, false, NULL);
	
	return err;
}



EXPORT_FUNCTION S4Err S4Key_GetAllocatedProperty( S4KeyContextRef ctx,
																 const char *propName,
																 S4KeyPropertyType *outPropType, void **outData, size_t *datSize)
{
	S4Err               err = kS4Err_NoErr;
	
	validateS4KeyContext(ctx);
	ValidateParam(outData);
	
	err =  s4Key_GetPropertyInternal(ctx, propName, outPropType, NULL, NULL, 0, datSize, true, (uint8_t**) outData);
	
	return err;
}

EXPORT_FUNCTION S4Err S4Key_RemoveProperty( S4KeyContextRef ctx,
														 const char *propName)
{
	S4Err               err = kS4Err_NoErr;
	S4KeyPropertyInfo  *propInfo = NULL;
	bool found = false;
	
	bool needsSigning = false;
	
	// is it a read only property?
	for(propInfo = sPropertyTable; propInfo->name; propInfo++)
	{
		if(CMP2(propName, strlen(propName), propInfo->name, strlen(propInfo->name)))
		{
			if(propInfo->readOnly)
				RETERR(kS4Err_BadParams);
			
			found = true;
			break;
		}
	}
	
	// delete property
	err = sDeleteProperty(ctx, propName, &needsSigning);
	if(IsntS4Err(err))
	{
		if((ctx->type == kS4KeyType_PublicKey)
			&& ECC_isPrivate(ctx->pub.ecc)
			&& needsSigning)
		{
			//  re-sign key  when new property is added
			err = S4Key_SignKey(ctx,ctx, LONG_MAX); CKERR;
		}
	}
	
done:
	return err;
	
}

#ifdef __clang__
#pragma mark - Public Key wrapper.
#endif

EXPORT_FUNCTION S4Err S4Key_Clone_ECC_Context(S4KeyContextRef pubKeyCtx,  ECC_ContextRef *eccOut)
{
	S4Err           err = kS4Err_NoErr;
	ECC_ContextRef  newEcc = kInvalidECC_ContextRef;
	uint8_t         keyData[256];
	size_t          keyDataLen = 0;
	
	validateS4KeyContext(pubKeyCtx);
	ValidateParam(pubKeyCtx->type == kS4KeyType_PublicKey);
	ValidateParam(ECC_AlgorithmIsAvailable(pubKeyCtx->pub.eccAlgor));
	ValidateParam(eccOut);
	
	if(ECC_isPrivate(pubKeyCtx->pub.ecc))
	{
		err =  ECC_Export(pubKeyCtx->pub.ecc, true, keyData, sizeof(keyData), &keyDataLen);CKERR;
		err = ECC_Import(keyData, keyDataLen, &newEcc);CKERR;
	}
	else
	{
		err = ECC_Export_ANSI_X963(pubKeyCtx->pub.ecc, keyData, sizeof(keyData), &keyDataLen);CKERR;
		err = ECC_Import_ANSI_X963(keyData, keyDataLen, &newEcc);CKERR;
	}
	
	if(eccOut) *eccOut = newEcc;
	
done:
	
	if(IsS4Err(err))
	{
		if(ECC_ContextRefIsValid(newEcc))
		{
			ECC_Free(newEcc);
		}
	}
	
	ZERO(keyData, sizeof(keyData));
	
	return err;
	
};



static S4Err sDecryptFromPubKey( S4KeyContextRef      encodedCtx,
										  ECC_ContextRef    eccPriv,
										  S4KeyContextRef       *symCtx)
{
	S4Err           err = kS4Err_NoErr;
	S4KeyContext*   keyCTX = NULL;
	
	int                 encyptAlgor = kCipher_Algorithm_Invalid;
	size_t              keyBytes = 0;
	
	uint8_t             decrypted_key[128] = {0};
	size_t              decryptedLen = 0;
	
	uint8_t             keyHash[kS4KeyESK_HashBytes] = {0};
	
	validateS4KeyContext(encodedCtx);
	validateECCContext(eccPriv);
	ValidateParam(symCtx);
	
	ValidateParam(encodedCtx->type == kS4KeyType_PublicEncrypted);
	
	ValidateParam (ECC_isPrivate(eccPriv));
	
	if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Symmetric)
	{
		keyBytes = sGetKeyLength(kS4KeyType_Symmetric, encodedCtx->publicKeyEncoded.cipherAlgor);
		encyptAlgor = encodedCtx->publicKeyEncoded.cipherAlgor;
		
	}
	else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Tweekable)
	{
		keyBytes = sGetKeyLength(kS4KeyType_Tweekable, encodedCtx->publicKeyEncoded.cipherAlgor);
		encyptAlgor = encodedCtx->publicKeyEncoded.cipherAlgor;
	}
	else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Share)
	{
		encyptAlgor = kCipher_Algorithm_SharedKey;
	}
	
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	
	if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Symmetric)
	{
		keyCTX->type  = kS4KeyType_Symmetric;
		keyCTX->sym.symAlgor = encodedCtx->publicKeyEncoded.cipherAlgor;
		keyCTX->sym.keylen = keyBytes;
		
		err = ECC_Decrypt(eccPriv,
								encodedCtx->publicKeyEncoded.encrypted, encodedCtx->publicKeyEncoded.encryptedLen,
								decrypted_key, sizeof(decrypted_key), &decryptedLen  );CKERR;
		
		ASSERTERR(decryptedLen == keyBytes, kS4Err_CorruptData );
		
		COPY(decrypted_key, keyCTX->sym.symKey, decryptedLen);
		
	}
	else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Tweekable)
	{
		keyCTX->type  = kS4KeyType_Tweekable;
		keyCTX->tbc.tbcAlgor = encodedCtx->publicKeyEncoded.cipherAlgor;
		keyCTX->tbc.keybits = keyBytes << 3;
		
		err = ECC_Decrypt(eccPriv,
								encodedCtx->publicKeyEncoded.encrypted, encodedCtx->publicKeyEncoded.encryptedLen,
								decrypted_key, sizeof(decrypted_key), &decryptedLen  );CKERR;
		
		ASSERTERR(decryptedLen == keyBytes , kS4Err_CorruptData );
		
		memcpy(keyCTX->tbc.key, decrypted_key, keyBytes);
		
		//       Skein_Get64_LSB_First(keyCTX->tbc.key, decrypted_key, keyBytes >>2);   /* bytes to words */
	}
	else
		RETERR(kS4Err_BadParams);
	
	// check integrity of decypted value against the MAC
	err = sKEY_HASH(decrypted_key, keyBytes, keyCTX->type,  encyptAlgor,
						 keyHash, kS4KeyESK_HashBytes ); CKERR;
	
	ASSERTERR( CMP(keyHash, encodedCtx->publicKeyEncoded.keyHash, kS4KeyESK_HashBytes),
				 kS4Err_BadIntegrity)
	
	
	
	*symCtx = keyCTX;
	
	
	
done:
	
	if(IsS4Err(err))
	{
		if(IsntNull(keyCTX))
		{
			XFREE(keyCTX);
		}
	}
	
	ZERO(decrypted_key, sizeof(decrypted_key));
	
	return err;
	
}


static S4Err sSerializeToPubKey(S4KeyContextRef   ctx,
										  ECC_ContextRef    eccPub,
										  uint8_t          **outData,
										  size_t           *outSize)
{
	S4Err           err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	uint8_t             *yajlBuf = NULL;
	size_t              yajlLen = 0;
	yajl_gen            g = NULL;
	
	uint8_t             tempBuf[1024];
	size_t              tempLen;
	uint8_t             *outBuf = NULL;
	
	const char* 		curveName = NULL;
	ECC_Algorithm 		eccAlgor = kECC_Algorithm_Invalid;
	
	uint8_t             keyID[kS4Key_KeyIDBytes];
	size_t              keyIDLen = 0;
	
	uint8_t             keyHash[kS4KeyESK_HashBytes];
	int                 keyAlgorithm = 0;
	
	uint8_t            encrypted[256] = {0};       // typical 199 bytes
	size_t              encryptedLen = 0;
	
	size_t              keyBytes = 0;
	void*               keyToEncrypt = NULL;
	
	char*              keySuiteString = "Invalid";
	
	yajl_alloc_funcs allocFuncs = {
		yajlMalloc,
		yajlRealloc,
		yajlFree,
		(void *) NULL
	};
	
	
	validateS4KeyContext(ctx);
	validateECCContext(eccPub);
	ValidateParam(outData);
	
	err = ECC_GetAlgorithm(eccPub, &eccAlgor);CKERR;
	err = ECC_GetName(eccAlgor, &curveName);CKERR;
	
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
			keyBytes = ctx->sym.keylen ;
			keyToEncrypt = ctx->sym.symKey;
			keyAlgorithm = ctx->sym.symAlgor;
			keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
			break;
			
		case kS4KeyType_Tweekable:
			keyBytes = ctx->tbc.keybits >> 3 ;
			keyToEncrypt = ctx->tbc.key;
			keyAlgorithm = ctx->tbc.tbcAlgor;
			keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
			break;
			
		case kS4KeyType_Share:
			keyBytes = (int)ctx->share.shareSecretLen ;
			keyToEncrypt = ctx->share.shareSecret;
			keyAlgorithm = kCipher_Algorithm_SharedKey;
			keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
			break;
			
		default:
			break;
	}
	
	/* limit ECC encryption to <= 512 bits of data */
	//    ValidateParam(keyBytes <= (512 >>3));
	
	err = sKEY_HASH(keyToEncrypt, keyBytes, ctx->type,
						 keyAlgorithm, keyHash, kS4KeyESK_HashBytes ); CKERR;
	
	err = ECC_PubKeyHash(eccPub, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
	
	err = ECC_Encrypt(eccPub, keyToEncrypt, keyBytes,  encrypted, sizeof(encrypted), &encryptedLen);CKERR;
	
	g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
	
#if DEBUG
	yajl_gen_config(g, yajl_gen_beautify, 1);
#else
	yajl_gen_config(g, yajl_gen_beautify, 0);
	
#endif
	yajl_gen_config(g, yajl_gen_validate_utf8, 1);
	stat = yajl_gen_map_open(g);CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)curveName, strlen(curveName)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeyID, strlen(kS4KeyProp_KeyID)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(keyID, keyIDLen, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(keyHash, kS4KeyESK_HashBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
		case kS4KeyType_Tweekable:
			break;
			
		case kS4KeyType_Share:
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIndex, strlen(kS4KeyProp_ShareIndex)) ; CKYJAL;
			sprintf((char *)tempBuf, "%d", ctx->share.xCoordinate);
			stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
			sprintf((char *)tempBuf, "%d", ctx->share.threshold);
			stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareHash, strlen(kS4KeyProp_ShareHash)) ; CKYJAL;
			tempLen = sizeof(tempBuf);
			base64_encode(ctx->share.shareOwner, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
			stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
			break;
			
		default:
			break;
	}
	
	
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(encrypted, encryptedLen, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	err = sGenPropStrings(ctx->propList, g); CKERR;
	err = sGenSignablePropString(ctx, g); CKERR;
	err = sGenSignatureStrings(ctx, g); CKERR;
	
	stat = yajl_gen_map_close(g); CKYJAL;
	stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
	
	outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
	memcpy(outBuf, yajlBuf, yajlLen);
	outBuf[yajlLen] = 0;
	
	*outData = outBuf;
	if(outSize)
		*outSize = yajlLen;
	
done:
	if(IsntNull(g))
		yajl_gen_free(g);
	
	return err;
	
}

#ifdef __clang__
#pragma mark - create Key.
#endif

EXPORT_FUNCTION S4Err S4Key_NewKey(Cipher_Algorithm       algorithm,
											  S4KeyContextRef    *ctxOut)
{
	S4Err   err = kS4Err_NoErr;
	S4KeyContext*    keyCTX  = NULL;
	
	int     keyBytes  = 0;
	uint8_t *keyData = NULL;
	
	ValidateParam(ctxOut);
	
	switch(algorithm)
	{
		case kCipher_Algorithm_AES128:
			keyBytes = 128 >> 3;
			break;
			
		case kCipher_Algorithm_AES192:
			keyBytes = 192 >> 3;
			break;
			
		case kCipher_Algorithm_AES256:
			keyBytes = 256 >> 3;
			break;
			
		case kCipher_Algorithm_2FISH256:
			keyBytes = 256 >> 3;
			break;
			
		case kCipher_Algorithm_3FISH256:
			keyBytes =  256 >> 3;
			break;
			
		case kCipher_Algorithm_3FISH512:
			keyBytes = 512 >> 3;
			break;
			
		case kCipher_Algorithm_3FISH1024:
			keyBytes = 1024 >> 3;
			break;
			
		default: ;
	}
	
	if(keyBytes)
	{
		keyData = (uint8_t*)XMALLOC(keyBytes);
		err = RNG_GetBytes(keyData, keyBytes);CKERR;
	}
	
	switch(algorithm)
	{
		case kCipher_Algorithm_AES128:
		case kCipher_Algorithm_AES192:
		case kCipher_Algorithm_AES256:
		case kCipher_Algorithm_2FISH256:
			
			err = S4Key_NewSymmetric(algorithm, keyData, &keyCTX);
			break;
			
		case kCipher_Algorithm_3FISH256:
		case kCipher_Algorithm_3FISH512:
		case kCipher_Algorithm_3FISH1024:
			
			err = S4Key_NewTBC(algorithm, keyData, &keyCTX);
			break;
			
		case kCipher_Algorithm_ECC384:
		case kCipher_Algorithm_ECC414:
			err= S4Key_NewPublicKey(algorithm, &keyCTX);
			break;
			
		default:
			RETERR(kS4Err_BadCipherNumber);
	}
	
	
	*ctxOut = keyCTX;
	
done:
	
	if(keyData && keyBytes)
	{
		ZERO(keyData, keyBytes);
		XFREE(keyData);
	}
	
	if(IsS4Err(err))
	{
		if(keyCTX)
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	
	return err;
}

EXPORT_FUNCTION S4Err S4Key_NewSymmetric(Cipher_Algorithm       algorithm,
													  const void             *key,
													  S4KeyContextRef    *ctxOut)
{
	S4Err               err = kS4Err_NoErr;
	S4KeyContext*    keyCTX  = NULL;
	
	ValidateParam(ctxOut);
	
	int             keylen  = 0;
	
	switch(algorithm)
	{
		case kCipher_Algorithm_AES128:
			keylen = 128 >> 3;
			break;
			
		case kCipher_Algorithm_AES192:
			keylen = 192 >> 3;
			break;
			
		case kCipher_Algorithm_AES256:
			keylen = 256 >> 3;
			break;
			
		case kCipher_Algorithm_2FISH256:
			keylen = 256 >> 3;
			break;
			
		default:
			RETERR(kS4Err_BadCipherNumber);
	}
	
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	keyCTX->type  = kS4KeyType_Symmetric;
	keyCTX->propList = NULL;
	keyCTX->sigList = NULL;
	
	keyCTX->sym.symAlgor = algorithm;
	keyCTX->sym.keylen = keylen;
	
	// leave null bytes at end of key, for odd size keys (like 192)
	ZERO(keyCTX->sym.symKey, sizeof(keyCTX->sym.symKey) );
	COPY(key, keyCTX->sym.symKey, keylen);
	
	*ctxOut = keyCTX;
	
done:
	if(IsS4Err(err))
	{
		if(keyCTX)
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	return err;
}


EXPORT_FUNCTION S4Err S4Key_NewTBC(     Cipher_Algorithm       algorithm,
											  const void     *key,
											  S4KeyContextRef   *ctxOut)
{
	S4Err               err = kS4Err_NoErr;
	S4KeyContext*    keyCTX  = NULL;
	
	ValidateParam(ctxOut);
	
	int             keybits  = 0;
	
	switch(algorithm)
	{
		case kCipher_Algorithm_3FISH256:
			keybits = Threefish256;
			break;
			
		case kCipher_Algorithm_3FISH512:
			keybits = Threefish512;
			break;
			
		case kCipher_Algorithm_3FISH1024:
			keybits = Threefish1024 ;
			break;
			
		default:
			RETERR(kS4Err_BadCipherNumber);
	}
	
	
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	keyCTX->type  = kS4KeyType_Tweekable;
	keyCTX->propList = NULL;
	keyCTX->sigList = NULL;
	
	keyCTX->tbc.tbcAlgor = algorithm;
	keyCTX->tbc.keybits = keybits;
	
	memcpy(keyCTX->tbc.key, key, keybits >> 3);
	
	//   Skein_Get64_LSB_First(keyCTX->tbc.key, key, keybits >>5);   /* bits to words */
	
	*ctxOut = keyCTX;
	
done:
	if(IsS4Err(err))
	{
		if(keyCTX)
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	return err;
}


S4Err sConvertShareToKey(S4SharesPartContext   *share,
								 S4KeyContextRef    *ctxOut)
{
	S4Err               err = kS4Err_NoErr;
	S4KeyContext*    keyCTX  = NULL;
	
	
	ValidateParam(ctxOut);
	ValidateParam(sS4SharesPartContextIsValid(share));
	ValidateParam(share->shareSecretLen <= kS4ShareInfo_MaxSecretBytes);
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	keyCTX->type  = kS4KeyType_Share;
	keyCTX->propList = NULL;
	keyCTX->sigList = NULL;
	
	keyCTX->share.xCoordinate = share->xCoordinate;
	keyCTX->share.threshold   = share->threshold;
	COPY(share->shareOwner, keyCTX->share.shareOwner, kS4ShareInfo_HashBytes);
	COPY(share->shareID, keyCTX->share.shareID, kS4ShareInfo_HashBytes);
	keyCTX->share.shareSecretLen    = share->shareSecretLen;
	COPY(share->shareSecret, keyCTX->share.shareSecret, share->shareSecretLen);
	
	*ctxOut = keyCTX;
	
done:
	if(IsS4Err(err))
	{
		if(keyCTX)
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	return err;
	
}


static S4Err sCalculateECCData(S4KeyContextRef  ctx)
{
	S4Err               err = kS4Err_NoErr;
	size_t          len = 0;
	size_t          pubKeyLen = 0;
	
	if(ECC_isPrivate(ctx->pub.ecc))
	{
		ctx->pub.privKey = XMALLOC(kS4KeyPublic_MAX_PrivKeyLen);
		err =  ECC_Export( ctx->pub.ecc, true, ctx->pub.privKey, kS4KeyPublic_MAX_PrivKeyLen, &len);CKERR;
		ctx->pub.privKeyLen  = (uint8_t)(len & 0xff);
		ctx->pub.isPrivate = 1;
	}
	else
	{
		ctx->pub.isPrivate = 0;
		ctx->pub.privKeyLen = 0;
		ctx->pub.privKey = NULL;
	}
	
	err =  ECC_Export_ANSI_X963( ctx->pub.ecc, ctx->pub.pubKey, sizeof(ctx->pub.pubKey), &pubKeyLen);CKERR;
	ctx->pub.pubKeyLen = pubKeyLen;
	
	err = ECC_PubKeyHash(ctx->pub.ecc, ctx->pub.keyID, kS4Key_KeyIDBytes, NULL);CKERR;
	
done:
	return err;
	
}


EXPORT_FUNCTION S4Err S4Key_Import_ECC_Context(ECC_ContextRef ecc, S4KeyContextRef*ctxOut)
{
	S4Err err = kS4Err_NoErr;
	
	ValidateParam(ECC_ContextRefIsValid(ecc));
	ValidateParam(ctxOut);
	
	S4KeyContext*       keyCTX  = NULL;
	ECC_Algorithm		algorithm = kECC_Algorithm_Invalid;
	
	err = ECC_GetAlgorithm(ecc, &algorithm); CKERR;
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	keyCTX->type  = kS4KeyType_PublicKey;
	keyCTX->propList = NULL;
	keyCTX->sigList = NULL;
	
	keyCTX->pub.ecc = ecc;
	keyCTX->pub.eccAlgor = algorithm;
	err = sCalculateECCData(keyCTX); CKERR;
	
	*ctxOut = keyCTX;
	
done:
	if(IsS4Err(err))
	{
		if(keyCTX)
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	return err;
	
}

EXPORT_FUNCTION S4Err
S4Key_NewPublicKey(Cipher_Algorithm algorithm,
						 S4KeyContextRef* ctxOut)
{
	S4Err               err = kS4Err_NoErr;
	S4KeyContext*       keyCTX  = NULL;
	ECC_ContextRef      ecc = kInvalidECC_ContextRef;
	
	ValidateParam(ctxOut);
	
	ECC_Algorithm eccAlgor = kECC_Algorithm_Invalid;
	
	switch(algorithm)
	{
		case kCipher_Algorithm_ECC384:
			eccAlgor = kECC_Algorithm_ECC384;
			break;
			
		case kCipher_Algorithm_ECC414:
			eccAlgor = kECC_Algorithm_Curve41417;
			break;
			
		default:
			RETERR(kS4Err_BadCipherNumber);
	}
	
	err = ECC_Init(eccAlgor,&ecc);CKERR;
	err = S4Key_Import_ECC_Context(ecc, &keyCTX); CKERR;
	
	// self sign key
	err = S4Key_SignKey(keyCTX,keyCTX, LONG_MAX); CKERR;
	
	*ctxOut = keyCTX;
	
done:
	if(IsS4Err(err))
	{
		if(keyCTX)
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	return err;
	
}

void sZeroKeyCtx (S4KeyContextRef ctx)
{
	if(sS4KeyContextIsValid(ctx))
	{
		sFreePropertyList(ctx->propList);
		ctx->propList = NULL;
		
		S4KeySigItem *sig = ctx->sigList;
		
		while(sig)
		{
			S4KeySigItem *nextSig = sig->next;
			
			sFreeKeySigContents(&sig->sig);
			XFREE(sig);
			sig = nextSig;
		}
		
		
		switch (ctx->type) {
			case kS4KeyType_PublicKey:
				
				if(ECC_ContextRefIsValid(ctx->pub.ecc))
					ECC_Free(ctx->pub.ecc);
				
				if(ctx->pub.privKey && ctx->pub.privKeyLen)
				{
					ZERO(ctx->pub.privKey ,ctx->pub.privKeyLen);
					XFREE(ctx->pub.privKey);
					ctx->pub.privKey = NULL;
				}
				
				break;
				
			case kS4KeyType_P2K_ESK:
			case kS4KeyType_Share_ESK:
				
				if(ctx->esk.p2kParams)
				{
					ZERO(ctx->esk.p2kParams ,strlen(ctx->esk.p2kParams));
					XFREE((void*)ctx->esk.p2kParams);
					ctx->esk.p2kParams = NULL;
				}
				if(ctx->esk.encrypted)
				{
					ZERO(ctx->esk.encrypted ,ctx->esk.encryptedLen );
					XFREE((void*)ctx->esk.encrypted);
					ctx->esk.encrypted = NULL;
				}
				if(ctx->esk.shareIDList)
				{
					for(uint8_t**  item =  ctx->esk.shareIDList;
						 *item; item++)  XFREE(*item);
					XFREE(ctx->esk.shareIDList);
				}
				
				break;
				
			case kS4KeyType_Signature:
			{
				if(ctx->sig.signature)
					XFREE(ctx->sig.signature);
				
				if(ctx->sig.propNameList)
				{
					char**   itemName = ctx->sig.propNameList;
					for(;*itemName; itemName++)  XFREE(*itemName);
					XFREE(ctx->sig.propNameList);
				}
				
			}
				break;
				
			default:
				break;
		}
		
		
		
		ZERO(ctx, sizeof(S4KeyContext));
	}
	
}

EXPORT_FUNCTION
void S4Key_Free(S4KeyContextRef ctx)
{
	if(sS4KeyContextIsValid(ctx))
	{
		sZeroKeyCtx(ctx);
		XFREE(ctx);
	}
}


static S4Err sClonePubKey(S4KeyContext *src, S4KeyContext *dest )
{
	S4Err               err = kS4Err_NoErr;
	
	uint8_t         keyData[256];
	size_t          keyDataLen = 0;
	
	dest->magic = kS4KeyContextMagic;
	dest->type = kS4KeyType_PublicKey;
	dest->pub.eccAlgor = src->pub.eccAlgor;
	
	if(ECC_isPrivate(src->pub.ecc))
	{
		err =  ECC_Export(src->pub.ecc, true, keyData, sizeof(keyData), &keyDataLen);CKERR;
		err = ECC_Import( keyData, keyDataLen, &dest->pub.ecc);CKERR;
	}
	else
	{
		err = ECC_Export_ANSI_X963(src->pub.ecc, keyData, sizeof(keyData), &keyDataLen);CKERR;
		err = ECC_Import_ANSI_X963(keyData, keyDataLen, &dest->pub.ecc);CKERR;
	}
	
	err = sCalculateECCData(dest); CKERR;
	
done:
	
	ZERO(keyData, sizeof(keyData));
	return err;
}

static S4Err sCloneDetachedSig(S4KeyContext *src, S4KeyContext *dest )
{
	S4Err               err = kS4Err_NoErr;
	
	COPY(src->sig.issuerID, dest->sig.issuerID, kS4Key_KeyIDBytes );
	COPY(src->sig.sigID, dest->sig.sigID, kS4Key_KeyIDBytes );
	
	dest->sig.signDate = src->sig.signDate;
	dest->sig.expirationTime = src->sig.expirationTime;
	dest->sig.hashAlgorithm = src->sig.hashAlgorithm;
	
	dest->sig.signature = XMALLOC(src->sig.signatureLen);  CKNULL(dest->sig.signature);
	COPY(src->sig.signature, dest->sig.signature, src->sig.signatureLen );
	dest->sig.signatureLen = src->sig.signatureLen;
	
done:
	
	return err;
	
}

EXPORT_FUNCTION S4Err S4Key_Copy(S4KeyContextRef ctx, S4KeyContextRef *ctxOut)
{
	S4Err               err = kS4Err_NoErr;
	S4KeyContext*    keyCTX  = NULL;
	
	validateS4KeyContext(ctx);
	ValidateParam(ctxOut);
	
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX,sizeof (S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	keyCTX->type = ctx->type;
	
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
			keyCTX->sym = ctx->sym;
			break;
			
		case kS4KeyType_Tweekable:
			keyCTX->tbc = ctx->tbc;
			break;
			
		case kS4KeyType_P2K_ESK:
			keyCTX->esk = ctx->esk;
			if(ctx->esk.encrypted && ctx->esk.encryptedLen > 0)
			{
				keyCTX->esk.encrypted = XMALLOC(ctx->esk.encryptedLen);
				COPY(ctx->esk.encrypted,keyCTX->esk.encrypted, ctx->esk.encryptedLen);
			}
			
			if(ctx->esk.p2kParams)
				keyCTX->esk.p2kParams = strdup(ctx->esk.p2kParams);
			
			break;
			
		case kS4KeyType_PBKDF2:
			keyCTX->pbkdf2 = ctx->pbkdf2;
			break;
			
		case kS4KeyType_PublicEncrypted:
			keyCTX->publicKeyEncoded = ctx->publicKeyEncoded;
			break;
			
		case kS4KeyType_SymmetricEncrypted:
			keyCTX->symKeyEncoded = ctx->symKeyEncoded;
			break;
			
		case kS4KeyType_Share:
			keyCTX->share = ctx->share;
			break;
			
		case kS4KeyType_PublicKey:
			err = sClonePubKey(ctx, keyCTX); CKERR;
			break;
			
		case kS4KeyType_Signature:
			err = sCloneDetachedSig(ctx, keyCTX); CKERR;
			break;
			
		default:
			break;
	}
	
	sClonePropertiesLists(ctx->propList, &keyCTX->propList);
	sCloneSignatures(ctx, keyCTX);
	*ctxOut = keyCTX;
	
done:
	if(IsS4Err(err))
	{
		if(keyCTX)
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	return err;
	
}


#ifdef __clang__
#pragma mark - export key.
#endif

/*
 
 {
 "version": 1,
 "keySuite": "aes256",
 "encoding": "pbkdf2",
 "salt": "qzbdGRxw4js=",
 "rounds": 192307,
 "hash": "KSA9JcWT/i4TvAIC3lYKrQ==",
 "encrypted": "3+lt1R5cYBO7aNxp/WA8xbjieKtblezx3M8siskX40I="
 }
 
 */

EXPORT_FUNCTION S4Err S4Key_SerializeToPassPhrase(S4KeyContextRef  ctx,
																  const uint8_t       *passphrase,
																  size_t           passphraseLen,
																  uint8_t          **outData,
																  size_t           *outSize)
{
	S4Err           err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	uint8_t             *yajlBuf = NULL;
	size_t              yajlLen = 0;
	yajl_gen            g = NULL;
	
	uint8_t             tempBuf[1024];
	size_t              tempLen;
	uint8_t             *outBuf = NULL;
	
	uint32_t        rounds;
	uint8_t         keyHash[kS4KeyESK_HashBytes] = {0};
	uint8_t         salt[kS4KeyPBKDF2_SaltBytes] = {0};
	
	uint8_t         unlocking_key[32] = {0};
	
	Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
	uint8_t             encrypted_key[128] = {0};
	size_t              keyBytes = 0;
	void*               keyToEncrypt = NULL;
	
	const char*    		encodingPropString = "Invalid";
	const char*    		keySuiteString = "Invalid";
	
	yajl_alloc_funcs allocFuncs = {
		yajlMalloc,
		yajlRealloc,
		yajlFree,
		(void *) NULL
	};
	
	
	validateS4KeyContext(ctx);
	ValidateParam(passphrase);
	ValidateParam(outData);
	
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
			keyBytes = ctx->sym.keylen ;
			keyToEncrypt = ctx->sym.symKey;
			
			switch (ctx->sym.symAlgor) {
				case kCipher_Algorithm_2FISH256:
					encyptAlgor = kCipher_Algorithm_2FISH256;
					encodingPropString =  kS4KeyProp_Encoding_PBKDF2_2FISH256;
					break;
					
				case kCipher_Algorithm_AES192:
					encyptAlgor = kCipher_Algorithm_AES256;
					encodingPropString =  kS4KeyProp_Encoding_PBKDF2_AES256;
					
					//  pad the end  (treat it like it was 256 bits)
					ZERO(&ctx->sym.symKey[24], 8);
					keyBytes = 32;
					break;
					
				default:
					encyptAlgor = kCipher_Algorithm_AES256;
					encodingPropString =  kS4KeyProp_Encoding_PBKDF2_AES256;
					break;
			}
			
			keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
			break;
			
		case kS4KeyType_Tweekable:
			keyBytes = ctx->tbc.keybits >> 3 ;
			encyptAlgor = kCipher_Algorithm_2FISH256;
			keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
			encodingPropString =  kS4KeyProp_Encoding_PBKDF2_2FISH256;
			keyToEncrypt = ctx->tbc.key;
			
			break;
			
		case kS4KeyType_Share:
			keyBytes = (int)ctx->share.shareSecretLen ;
			encyptAlgor = kCipher_Algorithm_2FISH256;
			keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
			keyToEncrypt = ctx->share.shareSecret;
			encodingPropString =  kS4KeyProp_Encoding_PBKDF2_2FISH256;
			
			// we only encode block sizes of 16, 32, 48 and 64
			ASSERTERR((keyBytes % 16) == 0, kS4Err_FeatureNotAvailable);
			ASSERTERR(keyBytes <= 64, kS4Err_FeatureNotAvailable);
			
			break;
			
		default:
			RETERR(kS4Err_BadParams);
			break;
	}
	
	
	err = RNG_GetBytes( salt, kS4KeyPBKDF2_SaltBytes ); CKERR;
	
	err = PASS_TO_KEY_SETUP(passphraseLen, keyBytes,
									salt, sizeof(salt),
									&rounds); CKERR;
	
	err = PASS_TO_KEY(passphrase, passphraseLen,
							salt, sizeof(salt), rounds,
							unlocking_key, sizeof(unlocking_key)); CKERR;
	
	err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
								  salt, sizeof(salt),
								  rounds,
								  keyHash, kS4KeyESK_HashBytes); CKERR;
	
	err =  ECB_Encrypt(encyptAlgor, unlocking_key,
							 keyToEncrypt, keyBytes,
							 encrypted_key, keyBytes); CKERR;
	
	g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
	
#if DEBUG
	yajl_gen_config(g, yajl_gen_beautify, 1);
#else
	yajl_gen_config(g, yajl_gen_beautify, 0);
	
#endif
	yajl_gen_config(g, yajl_gen_validate_utf8, 1);
	stat = yajl_gen_map_open(g);CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)encodingPropString, strlen(encodingPropString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Salt, strlen(kS4KeyProp_Salt)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(salt, kS4KeyPBKDF2_SaltBytes, tempBuf, &tempLen);
	
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Rounds, strlen(kS4KeyProp_Rounds)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", rounds);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(keyHash, kS4KeyESK_HashBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
		case kS4KeyType_Tweekable:
			break;
			
		case kS4KeyType_Share:
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIndex, strlen(kS4KeyProp_ShareIndex)) ; CKYJAL;
			sprintf((char *)tempBuf, "%d", ctx->share.xCoordinate);
			stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
			sprintf((char *)tempBuf, "%d", ctx->share.threshold);
			stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareHash, strlen(kS4KeyProp_ShareHash)) ; CKYJAL;
			tempLen = sizeof(tempBuf);
			base64_encode(ctx->share.shareOwner, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
			stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
			break;
			
		default:
			break;
	}
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(encrypted_key, keyBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	err = sGenPropStrings(ctx->propList, g); CKERR;
	err = sGenSignablePropString(ctx, g); CKERR;
	err = sGenSignatureStrings(ctx, g); CKERR;
	
	stat = yajl_gen_map_close(g); CKYJAL;
	stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
	
	
	outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
	memcpy(outBuf, yajlBuf, yajlLen);
	outBuf[yajlLen] = 0;
	
	*outData = outBuf;
	
	if(outSize)
		*outSize = yajlLen;
	
done:
	if(IsntNull(g))
		yajl_gen_free(g);
	
	return err;
	
}




EXPORT_FUNCTION S4Err S4Key_SerializeToS4Key(S4KeyContextRef  ctx,
															S4KeyContextRef  passKeyCtx,
															uint8_t          **outData,
															size_t           *outSize)
{
	S4Err           err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	uint8_t             *yajlBuf = NULL;
	size_t              yajlLen = 0;
	yajl_gen            g = NULL;
	
	uint8_t             tempBuf[1024];
	size_t              tempLen;
	uint8_t             *outBuf = NULL;
	
	
	uint8_t             keyHash[kS4KeyESK_HashBytes] = {0};
	uint8_t             keyID[kS4Key_KeyIDBytes] = {0};
	
	size_t              keyBytes = 0;
	void*               keyToEncrypt = NULL;
	
	Cipher_Algorithm    keyAlgorithm = kCipher_Algorithm_Invalid;
	
	Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
	void*               unlockingKey    = NULL;
	
	const char*           keySuiteString = "Invalid";
	const char*           encodingPropString = "Invalid";
	
	
	yajl_alloc_funcs allocFuncs = {
		yajlMalloc,
		yajlRealloc,
		yajlFree,
		(void *) NULL
	};
	
	
	validateS4KeyContext(ctx);
	validateS4KeyContext(passKeyCtx);
	ValidateParam(outData);
	
	switch (passKeyCtx->type)
	{
		case kS4KeyType_Symmetric:
			unlockingKey = passKeyCtx->sym.symKey;
			encyptAlgor =  passKeyCtx->sym.symAlgor;
			ASSERTERR(passKeyCtx->sym.symAlgor != kCipher_Algorithm_AES192, kS4Err_FeatureNotAvailable);
			
			switch (passKeyCtx->sym.symAlgor) {
					
				case kCipher_Algorithm_AES128:
					encodingPropString =  kS4KeyProp_Encoding_SYM_AES128;
					break;
					
				case kCipher_Algorithm_AES256:
					encodingPropString =  kS4KeyProp_Encoding_SYM_AES256;
					break;
					
				case kCipher_Algorithm_2FISH256:
					encodingPropString =  kS4KeyProp_Encoding_SYM_2FISH256;
					break;
					
				default:
					RETERR(kS4Err_FeatureNotAvailable);
					
					break;
			}
			
			break;
			
		case kS4KeyType_PublicKey:
			
			return sSerializeToPubKey(ctx, passKeyCtx->pub.ecc, outData, outSize);
			break;
			
		default:
			RETERR(kS4Err_FeatureNotAvailable);
			break;
	}
	
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
			keyBytes = ctx->sym.keylen ;
			keyToEncrypt = ctx->sym.symKey;
			keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
			keyAlgorithm = ctx->sym.symAlgor;
			
			if (ctx->sym.symAlgor == kCipher_Algorithm_AES192)
			{
				//  pad the end  (treat it like it was 256 bits)
				ZERO(&ctx->sym.symKey[24], 8);
				keyBytes = 32;
				
			}
			break;
			
		case kS4KeyType_Tweekable:
			keyBytes = ctx->tbc.keybits >> 3 ;
			keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
			keyToEncrypt = ctx->tbc.key;
			keyAlgorithm = ctx->tbc.tbcAlgor;
			break;
			
		case kS4KeyType_Share:
			keyBytes = (int)ctx->share.shareSecretLen ;
			keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
			keyToEncrypt = ctx->share.shareSecret;
			keyAlgorithm = kCipher_Algorithm_SharedKey;
			
			// we only encode block sizes of 16, 32, 48 and 64
			ASSERTERR((keyBytes % 16) == 0, kS4Err_FeatureNotAvailable);
			ASSERTERR(keyBytes <= 64, kS4Err_FeatureNotAvailable);
			
			break;
			
		case kS4KeyType_PublicKey:
			ASSERTERR(ctx->pub.isPrivate, kS4Err_FeatureNotAvailable);
			keyBytes = (int)ctx->pub.privKeyLen ;
			keyToEncrypt = ctx->pub.privKey;
			keySuiteString = cipher_algor_table((Cipher_Algorithm) ctx->pub.eccAlgor);
			keyAlgorithm = (Cipher_Algorithm) ctx->pub.eccAlgor;
			break;
			
		default:
			RETERR(kS4Err_BadParams);
			break;
	}
	
	err = sKEY_HASH(keyToEncrypt, keyBytes, ctx->type,
						 keyAlgorithm, keyHash, kS4KeyESK_HashBytes ); CKERR;
	
	g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
	
#if DEBUG
	yajl_gen_config(g, yajl_gen_beautify, 1);
#else
	yajl_gen_config(g, yajl_gen_beautify, 0);
	
#endif
	yajl_gen_config(g, yajl_gen_validate_utf8, 1);
	stat = yajl_gen_map_open(g);CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)encodingPropString, strlen(encodingPropString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(keyHash, kS4KeyESK_HashBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	// calculate the hash
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
		case kS4KeyType_Tweekable:
			break;
			
		case kS4KeyType_Share:
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIndex, strlen(kS4KeyProp_ShareIndex)) ; CKYJAL;
			sprintf((char *)tempBuf, "%d", ctx->share.xCoordinate);
			stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
			sprintf((char *)tempBuf, "%d", ctx->share.threshold);
			stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareHash, strlen(kS4KeyProp_ShareHash)) ; CKYJAL;
			tempLen = sizeof(tempBuf);
			base64_encode(ctx->share.shareOwner, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
			stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
			break;
			
		case kS4KeyType_PublicKey:
		{
			size_t              keyIDLen = 0;
			
			err = ECC_PubKeyHash(ctx->pub.ecc, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
			
			stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeyID, strlen(kS4KeyProp_KeyID)) ; CKYJAL;
			tempLen = sizeof(tempBuf);
			base64_encode(keyID, keyIDLen, tempBuf, &tempLen);
			stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
		}
			break;
			
		default:
			break;
	}
	
	
	// create the encyptd payload.
	if(ctx->type == kS4KeyType_PublicKey)
	{
		uint8_t *CT = NULL;
		size_t CTLen = 0;
		
		stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_PrivKey, strlen(kS4KeyProp_PrivKey)) ; CKYJAL;
		tempLen = sizeof(tempBuf);
		
		// the private key is CBC encrypted to the unlocking key, we pad and use the keyID as the IV.
		err =  CBC_EncryptPAD (encyptAlgor,unlockingKey, keyID, keyToEncrypt, keyBytes, &CT, &CTLen); CKERR;
		base64_encode(CT, CTLen, tempBuf, &tempLen);
		XFREE(CT);
	}
	else
	{
		stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
		tempLen = sizeof(tempBuf);
		
		uint8_t encrypted_key[128] = {0};
		err =  ECB_Encrypt(encyptAlgor, unlockingKey,
								 keyToEncrypt, keyBytes,
								 encrypted_key,keyBytes); CKERR;
		base64_encode(encrypted_key, keyBytes, tempBuf, &tempLen);
	}
	
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	err = sGenPropStrings(ctx->propList, g); CKERR;
	err = sGenSignablePropString(ctx, g); CKERR;
	err = sGenSignatureStrings(ctx, g); CKERR;
	
	stat = yajl_gen_map_close(g); CKYJAL;
	stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
	
	
	outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
	memcpy(outBuf, yajlBuf, yajlLen);
	outBuf[yajlLen] = 0;
	
	*outData = outBuf;
	
	if(outSize)
		*outSize = yajlLen;
	
done:
	if(IsntNull(g))
		yajl_gen_free(g);
	
	return err;
	
}


EXPORT_FUNCTION S4Err S4Key_SerializePubKey(S4KeyContextRef  ctx,
														  uint8_t          **outData,
														  size_t           *outSize)
{
	S4Err           err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	uint8_t             *yajlBuf = NULL;
	size_t              yajlLen = 0;
	yajl_gen            g = NULL;
	
	uint8_t             tempBuf[1024];
	size_t              tempLen;
	uint8_t             *outBuf = NULL;
	
	uint8_t             keyID[kS4Key_KeyIDBytes];
	size_t              keyIDLen = 0;
	
	char*               keySuiteString = "Invalid";
	
	yajl_alloc_funcs allocFuncs = {
		yajlMalloc,
		yajlRealloc,
		yajlFree,
		(void *) NULL
	};
	
	
	validateS4KeyContext(ctx);
	ValidateParam(outData);
	
	
	switch (ctx->type)
	{
		case kS4KeyType_PublicKey:
			
			err = ECC_PubKeyHash(ctx->pub.ecc, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
			
			switch (ctx->pub.eccAlgor)
		{
			case kECC_Algorithm_ECC384:
				keySuiteString =  K_KEYSUITE_ECC384;
				break;
				
			case kECC_Algorithm_Curve41417:
				keySuiteString =  K_KEYSUITE_ECC414;
				
				break;
				
			default:
				RETERR(kS4Err_BadParams);
				
				break;
		}
			break;
			
		default:
			RETERR(kS4Err_BadParams);
			break;
			
	}
	
	g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
	
#if DEBUG
	yajl_gen_config(g, yajl_gen_beautify, 1);
#else
	yajl_gen_config(g, yajl_gen_beautify, 0);
	
#endif
	yajl_gen_config(g, yajl_gen_validate_utf8, 1);
	stat = yajl_gen_map_open(g);CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeyID, strlen(kS4KeyProp_KeyID)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(keyID, keyIDLen, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_PubKey, strlen(kS4KeyProp_PubKey)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(ctx->pub.pubKey, ctx->pub.pubKeyLen, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	err = sGenPropStrings(ctx->propList, g); CKERR;
	err = sGenSignablePropString(ctx, g); CKERR;
	err = sGenSignatureStrings(ctx, g); CKERR;
	
	stat = yajl_gen_map_close(g); CKYJAL;
	stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
	
	
	outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
	memcpy(outBuf, yajlBuf, yajlLen);
	outBuf[yajlLen] = 0;
	
	*outData = outBuf;
	
	if(outSize)
		*outSize = yajlLen;
	
done:
	if(IsntNull(g))
		yajl_gen_free(g);
	
	return err;
	
}

#ifdef __clang__
#pragma mark - import key.
#endif


#define _base(x) ((x >= '0' && x <= '9') ? '0' : \
(x >= 'a' && x <= 'f') ? 'a' - 10 : \
(x >= 'A' && x <= 'F') ? 'A' - 10 : \
'\255')
#define HEXOF(x) (x - _base(x))


enum S4Key_JSON_Type_
{
	S4Key_JSON_Type_Invalid ,
	S4Key_JSON_Type_BASE ,
	S4Key_JSON_Type_VERSION,
	S4Key_JSON_Type_KEYALGORITHM,
	S4Key_JSON_Type_HASHALGORITHM,
	
	S4Key_JSON_Type_ROUNDS,
	S4Key_JSON_Type_SALT,
	S4Key_JSON_Type_P2K_PARAMS,
	S4Key_JSON_Type_ENCODING,
	S4Key_JSON_Type_MAC,
	S4Key_JSON_Type_ENCRYPTED_SYMKEY,
	S4Key_JSON_Type_KEYID,
	S4Key_JSON_Type_SYMKEY,
	
	S4Key_JSON_Type_SHAREHASH,
	S4Key_JSON_Type_THRESHOLD,
	S4Key_JSON_Type_SHAREINDEX,
	
	S4Key_JSON_Type_PUBKEY,
	S4Key_JSON_Type_PRIVKEY,
	
	S4Key_JSON_Type_PROPERTY,
	
	S4Key_JSON_Type_SIGNATURES,
	S4Key_JSON_Type_SIGNATURE,
	S4Key_JSON_Type_SIGNEDBY,
	S4Key_JSON_Type_SIGNDATE,
	S4Key_JSON_Type_SIGEXPIRETIME,
	S4Key_JSON_Type_SIGNED_PROPS,
	S4Key_JSON_Type_SIGNABLE_PROPS,
	S4Key_JSON_Type_SIGID,
	
	S4Key_JSON_Type_ESK,
	S4Key_JSON_Type_IV,
	S4Key_JSON_Type_ENCODED_OBJECT,
	
	ENUM_FORCE( S4Key_JSON_Type_ )
};
ENUM_TYPEDEF( S4Key_JSON_Type_, S4Key_JSON_Type   );

struct S4KeyJSONcontext
{
	uint8_t             version;    // message version
	//    S4KeyContext       key;        // used for decoding messages
	
	S4KeyContext        *keys;     // pointer to array of S4KeyContext
	int                 index;      // current key
	
	int                 level;
	
	S4Key_JSON_Type jType[8];
	void*           jItem;
	size_t*         jItemSize;
	uint8_t*        jTag;
	
	S4KeySig        currentSigItem;             // temp space used for parsing signatures
	
	char**          currentSignablePropList; // used for importing current key
	
};

typedef struct S4KeyJSONcontext S4KeyJSONcontext;

// setup the keytype based on encoding string
static S4Err sParseEncodingString(const unsigned char * stringVal,  size_t stringLen,
											 S4KeyContextRef keyP)
{
	S4Err	err = kS4Err_NoErr;
	bool 	valid = false;
	
	if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_PBKDF2_2FISH256, strlen(kS4KeyProp_Encoding_PBKDF2_2FISH256)))
	{
		keyP->type = kS4KeyType_PBKDF2;
		keyP->pbkdf2.encyptAlgor = kCipher_Algorithm_2FISH256;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_PBKDF2_AES256, strlen(kS4KeyProp_Encoding_PBKDF2_AES256)))
	{
		keyP->type = kS4KeyType_PBKDF2;
		keyP->pbkdf2.encyptAlgor = kCipher_Algorithm_AES256;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_PUBKEY_ECC384, strlen(kS4KeyProp_Encoding_PUBKEY_ECC384)))
	{
		keyP->type = kS4KeyType_PublicEncrypted;
		keyP->publicKeyEncoded.keysize = 384;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_PUBKEY_ECC414, strlen(kS4KeyProp_Encoding_PUBKEY_ECC414)))
	{
		keyP->type = kS4KeyType_PublicEncrypted;
		keyP->publicKeyEncoded.keysize = 414;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_SYM_2FISH256, strlen(kS4KeyProp_Encoding_SYM_2FISH256)))
	{
		keyP->type = kS4KeyType_SymmetricEncrypted;
		keyP->symKeyEncoded.encryptingAlgor = kCipher_Algorithm_2FISH256;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_SYM_AES128, strlen(kS4KeyProp_Encoding_SYM_AES128)))
	{
		keyP->type = kS4KeyType_SymmetricEncrypted;
		keyP->symKeyEncoded.encryptingAlgor = kCipher_Algorithm_AES128;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_SYM_AES256, strlen(kS4KeyProp_Encoding_SYM_AES256)))
	{
		keyP->type = kS4KeyType_SymmetricEncrypted;
		keyP->symKeyEncoded.encryptingAlgor = kCipher_Algorithm_AES256;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_Signature, strlen(kS4KeyProp_Encoding_Signature)))
	{
		keyP->type = kS4KeyType_Signature;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_P2K, strlen(kS4KeyProp_Encoding_P2K)))
	{
		keyP->type = kS4KeyType_P2K_ESK;
		keyP->esk.objectAlgor = kCipher_Algorithm_Unknown;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_SPLIT_AES256, strlen(kS4KeyProp_Encoding_SPLIT_AES256)))
	{
		keyP->type = kS4KeyType_Share_ESK;
		keyP->esk.cipherAlgor = kCipher_Algorithm_AES256;
		valid = 1;
	}
	else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_SPLIT_2FISH256, strlen(kS4KeyProp_Encoding_SPLIT_2FISH256)))
	{
		keyP->type = kS4KeyType_Share_ESK;
		keyP->esk.cipherAlgor = kCipher_Algorithm_2FISH256;
		valid = 1;
	}
	
	if(!valid)
		err = kS4Err_BadParams;
	
	return err;
	
}

static S4Err sParseKeySuiteString(const unsigned char * stringVal,  size_t stringLen,
											 S4KeyType *keyTypeOut, Cipher_Algorithm *algorithmOut)
{
	
	S4Err       err = kS4Err_NoErr;
	S4KeyType   keyType = kS4KeyType_Invalid;
	int32_t     algorithm = kEnumMaxValue;
	
	if(CMP2(stringVal, stringLen, K_KEYSUITE_AES128, strlen(K_KEYSUITE_AES128)))
	{
		keyType  = kS4KeyType_Symmetric;
		algorithm = kCipher_Algorithm_AES128;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_AES192, strlen(K_KEYSUITE_AES192)))
	{
		keyType  = kS4KeyType_Symmetric;
		algorithm = kCipher_Algorithm_AES192;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_AES256, strlen(K_KEYSUITE_AES256)))
	{
		keyType  = kS4KeyType_Symmetric;
		algorithm = kCipher_Algorithm_AES256;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_2FISH256, strlen(K_KEYSUITE_2FISH256)))
	{
		keyType  = kS4KeyType_Symmetric;
		algorithm = kCipher_Algorithm_2FISH256;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH256, strlen(K_KEYSUITE_3FISH256)))
	{
		keyType  = kS4KeyType_Tweekable;
		algorithm = kCipher_Algorithm_3FISH256;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH512, strlen(K_KEYSUITE_3FISH512)))
	{
		keyType  = kS4KeyType_Tweekable;
		algorithm = kCipher_Algorithm_3FISH512;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH1024, strlen(K_KEYSUITE_3FISH1024)))
	{
		keyType  = kS4KeyType_Tweekable;
		algorithm = kCipher_Algorithm_3FISH1024;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_SPLIT, strlen(K_KEYSUITE_SPLIT)))
	{
		keyType  = kS4KeyType_Share;
		algorithm = kCipher_Algorithm_SharedKey;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_ECC384, strlen(K_KEYSUITE_ECC384)))
	{
		keyType  = kS4KeyType_PublicKey;
		algorithm = kCipher_Algorithm_ECC384;
	}
	else if(CMP2(stringVal, stringLen, K_KEYSUITE_ECC414, strlen(K_KEYSUITE_ECC414)))
	{
		keyType  = kS4KeyType_PublicKey;
		algorithm = kCipher_Algorithm_ECC414;
	}
	
	if(keyType == kS4KeyType_Invalid)
		err = kS4Err_CorruptData;
	
	if(keyTypeOut)
		*keyTypeOut = keyType;
	
	if(algorithmOut)
		*algorithmOut = algorithm;
	
	return err;
}


static void sAppendSigProp(S4KeySig* sig,const char * str, size_t len)
{
	
	int offset = 0;
	
	if(!sig->propNameList)
	{
		sig->propNameList = XMALLOC(sizeof(char*) * 2);  // do we ever check for memory anymore?
	}
	else
	{
		for(offset = 0; sig->propNameList[offset] != NULL; offset++);
		sig->propNameList = XREALLOC(sig->propNameList, sizeof(char*) * (offset + 2));
	}
	
	char* name = XMALLOC(len +1);
	COPY(str, name, len);
	name[len] = 0;
	sig->propNameList[offset++] = name;
	sig->propNameList[offset] = NULL;
}

// same as S4Key_DeserializeKeys but this will return error if one than one key wa found.

EXPORT_FUNCTION S4Err S4Key_DeserializeKey( uint8_t *inData, size_t inLen,
														 S4KeyContextRef    *ctxOut)
{
	S4Err   err = kS4Err_NoErr;
	
	S4KeyContextRef  *importCtx = NULL;
	size_t      keyCount = 0;
	
	ValidateParam(ctxOut);
	
	err = S4Key_DeserializeKeys(inData, inLen, &keyCount, &importCtx ); CKERR;
	ASSERTERR(keyCount == 1 ,  kS4Err_BadParams);
	
	*ctxOut = importCtx[0];
	XFREE(importCtx);
	
done:
	
	if(IsS4Err(err))
	{
		if(importCtx)
		{
			for(int i = 0; i< keyCount; i++)
			{
				if(S4KeyContextRefIsValid(importCtx[i]))
				{
					S4Key_Free(importCtx[i]);
				}
			}
			
			XFREE(importCtx);
		}
	}
	
	return err;
	
}


EXPORT_FUNCTION S4Err S4Key_DeserializeKeys( uint8_t *inData, size_t inLen,
														  size_t           *outCount,
														  S4KeyContextRef  *ctxArray[])
{
	S4Err               	err = kS4Err_NoErr;
	
	JSONParseContext* 		pctx = NULL;
	S4KeyContextRef	*keys 	= NULL;
	
	ValidateParam(inData);
	
	// parse the JSON
	err = sParseJSON(inData, inLen, &pctx);
	CKERR;
	
	if(pctx->dictCount)
	{
		keys = XMALLOC(sizeof(S4KeyContextRef) *  pctx->dictCount);
		
		// process  each dictionary we imported
		for(int dictNum = 0; dictNum < pctx->dictCount; dictNum++)
		{
			err = sJSONParseDictionaryToS4Key(pctx, dictNum, &keys[dictNum]); CKERR;
		}
	}
	
	
	if(outCount)
	{
		*outCount = pctx->dictCount;
	}
	
	if(ctxArray)
	{
		if(!(pctx->dictCount))
			*ctxArray = NULL;
		else
			*ctxArray = keys;
	}
done:
	
	sFreeParseContext(pctx);
	
	return err;
	
}

#ifdef __clang__
#pragma mark - verify passphrase.
#endif

EXPORT_FUNCTION S4Err S4Key_VerifyPassPhrase(   S4KeyContextRef  ctx,
															const uint8_t    *passphrase,
															size_t           passphraseLen)
{
	S4Err           err = kS4Err_NoErr;
	uint8_t         unlocking_key[32] = {0};
	
	size_t           expectedKeyBytes = 0;
	
	uint8_t         keyHash[kS4KeyESK_HashBytes] = {0};
	
	validateS4KeyContext(ctx);
	ValidateParam(passphrase);
	
	ValidateParam(ctx->type == kS4KeyType_PBKDF2);
	
	if(ctx->type == kS4KeyType_PBKDF2)
	{
		if(ctx->pbkdf2.keyAlgorithmType == kS4KeyType_Symmetric)
		{
			expectedKeyBytes = sGetKeyLength(kS4KeyType_Symmetric, ctx->pbkdf2.cipherAlgor);
			
		}
		else  if(ctx->pbkdf2.keyAlgorithmType == kS4KeyType_Tweekable)
		{
			expectedKeyBytes = sGetKeyLength(kS4KeyType_Tweekable, ctx->pbkdf2.cipherAlgor);
		}
		
		err = PASS_TO_KEY(passphrase, passphraseLen,
								ctx->pbkdf2.salt, sizeof(ctx->pbkdf2.salt), ctx->pbkdf2.rounds,
								unlocking_key, sizeof(unlocking_key)); CKERR;
		
		
		err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
									  ctx->pbkdf2.salt, sizeof(ctx->pbkdf2.salt), ctx->pbkdf2.rounds,
									  keyHash, kS4KeyESK_HashBytes); CKERR;
		
		ASSERTERR(CMP(keyHash, ctx->pbkdf2.keyHash, kS4KeyESK_HashBytes), kS4Err_BadIntegrity)
		
	}
	
	else
		RETERR(kS4Err_BadParams);
	
done:
	
	ZERO(unlocking_key, sizeof(unlocking_key));
	
	return err;
	
}

EXPORT_FUNCTION S4Err S4Key_DecryptFromPassPhrase( S4KeyContextRef  passCtx,
																  const uint8_t    *passphrase,
																  size_t           passphraseLen,
																  S4KeyContextRef       *symCtx)
{
	S4Err           err = kS4Err_NoErr;
	S4KeyContext*   keyCTX = NULL;
	
	Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
	uint8_t             unlocking_key[32] = {0};
	size_t             	expectedKeyBytes = 0;
	size_t           	keyBytes = 0;
	
	uint8_t             decrypted_key[128] = {0};
	uint8_t             keyHash[kS4KeyESK_HashBytes] = {0};
	
	validateS4KeyContext(passCtx);
	ValidateParam(passphrase);
	
	ValidateParam(passCtx->type == kS4KeyType_PBKDF2);
	
	if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Symmetric)
	{
		expectedKeyBytes = sGetKeyLength(kS4KeyType_Symmetric, passCtx->pbkdf2.cipherAlgor);
		
		switch (passCtx->pbkdf2.cipherAlgor)
		{
			case kCipher_Algorithm_2FISH256:
				encyptAlgor = kCipher_Algorithm_2FISH256;
				break;
				
			case kCipher_Algorithm_AES192:
				encyptAlgor = kCipher_Algorithm_AES256;
				break;
				
			default:
				encyptAlgor = kCipher_Algorithm_AES256;
				break;
		}
		
	}
	else  if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Tweekable)
	{
		encyptAlgor = kCipher_Algorithm_2FISH256;
		
		expectedKeyBytes = sGetKeyLength(kS4KeyType_Tweekable, passCtx->pbkdf2.cipherAlgor);
	}
	else
		RETERR(kS4Err_BadParams);
	
	
	keyBytes = expectedKeyBytes;
	
	err = PASS_TO_KEY(passphrase, passphraseLen,
							passCtx->pbkdf2.salt, sizeof(passCtx->pbkdf2.salt), passCtx->pbkdf2.rounds,
							unlocking_key, sizeof(unlocking_key)); CKERR;
	
	err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
								  passCtx->pbkdf2.salt, sizeof(passCtx->pbkdf2.salt), passCtx->pbkdf2.rounds,
								  keyHash, kS4KeyESK_HashBytes); CKERR;
	
	if(!CMP(keyHash, passCtx->pbkdf2.keyHash, kS4KeyESK_HashBytes))
		RETERR (kS4Err_BadIntegrity);
	
	
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	
	if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Symmetric)
	{
		size_t bytesToDecrypt = keyBytes == 24?32:keyBytes;
		keyCTX->type  = kS4KeyType_Symmetric;
		keyCTX->sym.symAlgor = passCtx->pbkdf2.cipherAlgor;
		keyCTX->sym.keylen = expectedKeyBytes;
		
		err =  ECB_Decrypt(encyptAlgor, unlocking_key, passCtx->pbkdf2.encrypted,
								 bytesToDecrypt, decrypted_key, bytesToDecrypt); CKERR;
		
		COPY(decrypted_key, keyCTX->sym.symKey, bytesToDecrypt);
		
	}
	else  if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Tweekable)
	{
		keyCTX->type  = kS4KeyType_Tweekable;
		keyCTX->tbc.tbcAlgor = passCtx->pbkdf2.cipherAlgor;
		keyCTX->tbc.keybits = keyBytes << 3;
		
		err =  ECB_Decrypt(encyptAlgor, unlocking_key, passCtx->pbkdf2.encrypted,
								 keyBytes,  decrypted_key, keyBytes); CKERR;
		
		memcpy(keyCTX->tbc.key, decrypted_key, keyBytes);
		
		//      Skein_Get64_LSB_First(keyCTX->tbc.key, decrypted_key, keyBytes >>2);   /* bytes to words */
	}
	
	
	sClonePropertiesLists(passCtx->propList, &keyCTX->propList);
	sCloneSignatures(passCtx, keyCTX);
	
	*symCtx = keyCTX;
	
done:
	if(IsS4Err(err))
	{
		if(IsntNull(keyCTX))
		{
			XFREE(keyCTX);
		}
	}
	
	ZERO(decrypted_key, sizeof(decrypted_key));
	ZERO(unlocking_key, sizeof(unlocking_key));
	
	return err;
	
}

EXPORT_FUNCTION S4Err S4Key_DecryptFromS4Key( S4KeyContextRef      encodedCtx,
															S4KeyContextRef       passKeyCtx,
															S4KeyContextRef       *outKeyCtx)
{
	S4Err               err = kS4Err_NoErr;
	S4KeyContext*       keyCTX = NULL;
	
	int                 encyptAlgor = kCipher_Algorithm_Invalid;
	void*               keyToDecrypt = NULL;
	
	uint8_t             decrypted_key[128] = {0};
	size_t              decryptedLen = 0;
	
	uint8_t*            decrypted_privKey = NULL;
	size_t              decrypted_privKeyLen = 0;
	
	uint8_t*            unlockingKey    = NULL;
	uint8_t             keyHash[kS4KeyESK_HashBytes] = {0};
	
	validateS4KeyContext(encodedCtx);
	validateS4KeyContext(passKeyCtx);
	ValidateParam(outKeyCtx);
	
	if(encodedCtx->type == kS4KeyType_PublicEncrypted )
	{
		return sDecryptFromPubKey(encodedCtx, passKeyCtx->pub.ecc, outKeyCtx);
	}
	
	ValidateParam(encodedCtx->type == kS4KeyType_SymmetricEncrypted);
	
	if(encodedCtx->symKeyEncoded.keyAlgorithmType == kS4KeyType_Symmetric)
	{
		decryptedLen = sGetKeyLength(kS4KeyType_Symmetric, encodedCtx->symKeyEncoded.cipherAlgor);
		keyToDecrypt = encodedCtx->symKeyEncoded.encrypted;
		encyptAlgor = encodedCtx->symKeyEncoded.encryptingAlgor;
		
	}
	else  if(encodedCtx->symKeyEncoded.keyAlgorithmType == kS4KeyType_Tweekable)
	{
		decryptedLen = sGetKeyLength(kS4KeyType_Tweekable, encodedCtx->symKeyEncoded.cipherAlgor);
		keyToDecrypt = encodedCtx->symKeyEncoded.encrypted;
		encyptAlgor = encodedCtx->symKeyEncoded.encryptingAlgor;
	}
	else  if(encodedCtx->symKeyEncoded.keyAlgorithmType == kS4KeyType_PublicKey)
	{
		keyToDecrypt = encodedCtx->symKeyEncoded.encrypted;
		encyptAlgor = encodedCtx->symKeyEncoded.encryptingAlgor;
	}
	else
	{
		RETERR(kS4Err_FeatureNotAvailable);
	}
	
	unlockingKey = passKeyCtx->sym.symKey;
	ASSERTERR(encyptAlgor == passKeyCtx->sym.symAlgor, kS4Err_BadParams)
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	
	if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Symmetric)
	{
		keyCTX->type  = kS4KeyType_Symmetric;
		keyCTX->sym.symAlgor = encodedCtx->symKeyEncoded.cipherAlgor;
		keyCTX->sym.keylen = decryptedLen;
		
		if(encodedCtx->symKeyEncoded.cipherAlgor  ==  kCipher_Algorithm_AES192)
		{
			//  it's padded at the end  (treat it like it was 256 bits)
			decryptedLen = 32;
		}
		
		err =  ECB_Decrypt(encyptAlgor, unlockingKey,
								 keyToDecrypt, decryptedLen,
								 decrypted_key, decryptedLen); CKERR;
		
		COPY(decrypted_key, keyCTX->sym.symKey, decryptedLen);
		
		// check integrity of decypted value against the MAC
		err = sKEY_HASH(decrypted_key, decryptedLen, keyCTX->type,  keyCTX->sym.symAlgor,
							 keyHash, kS4KeyESK_HashBytes ); CKERR;
		
	}
	else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Tweekable)
	{
		keyCTX->type  = kS4KeyType_Tweekable;
		keyCTX->tbc.tbcAlgor = encodedCtx->symKeyEncoded.cipherAlgor;
		keyCTX->tbc.keybits = decryptedLen << 3;
		
		err =  ECB_Decrypt(encyptAlgor, unlockingKey,
								 keyToDecrypt, decryptedLen,
								 decrypted_key, decryptedLen); CKERR;
		
		memcpy(keyCTX->tbc.key, decrypted_key, decryptedLen);
		//        Skein_Get64_LSB_First(keyCTX->tbc.key, decrypted_key, decryptedLen >>2);   /* bytes to words */
		
		// check integrity of decypted value against the MAC
		err = sKEY_HASH(decrypted_key, decryptedLen, keyCTX->type,  keyCTX->sym.symAlgor,
							 keyHash, kS4KeyESK_HashBytes ); CKERR;
	}
	else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_PublicKey)
	{
		
		keyCTX->type  = kS4KeyType_PublicKey;
		keyCTX->pub.eccAlgor = (ECC_Algorithm) encodedCtx->symKeyEncoded.cipherAlgor;
		
		// the private key is CBC encrypted to the unlocking key, we pad and use the keyID as the IV.
		err =  CBC_DecryptPAD (encyptAlgor,unlockingKey,
									  encodedCtx->symKeyEncoded.keyID,
									  encodedCtx->symKeyEncoded.encrypted, encodedCtx->symKeyEncoded.encryptedLen,
									  &decrypted_privKey, &decrypted_privKeyLen); CKERR;
		
		err = ECC_Import( decrypted_privKey, decrypted_privKeyLen,
							  &keyCTX->pub.ecc); CKERR;
		err = sCalculateECCData(keyCTX); CKERR;
		
		// check integrity of decypted value against the MAC
		err = sKEY_HASH(decrypted_privKey, decrypted_privKeyLen, keyCTX->type,
							 (Cipher_Algorithm) keyCTX->pub.eccAlgor,
							 keyHash, kS4KeyESK_HashBytes ); CKERR;
		
	}
	
	ASSERTERR( CMP(keyHash, encodedCtx->symKeyEncoded.keyHash, kS4KeyESK_HashBytes),
				 kS4Err_BadIntegrity)
	
	sClonePropertiesLists(encodedCtx->propList, &keyCTX->propList);
	sCloneSignatures(encodedCtx, keyCTX);
	
	*outKeyCtx = keyCTX;
	
done:
	
	if(IsntNull(decrypted_privKey))
	{
		ZERO(decrypted_privKey, decrypted_privKeyLen);
		XFREE(decrypted_privKey);
	}
	
	if(IsS4Err(err))
	{
		if(IsntNull(keyCTX))
		{
			XFREE(keyCTX);
		}
	}
	
	ZERO(decrypted_key, sizeof(decrypted_key));
	
	return err;
	
}


#ifdef __clang__
#pragma mark - Share key generation.
#endif

EXPORT_FUNCTION S4Err S4Key_SerializeToShares(S4KeyContextRef       ctx,
															 uint32_t              totalShares,
															 uint32_t              threshold,
															 S4KeyContextRef    	*sharesArray[],
															 uint8_t               **outAllocData,
															 size_t                *outSize)
{
	const size_t kMaxCipherSize  = 32;
	
	S4Err               err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	uint8_t             *yajlBuf = NULL;
	size_t              yajlLen = 0;
	yajl_gen            g = NULL;
	
	uint8_t             tempBuf[1024];
	size_t              tempLen;
	uint8_t             *outBuf = NULL;
	
	S4SharesContextRef   shareCTX = NULL;
	S4KeyContextRef		 *shares 	= NULL;
	
	int                 i;
	
	size_t              cipherSizeInBits = 0;
	size_t              cipherSizeInBytes = 0;
	Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
	CBC_ContextRef      cbc 			= kInvalidCBC_ContextRef;
	
	Cipher_Algorithm    objectAlgor = kCipher_Algorithm_Invalid;
	
	size_t              keyBytes = 0;
	uint8_t        		unlockingKey[kMaxCipherSize] = {0};	// KEY THAT IS SPLIT
	uint8_t      		IV[kMaxCipherSize] = {0};
	uint8_t             *ESK= NULL ;	//	session Key encrypted to unlockingKey
	
	uint8_t             keyHash[kS4KeyESK_HashBytes] = {0};
	
	void*               keyToEncrypt = NULL;
	
	const char*           encodingPropString = "Invalid";
	const char*           keySuiteString = "Invalid";
	
	yajl_alloc_funcs allocFuncs = {
		yajlMalloc,
		yajlRealloc,
		yajlFree,
		(void *) NULL
	};
	
	
	validateS4KeyContext(ctx);
	ValidateParam(sharesArray);
	ValidateParam(outAllocData);
	
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
			keyBytes = ctx->sym.keylen ;
			keyToEncrypt = ctx->sym.symKey;
			
			switch (ctx->sym.symAlgor) {
				case kCipher_Algorithm_2FISH256:
					encyptAlgor = kCipher_Algorithm_2FISH256;
					encodingPropString =  kS4KeyProp_Encoding_SPLIT_2FISH256;
					break;
					
				case kCipher_Algorithm_AES192:
					encyptAlgor = kCipher_Algorithm_AES256;
					encodingPropString =  kS4KeyProp_Encoding_SPLIT_AES256;
					
					//  pad the end  (treat it like it was 256 bits)
					ZERO(&ctx->sym.symKey[24], 8);
					keyBytes = 32;
					break;
					
				default:
					encyptAlgor = kCipher_Algorithm_AES256;
					encodingPropString =  kS4KeyProp_Encoding_SPLIT_AES256;
					break;
			}
			objectAlgor = ctx->sym.symAlgor;
			keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
			break;
			
		case kS4KeyType_Tweekable:
			keyBytes = ctx->tbc.keybits >> 3 ;
			encyptAlgor = kCipher_Algorithm_2FISH256;
			keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
			encodingPropString =  kS4KeyProp_Encoding_SPLIT_2FISH256;
			keyToEncrypt = ctx->tbc.key;
			objectAlgor = ctx->tbc.tbcAlgor;
			break;
			
			
		default:
			RETERR(kS4Err_BadParams);
			break;
	}
	
	// create a random session key
	err = Cipher_GetKeySize(encyptAlgor, &cipherSizeInBits); CKERR;
	cipherSizeInBytes = cipherSizeInBits / 8;
	ValidateParam(cipherSizeInBytes <= kMaxCipherSize);
	
	ESK = XMALLOC(keyBytes);
	err = RNG_GetBytes( unlockingKey, cipherSizeInBytes ); CKERR;
	err = RNG_GetBytes(IV,cipherSizeInBytes); CKERR;
	
	err = CBC_Init(encyptAlgor, unlockingKey, IV,  &cbc);CKERR;
	err = CBC_Encrypt(cbc, keyToEncrypt, keyBytes, ESK, keyBytes); CKERR;
	
	// create the share itself
	err = S4Shares_New(unlockingKey, cipherSizeInBytes, totalShares, threshold, &shareCTX); CKERR;
	
	// create am array of S4KeyContexts containing the share Info
	shares = XMALLOC(sizeof(S4KeyContextRef) *  totalShares);
	for(int i = 0; i < totalShares; i++)
	{
		S4SharesPartContextRef shareInfo = kInvalidS4SharesPartContextRef;
		err = S4Shares_GetPart(shareCTX, i, &shareInfo); CKERR;
		err = sConvertShareToKey( shareInfo, &shares[i]); CKERR;
		S4SharesPart_Free(shareInfo);
	}
	
	err = sKEY_HASH(keyToEncrypt, keyBytes, ctx->type,
						 objectAlgor, keyHash, kS4KeyESK_HashBytes ); CKERR;
	
	g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
	
#if DEBUG
	yajl_gen_config(g, yajl_gen_beautify, 1);
#else
	yajl_gen_config(g, yajl_gen_beautify, 0);
	
#endif
	yajl_gen_config(g, yajl_gen_validate_utf8, 1);
	stat = yajl_gen_map_open(g);CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)encodingPropString, strlen(encodingPropString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(keyHash, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", threshold);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareTotal, strlen(kS4KeyProp_ShareTotal)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", totalShares);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareOwner, strlen(kS4KeyProp_ShareOwner)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(shareCTX->shareID, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	//	kS4KeyProp_IV
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_IV, strlen(kS4KeyProp_IV)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(IV, cipherSizeInBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(ESK, keyBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIDs, strlen(kS4KeyProp_ShareIDs)) ; CKYJAL;
	stat = yajl_gen_array_open(g); CKYJAL;
	for(i = 0; i < totalShares; i++ )
	{
		S4SharesPartContext*   shareInfo = NULL;
		err = S4Shares_GetPart(shareCTX, i, &shareInfo); CKERR;
		tempLen = sizeof(tempBuf);
		base64_encode(shareInfo->shareID, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
		stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
		
		if(shareInfo)
			XFREE(shareInfo);
	}
	stat = yajl_gen_array_close(g); CKYJAL;
	
	err = sGenPropStrings(ctx->propList, g); CKERR;
	err = sGenSignablePropString(ctx, g); CKERR;
	err = sGenSignatureStrings(ctx, g); CKERR;
	
	stat = yajl_gen_map_close(g); CKYJAL;
	stat = yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
	
	outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
	memcpy(outBuf, yajlBuf, yajlLen);
	outBuf[yajlLen] = 0;
	
	*outAllocData = outBuf;
	*sharesArray = shares;
	
	if(outSize)
		*outSize = yajlLen;
done:
	
	
	if(IsS4Err(err))
	{
		if(S4SharesContextRefIsValid(shareCTX))
			S4Shares_Free(shareCTX);
	}
	
	ZERO(unlockingKey, sizeof(unlockingKey));
	
	if(ESK)
		XFREE(ESK);
	
	if(cbc)
		CBC_Free(cbc);
	
	if(IsntNull(g))
		yajl_gen_free(g);
	
	return err;
}


EXPORT_FUNCTION S4Err S4Key_SerializeSharePart(S4KeyContextRef   	ctx,
															  uint8_t               **outData,
															  size_t                *outSize)
{
	S4Err               err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	uint8_t             *yajlBuf = NULL;
	size_t              yajlLen = 0;
	yajl_gen            g = NULL;
	
	uint8_t             tempBuf[1024];
	size_t              tempLen;
	uint8_t             *outBuf = NULL;
	const char*     	keySuiteString = "Invalid";
	
	yajl_alloc_funcs allocFuncs = {
		yajlMalloc,
		yajlRealloc,
		yajlFree,
		(void *) NULL
	};
	
	validateS4KeyContext(ctx);
	
	keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
	
	g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
	
#if DEBUG
	yajl_gen_config(g, yajl_gen_beautify, 1);
#else
	yajl_gen_config(g, yajl_gen_beautify, 0);
	
#endif
	yajl_gen_config(g, yajl_gen_validate_utf8, 1);
	stat = yajl_gen_map_open(g);CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareOwner, strlen(kS4KeyProp_ShareOwner)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(ctx->share.shareOwner, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareID, strlen(kS4KeyProp_ShareID)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(ctx->share.shareID, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", ctx->share.threshold);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIndex, strlen(kS4KeyProp_ShareIndex)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", ctx->share.xCoordinate);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode( ctx->share.shareSecret, ctx->share.shareSecretLen, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, tempLen) ; CKYJAL;
	
	
	err = sGenPropStrings(ctx->propList, g); CKERR;
	err = sGenSignablePropString(ctx, g); CKERR;
	err = sGenSignatureStrings(ctx, g); CKERR;
	
	stat = yajl_gen_map_close(g); CKYJAL;
	stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
	
	
	outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
	memcpy(outBuf, yajlBuf, yajlLen);
	outBuf[yajlLen] = 0;
	
	*outData = outBuf;
	
	if(outSize)
		*outSize = yajlLen;
done:
	
	
	if(IsntNull(g))
		yajl_gen_free(g);
	
	return err;
}



S4Err S4Key_RecoverKeyFromShares(   S4KeyContextRef  __S4_NONNULL shareCtx,
											S4KeyContextRef __NONNULL_ARRAY shares,
											uint32_t       	numShares,
											S4KeyContextRef __NULLABLE_REF_POINTER ctxOut)
{
	
	S4Err               err = kS4Err_NoErr;
	
	S4SharesPartContext*   shareParts = NULL;		// actual share parts
	S4SharesPartContextRef*   sharePartCtx = NULL;	// pointers into the share parts
	CBC_ContextRef 	cbc 	= kInvalidCBC_ContextRef;
	
	S4KeyContext*   keyCTX = NULL;		// new key
	
	Cipher_Algorithm	objectAlgor =  kCipher_Algorithm_Invalid;
	S4KeyType			objectType  = kS4KeyType_Invalid;
	uint8_t         	objectHash[kS4KeyESK_HashBytes] = {0};  // we use keyhash to check validity of decode
	
	size_t  	cipherSizeInBits = 0;
	size_t   	cipherSizeInBytes = 0;
	
	uint8_t     sessionKey[32];		// these are always some form of 256 bit key
	size_t      sessionKeyLen  = 0;
	
	uint8_t     *decryptedKey 	= NULL;
	size_t  	decryptedKeyLen = 0;
	
	validateS4KeyContext(shareCtx);
	ValidateParam(shares);
	
	ValidateParam(shareCtx->type == kS4KeyType_Share_ESK)
	
	err = Cipher_GetKeySize(shareCtx->esk.cipherAlgor, &cipherSizeInBits); CKERR;
	cipherSizeInBytes = cipherSizeInBits / 8;
	
	ValidateParam(shareCtx->esk.ivLen == cipherSizeInBytes)
	
	// check the shares
	for(int i = 0; i < numShares; i++)
	{
		validateS4KeyContext(shares[i]);
		ValidateParam(shares[i]->type == kS4KeyType_Share);
		
		if(!CMP(shareCtx->esk.shareOwner, shares[i]->share.shareOwner,kS4ShareInfo_HashBytes))
		{
			RETERR(kS4Err_ShareOwnerMismatch);
		}
	}
	
	if(shareCtx->esk.threshold > numShares)
		RETERR(kS4Err_NotEnoughShares);
	
	objectAlgor = shareCtx->esk.objectAlgor;
	objectType = sGetKeyType(objectAlgor);
	
	// create a S4SharesPartContext array for recombine.
	shareParts = XMALLOC(sizeof(S4SharesPartContext) * numShares); CKERR;
	ZERO(shareParts, sizeof(S4SharesPartContext) * numShares);
	
	sharePartCtx = XMALLOC(sizeof(S4SharesPartContextRef) * numShares); CKERR;
	
	// copy the parts in
	for(int i = 0; i < numShares; i++)
	{
		shareParts[i].threshold =  shares[i]->share.threshold;
		shareParts[i].xCoordinate =  shares[i]->share.xCoordinate;
		COPY(shares[i]->share.shareOwner, shareParts[i].shareOwner, kS4ShareInfo_HashBytes);
		COPY(shares[i]->share.shareSecret, shareParts[i].shareSecret, shares[i]->share.shareSecretLen);
		shareParts[i].shareSecretLen =  shares[i]->share.shareSecretLen;
		
		sharePartCtx[i] = &shareParts[i]; // copy a pointer to the parts
	}
	
	err = SHARES_CombineShareInfo(numShares, sharePartCtx,
											sessionKey, sizeof(sessionKey), &sessionKeyLen); CKERR;
	
	decryptedKeyLen = shareCtx->esk.encryptedLen;
	decryptedKey = XMALLOC(decryptedKeyLen);
	
	err = CBC_Init(shareCtx->esk.cipherAlgor, sessionKey, shareCtx->esk.iv,  &cbc);CKERR;
	err = CBC_Decrypt(cbc,
							shareCtx->esk.encrypted, decryptedKeyLen,
							decryptedKey, decryptedKeyLen); CKERR;
	
	// check the validity of the decode
	err = sKEY_HASH(decryptedKey, decryptedKeyLen,
						 objectType, objectAlgor,
						 objectHash, kS4KeyESK_HashBytes ); CKERR;
	
	ASSERTERR( CMP(objectHash, shareCtx->esk.keyHash, kS4KeyESK_HashBytes),
				 kS4Err_BadIntegrity)
	
	// create a key with the data
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	keyCTX->type = objectType;
	
	if(keyCTX->type == kS4KeyType_Symmetric)
	{
		keyCTX->sym.symAlgor = objectAlgor;
		size_t  expectedKeyBytes = sGetKeyLength(kS4KeyType_Symmetric, shareCtx->esk.objectAlgor);
		keyCTX->sym.keylen = expectedKeyBytes;
		COPY(decryptedKey, keyCTX->sym.symKey, expectedKeyBytes);
	}
	else  if(keyCTX->type == kS4KeyType_Tweekable)
	{
		keyCTX->tbc.tbcAlgor = objectAlgor;
		keyCTX->tbc.keybits = decryptedKeyLen << 3;
		COPY(decryptedKey, keyCTX->tbc.key, decryptedKeyLen);
	}
	
	sClonePropertiesLists(shareCtx->propList, &keyCTX->propList);
	sCloneSignatures(shareCtx, keyCTX);
	
	if(ctxOut)
	{
		*ctxOut = keyCTX;
	}
done:
	
	if(cbc)
		CBC_Free(cbc);
	
	if(decryptedKey)
	{
		ZERO(decryptedKey, decryptedKeyLen);
		XFREE(decryptedKey);
	}
	
	if(sharePartCtx)
		XFREE(sharePartCtx);
	
	if(shareParts)
	{
		ZERO(shareParts, sizeof(S4SharesPartContext) * numShares);
		XFREE(shareParts);
	}
	
	return err;
}


#ifdef __clang__
#pragma mark - Public Key Signatures.
#endif

EXPORT_FUNCTION S4Err S4Key_SignHash( S4KeyContextRef      pubKeyCtx,
												 void *hash, size_t hashLen,
												 void *outSig, size_t bufSize, size_t *outSigLen)
{
	S4Err           err = kS4Err_NoErr;
	
	
	validateS4KeyContext(pubKeyCtx);
	ValidateParam(pubKeyCtx->type == kS4KeyType_PublicKey);
	
	bool canSign =  ECC_isPrivate(pubKeyCtx->pub.ecc);
	
	if(!canSign)
		RETERR(kS4Err_BadParams);
	
	err = ECC_Sign(pubKeyCtx->pub.ecc, hash, hashLen,  outSig, bufSize, outSigLen);CKERR;
	
done:
	
	return err;
}
EXPORT_FUNCTION S4Err S4Key_VerifyHash( S4KeyContextRef  pubKeyCtx,
													void *hash, size_t hashLen,
													void *sig,  size_t sigLen)
{
	S4Err           err = kS4Err_NoErr;
	
	validateS4KeyContext(pubKeyCtx);
	ValidateParam(pubKeyCtx->type == kS4KeyType_PublicKey);
	
	bool canVerify =  sECC_ContextIsValid(pubKeyCtx->pub.ecc);
	
	if(!canVerify)
		RETERR(kS4Err_BadParams);
	
	err = ECC_Verify(pubKeyCtx->pub.ecc,  sig, sigLen, hash, hashLen);
	
done:
	return err;
	
}



static S4Err sCalulateKeyDigest( S4KeyContextRef  keyCtx,
										  char**            optionalPropNamesList,
										  HASH_Algorithm    hashAlgorithm,
										  time_t            signDate,
										  long              sigExpireTime,
										  uint8_t* hashBuf, size_t *hashBytes )
{
	S4Err             err = kS4Err_NoErr;
	HASH_ContextRef    hash = NULL;
	
	validateS4KeyContext(keyCtx);
	
	size_t      propListEntries = 0;
	char**       propList = NULL;
	
	time_t       issueTime = signDate;
	long         expireTime = sigExpireTime == 0?LONG_MAX:sigExpireTime;
	
	err = HASH_Init( hashAlgorithm, &hash); CKERR;
	
	if(optionalPropNamesList)
	{
		for(propListEntries = 0; optionalPropNamesList[propListEntries] != 0; propListEntries++);
		propList = optionalPropNamesList;
	}
	else
	{
		err = sGetSignablePropertyNames(keyCtx, &propList, &propListEntries); CKERR;
	}
	
	// sign in issue date and expire
	err  = HASH_Update(hash,kS4KeyProp_SignedDate, strlen(kS4KeyProp_SignedDate)); CKERR;
	err  = HASH_Update(hash, ":", 1); CKERR;
	err  = HASH_Update(hash, &issueTime, sizeof(time_t)); CKERR;
	err  = HASH_Update(hash, ",", 1); CKERR;
	err  = HASH_Update(hash,kS4KeyProp_SigExpire, strlen(kS4KeyProp_SigExpire)); CKERR;
	err  = HASH_Update(hash, ":", 1); CKERR;
	err  = HASH_Update(hash, &expireTime, sizeof(long)); CKERR;
	
	if(propList)
	{
		for(int i = 0; i < propListEntries; i++)
		{
			// hash in the name
			err  = HASH_Update(hash, ",", 1); CKERR;
			err  = HASH_Update(hash,propList[i], strlen(propList[i])); CKERR;
			err  = HASH_Update(hash, ":", 1); CKERR;
			
			// Handle the special built in properties
			if(STRCMP2(propList[i], kS4KeyProp_KeyType))
			{
				err  = HASH_Update(hash, &keyCtx->type, sizeof(S4KeyType)); CKERR;
			}
			else if(STRCMP2(propList[i], kS4KeyProp_KeySuite))
			{
				Cipher_Algorithm  cipherAlgor = kCipher_Algorithm_Invalid;
				err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeySuite, NULL, &cipherAlgor, sizeof(cipherAlgor), NULL ); CKERR;
				err = HASH_Update(hash, &cipherAlgor, sizeof(Cipher_Algorithm)); CKERR;
			}
			else if(STRCMP2(propList[i], kS4KeyProp_KeyID))
			{
				uint8_t keyID [kS4Key_KeyIDBytes] = {0};
				err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeyID, NULL, &keyID, sizeof(keyID), NULL ); CKERR;
				err  = HASH_Update(hash,keyID, sizeof(keyID)); CKERR;
			}
			else if(STRCMP2(propList[i], kS4KeyProp_SignedBy))
			{
				uint8_t keyID [kS4Key_KeyIDBytes] = {0};
				err = S4Key_GetProperty(keyCtx, kS4KeyProp_SignedBy, NULL, &keyID, sizeof(keyID), NULL ); CKERR;
				err  = HASH_Update(hash,keyID, sizeof(keyID)); CKERR;
			}
			else if(STRCMP2(propList[i], kS4KeyProp_Signature))
			{
				err  = HASH_Update(hash,keyCtx->sig.signature, keyCtx->sig.signatureLen);  CKERR;
			}
			else if(STRCMP2(propList[i], kS4KeyProp_SignedDate))
			{
				err  = HASH_Update(hash, &keyCtx->sig.signDate, sizeof(time_t)); CKERR;
			}
			else if(STRCMP2(propList[i], kS4KeyProp_SigExpire))
			{
				long  expireTime = keyCtx->sig.expirationTime == 0?LONG_MAX:keyCtx->sig.expirationTime;
				err  = HASH_Update(hash, &expireTime, sizeof(expireTime)); CKERR;
			}
			else if(STRCMP2(propList[i], kS4KeyProp_SigID))
			{
				uint8_t keyID [kS4Key_KeyIDBytes] = {0};
				err = S4Key_GetProperty(keyCtx, kS4KeyProp_SigID, NULL, &keyID, sizeof(keyID), NULL ); CKERR;
				err  = HASH_Update(hash,keyID, sizeof(keyID)); CKERR;
			}
			
			else if(STRCMP2(propList[i], kS4KeyProp_PubKey))
			{
				uint8_t         keyData[256];
				size_t          keyDataLen = 0;
				
				err = ECC_Export_ANSI_X963(keyCtx->pub.ecc, keyData, sizeof(keyData), &keyDataLen);CKERR;
				err  = HASH_Update(hash,keyData, keyDataLen); CKERR;
			}
			
			// handle the properties found on proplist
			else
			{
				S4KeyProperty* prop = sFindPropertyInList(keyCtx->propList,propList[i]);
				
				if(!prop) continue;
				
				if(!optionalPropNamesList
					&& ((prop->extended && S4KeyPropertyExtended_Signable) != S4KeyPropertyExtended_Signable))
					continue;
				
				switch(prop->type)
				{
					case S4KeyPropertyType_UTF8String:
					{
						err  = HASH_Update(hash,prop->value, prop->valueLen); CKERR;
					}
						break;
						
					case S4KeyPropertyType_Binary:
					{
						err  = HASH_Update(hash,prop->value, prop->valueLen); CKERR;
					}
						break;
						
					case S4KeyPropertyType_Time:
					{
						uint8_t     tempBuf[32];
						size_t      tempLen;
						time_t      gTime;
						struct      tm *nowtm;
						
						COPY(prop->value, &gTime, sizeof(gTime));
						nowtm = gmtime(&gTime);
						tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
						err  = HASH_Update(hash,tempBuf, tempLen); CKERR;
					}
						break;
						
					default:
						;
						
				}
				
			}
		}
	}
	
	HASH_GetSize(hash, hashBytes);
	HASH_Final(hash,hashBuf);
	
done:
	
	if(!optionalPropNamesList  && propList)
	{
		for(int i = 0; propList[i]; i++)
			XFREE(propList[i]);
		
		XFREE(propList);
	}
	
	if(!IsNull(hash))
		HASH_Free(hash);
	
	return err;
	
}

#ifdef __clang__
#pragma mark -  Key Signing/Verify
#endif
static void sCloneSignatures(S4KeyContext  *src, S4KeyContext  *dest )
{
	
	S4KeySigItem* item = NULL;
	S4KeySigItem** lastSig = &dest->sigList;
	
	for(item = src->sigList; item; item = item->next)
	{
		S4KeySigItem* newItem =  XMALLOC(sizeof(S4KeySigItem));
		ZERO(newItem,sizeof(S4KeySigItem));
		
		if(item->sig.signature)
		{
			newItem->sig.signature = XMALLOC(item->sig.signatureLen );
			COPY(item->sig.signature, newItem->sig.signature, item->sig.signatureLen );
			newItem->sig.signatureLen = item->sig.signatureLen;
			newItem->sig.hashAlgorithm  = item->sig.hashAlgorithm;
			
			COPY(item->sig.issuerID, newItem->sig.issuerID, kS4Key_KeyIDBytes );
			COPY(item->sig.sigID, newItem->sig.sigID, kS4Key_KeyIDBytes );
			
			newItem->sig.signDate = item->sig.signDate;
			newItem->sig.expirationTime  = item->sig.expirationTime;
			newItem->sig.propNameList = sDeepStrDup(item->sig.propNameList);
			
			*lastSig = newItem;
			lastSig = &newItem->next;
		}
		
		*lastSig = NULL;
	}
}

static char** sDeepStrDup( char** list)
{
	size_t          listCount = 0;
	char**          newList = NULL;
	
	if(list)
	{
		for(int i = 0; list[i]; i++)
			listCount++;
		
		if(listCount)
		{
			int i = 0;
			newList = XMALLOC((listCount + 1 ) * sizeof(char*) );
			
			for(i = 0; list[i]; i++)
				newList[i] = strdup(list[i]);
			
			newList[i++] = NULL;
		}
		
		
	}
	return newList;
}



static void sDeleteSignature(S4KeyContextRef pubCtx,
									  const uint8_t *signedBy )
{
	S4KeySigItem* item = NULL;
	S4KeySigItem* previous = NULL;
	
	// find the item;
	
	for(item = pubCtx->sigList; item; item = item->next)
	{
		if(CMP(item->sig.issuerID, signedBy, kS4Key_KeyIDBytes)) break;
		previous = item;
	}
	
	if(item)
	{
		// remove from list head?
		if(pubCtx->sigList == item)
			pubCtx->sigList = item->next;
		else
			previous->next = item->next;
		
		XFREE(item->sig.signature);
		XFREE(item);
	}
}

static void sInsertSig(S4KeyContextRef      signingCtx,
							  S4KeyContextRef      pubCtx,
							  uint8_t              sigID[kS4Key_KeyIDBytes],
							  uint8_t              *sigData,
							  size_t               sigDataLen,
							  HASH_Algorithm       hashAlgorithm,
							  time_t               signDate,
							  time_t               expirationTime,
							  char**               propNameList)
{
	S4KeySigItem* sigItem = XMALLOC(sizeof(S4KeySigItem));
	if(sigItem)
	{
		ZERO(sigItem,sizeof(S4KeySigItem));
		
		sigItem->sig.signature = XMALLOC(sigDataLen);
		COPY(sigData, sigItem->sig.signature, sigDataLen );
		sigItem->sig.signatureLen = sigDataLen;
		COPY(&signingCtx->pub.keyID ,  &sigItem->sig.issuerID, kS4Key_KeyIDBytes);
		COPY(sigID ,  &sigItem->sig.sigID, kS4Key_KeyIDBytes);
		
		sigItem->sig.hashAlgorithm  = hashAlgorithm;
		sigItem->sig.signDate       = signDate;
		sigItem->sig.expirationTime = expirationTime;
		sigItem->sig.propNameList   = sDeepStrDup(propNameList);
		
		// delete old sigs
		sDeleteSignature(pubCtx, signingCtx->pub.keyID);
		
		sigItem->next = pubCtx->sigList;
		pubCtx->sigList = sigItem;
	}
}

EXPORT_FUNCTION S4Err S4Key_SignKey( S4KeyContextRef      signingCtx,
												S4KeyContextRef      keyCtx,
												long                 sigExpireTime
												)
{
	S4Err           err = kS4Err_NoErr;
	
	size_t          propNameCount = 0;
	char**          propNameList = NULL;
	
	uint8_t        keyHash [32] = {0};
	size_t         keyHashLen = 0;
	
	uint8_t        sigBuff[256];
	size_t          sigBuffLen = 0;
	
	time_t          signDate = time(NULL);
	long            expireTime = sigExpireTime == 0?LONG_MAX:sigExpireTime;
	
	uint8_t        sigID [kS4Key_KeyIDBytes] = {0};
	
	HASH_Algorithm  hashAlgorithm = kHASH_Algorithm_SHA256;
	
	validateS4KeyContext(signingCtx);
	validateS4KeyContext(keyCtx);
	ValidateParam(keyCtx->type == kS4KeyType_PublicKey
					  || keyCtx->type == kS4KeyType_Signature );
	ValidateParam(signingCtx->type == kS4KeyType_PublicKey);
	
	bool canSign =  ECC_isPrivate(signingCtx->pub.ecc);
	
	if(!canSign)
		RETERR(kS4Err_BadParams);
	
	// Get the properties we use for signing.
	err = sGetSignablePropertyNames(keyCtx, &propNameList, &propNameCount); CKERR;
	
	// caclulate the key hash
	err = sCalulateKeyDigest(keyCtx,
									 propNameList,
									 hashAlgorithm,
									 signDate, expireTime,
									 keyHash, &keyHashLen); CKERR;
	
	// generate a random SigID
	err = RNG_GetBytes( sigID, sizeof(sigID)); CKERR;
	
	// calculate the key sig
	err = ECC_Sign(signingCtx->pub.ecc,
						keyHash, keyHashLen,
						sigBuff, sizeof(sigBuff), &sigBuffLen);CKERR;
	
	sInsertSig(signingCtx,
				  keyCtx,
				  sigID,
				  sigBuff, sigBuffLen,
				  hashAlgorithm,
				  signDate, expireTime,
				  propNameList);
	
done:
	
	if(propNameList)
	{
		for(int i = 0; propNameList[i]; i++)
			XFREE(propNameList[i]);
		XFREE(propNameList);
	}
	
	return err;
}

EXPORT_FUNCTION S4Err S4Key_GetKeySignatures( S4KeyContextRef      ctx,
															size_t              *outCount,
															S4KeyContextRef     *ctxArrayOut[])
{
	S4Err           err = kS4Err_NoErr;
	
	size_t                  keyCount = 0;
	S4KeyContextRef*         ctxArray = NULL;
	S4KeySigItem *sigItem   = NULL;
	int i;
	
	validateS4KeyContext(ctx);
	
	// get number of signatures
	for(sigItem = ctx->sigList; sigItem; sigItem = sigItem->next)
		keyCount++;
	
	// allocate the ctxArray
	ctxArray = XMALLOC(sizeof(S4KeyContextRef) * keyCount);
	ZERO(ctxArray, sizeof(S4KeyContextRef) * keyCount);
	
	for(i=0 , sigItem = ctx->sigList ; i < keyCount; i++, sigItem = sigItem->next)
	{
		
		S4KeyContext* keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
		ZERO(keyCTX, sizeof(S4KeyContext));
		
		keyCTX->magic = kS4KeyContextMagic;
		keyCTX->type  = kS4KeyType_Signature;
		keyCTX->propList = NULL;
		keyCTX->sigList = NULL;
		
		COPY(sigItem->sig.issuerID, keyCTX->sig.issuerID, kS4Key_KeyIDBytes);
		keyCTX->sig.signDate = sigItem->sig.signDate;
		keyCTX->sig.expirationTime = sigItem->sig.expirationTime;
		
		for(int offset = 0; sigItem->sig.propNameList[offset] != NULL; offset++)
		{
			sAppendSigProp(&keyCTX->sig,
								(char *)sigItem->sig.propNameList[offset],
								strlen(sigItem->sig.propNameList[offset]));
			
		}
		
		keyCTX->sig.hashAlgorithm  = sigItem->sig.hashAlgorithm;
		
		keyCTX->sig.signature = XMALLOC(sigItem->sig.signatureLen);
		COPY(sigItem->sig.signature, keyCTX->sig.signature, sigItem->sig.signatureLen);
		keyCTX->sig.signatureLen =  sigItem->sig.signatureLen;
		
		ctxArray[i] = keyCTX;
	}
	
	
done:
	
	if(ctxArrayOut)
	{
		if(!keyCount)
		{
			*ctxArrayOut = NULL;
		}
		else
		{
			*ctxArrayOut = ctxArray;
		}
	}
	
	if(outCount) *outCount = keyCount;
	
	return err;
	
}



EXPORT_FUNCTION S4Err S4Key_VerfiyKeySig( S4KeyContextRef      keyCtx,
													  S4KeyContextRef      sigingKeyCtx,
													  S4KeyContextRef      sigCtx)
{
	S4Err           err = kS4Err_NoErr;
	
	uint8_t        keyHash1[32] = {0};
	size_t         keyHash1Len = 0;
	
	validateS4KeyContext(keyCtx);
	validateS4KeyContext(sigingKeyCtx);
	
	ValidateParam(keyCtx->type == kS4KeyType_PublicKey
					  || keyCtx->type == kS4KeyType_Signature );
	
	ValidateParam(sigingKeyCtx->type == kS4KeyType_PublicKey);
	
	bool isPubKey = sECC_ContextIsValid(sigingKeyCtx->pub.ecc);
	if(!isPubKey)
		RETERR(kS4Err_BadParams);
	
	bool isSig =  sigCtx->type == kS4KeyType_Signature;
	if(!isSig)
		RETERR(kS4Err_BadParams);
	
	bool isCorrectKey = S4Key_CompareKeyID(sigingKeyCtx->pub.keyID, sigCtx->sig.issuerID);
	if(!isCorrectKey)
		RETERR(kS4Err_BadParams);
	
	
	err = sCalulateKeyDigest(keyCtx,sigCtx->sig.propNameList ,
									 kHASH_Algorithm_SHA256,
									 sigCtx->sig.signDate,
									 sigCtx->sig.expirationTime,
									 keyHash1, &keyHash1Len); CKERR;
	
	err = S4Key_VerifyHash(sigingKeyCtx,
								  keyHash1,keyHash1Len,
								  sigCtx->sig.signature, sigCtx->sig.signatureLen);  CKERR;
	
done:
	
	return err;
	
}

bool S4Key_CompareKeyID(uint8_t* keyID1, uint8_t* keyID2)
{
	return CMP(keyID1, keyID2, kS4Key_KeyIDBytes);
	
}


#ifdef __clang__
#pragma mark -  Deatched Sigs.
#endif

EXPORT_FUNCTION S4Err S4Key_NewSignature( S4KeyContextRef       pubCtx,
													  void                   *hashData,
													  size_t                 hashDataLen,
													  HASH_Algorithm         hashAlgorithm,
													  long                   sigExpireTime,
													  S4KeyContextRef        *ctxOut)
{
	S4Err           err = kS4Err_NoErr;
	S4KeyContext*    keyCTX  = NULL;
	
	int             keyBytes  = 0;
	uint8_t         *keyData = NULL;
	
	uint8_t         SIG[256];
	size_t          SIGlen = 0;
	
	uint8_t         sigID [kS4Key_KeyIDBytes] = {0};
	
	time_t          signDate = time(NULL);
	long            expireTime = sigExpireTime == 0?LONG_MAX:sigExpireTime;
	
	HASH_ContextRef hashCtx = kInvalidHASH_ContextRef;
	size_t hashSize = 0;
	
	validateS4KeyContext(pubCtx);
	ValidateParam(pubCtx->type == kS4KeyType_PublicKey);
	ValidateParam(ctxOut);
	
	// check if hashAlgorithm is appropriate for hashLen
	err = HASH_Init(hashAlgorithm, &hashCtx); CKERR;
	err = HASH_GetSize(hashCtx, &hashSize); CKERR;
	ValidateParam(hashDataLen == hashSize);
	HASH_Free(hashCtx); hashCtx = kInvalidHASH_ContextRef;
	
	err = S4Key_SignHash(pubCtx, hashData,hashDataLen, SIG, sizeof(SIG), &SIGlen); CKERR;
	
	// generate a randome SigID
	err = RNG_GetBytes( sigID, sizeof(sigID)); CKERR;
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	keyCTX->type  = kS4KeyType_Signature;
	keyCTX->propList = NULL;
	keyCTX->sigList = NULL;
	
	COPY(pubCtx->pub.keyID, keyCTX->sig.issuerID, kS4Key_KeyIDBytes );
	
	keyCTX->sig.signature = XMALLOC(SIGlen );  CKNULL(keyCTX->sig.signature);
	COPY(SIG, keyCTX->sig.signature, SIGlen );
	keyCTX->sig.signatureLen = SIGlen;
	
	COPY(sigID, keyCTX->sig.sigID, sizeof(keyCTX->sig.sigID));
	
	keyCTX->sig.hashAlgorithm   = hashAlgorithm;
	keyCTX->sig.signDate        = signDate;
	keyCTX->sig.expirationTime  = expireTime;
	
	*ctxOut = keyCTX;
	
done:
	
	if(hashCtx)
		HASH_Free(hashCtx);
	
	if(keyData && keyBytes)
	{
		ZERO(keyData, keyBytes);
		XFREE(keyData);
	}
	
	if(IsS4Err(err))
	{
		if(keyCTX)
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	
	return err;
	
	
}

EXPORT_FUNCTION S4Err S4Key_SerializeSignature( S4KeyContextRef      sigCtx,
															  uint8_t          **outData,
															  size_t           *outSize)
{
	S4Err           err = kS4Err_NoErr;
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	uint8_t             *yajlBuf = NULL;
	size_t              yajlLen = 0;
	yajl_gen            g = NULL;
	
	uint8_t             tempBuf[1024];
	size_t              tempLen;
	uint8_t             *outBuf = NULL;
	const char*         hashAlgorString = "Invalid";
	
	yajl_alloc_funcs allocFuncs = {
		yajlMalloc,
		yajlRealloc,
		yajlFree,
		(void *) NULL
	};
	
	validateS4KeyContext(sigCtx);
	ValidateParam(outData);
	
	ValidateParam(sigCtx->type == kS4KeyType_Signature);
	
	g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
	
#if DEBUG
	yajl_gen_config(g, yajl_gen_beautify, 1);
#else
	yajl_gen_config(g, yajl_gen_beautify, 0);
	
#endif
	yajl_gen_config(g, yajl_gen_validate_utf8, 1);
	stat = yajl_gen_map_open(g);CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding_Signature, strlen(kS4KeyProp_Encoding_Signature)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SigID, strlen(kS4KeyProp_SigID)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(sigCtx->sig.sigID, kS4Key_KeyIDBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_HashAlgorithm, strlen(kS4KeyProp_HashAlgorithm)) ; CKYJAL
	hashAlgorString = hash_algor_table(sigCtx->sig.hashAlgorithm);
	stat = yajl_gen_string(g, (uint8_t *)hashAlgorString, strlen(hashAlgorString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Signature, strlen(kS4KeyProp_Signature)) ; CKYJAL
	tempLen = sizeof(tempBuf);
	base64_encode(sigCtx->sig.signature, sigCtx->sig.signatureLen, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedBy, strlen(kS4KeyProp_SignedBy)) ; CKYJAL;
	tempLen = sizeof(tempBuf);
	base64_encode(sigCtx->sig.issuerID, kS4Key_KeyIDBytes, tempBuf, &tempLen);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedDate, strlen(kS4KeyProp_SignedDate)) ; CKYJAL;
	struct tm *nowtm;
	nowtm = gmtime(&sigCtx->sig.signDate);
	tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
	stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
	
	if(sigCtx->sig.expirationTime != LONG_MAX)
	{
		stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SigExpire, strlen(kS4KeyProp_SigExpire)) ; CKYJAL;
		stat = yajl_gen_integer(g, sigCtx->sig.expirationTime) ; CKYJAL;
	}
	
	err = sGenPropStrings(sigCtx->propList, g); CKERR;
	err = sGenSignatureStrings(sigCtx, g); CKERR;
	
	stat = yajl_gen_map_close(g); CKYJAL;
	stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
	
	outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
	memcpy(outBuf, yajlBuf, yajlLen);
	outBuf[yajlLen] = 0;
	
	
	*outData = outBuf;
	
	if(outSize)
		*outSize = yajlLen;
	
done:
	if(IsntNull(g))
		yajl_gen_free(g);
	
	return err;
	
}

EXPORT_FUNCTION S4Err S4Key_VerifySignature( S4KeyContextRef      sigCtx,
														  S4KeyContextRef       sigingKeyCtx,
														  void                   *hash,
														  size_t                 hashLen )
{
	S4Err           err = kS4Err_NoErr;
	
	
	validateS4KeyContext(sigingKeyCtx);
	validateS4KeyContext(sigCtx);
	
	ValidateParam(sigingKeyCtx->type == kS4KeyType_PublicKey);
	ValidateParam(sigCtx->type == kS4KeyType_Signature);
	
	bool isPubKey =  sECC_ContextIsValid(sigingKeyCtx->pub.ecc);
	if(!isPubKey)
		RETERR(kS4Err_BadParams);
	
	bool isCorrectKey = S4Key_CompareKeyID(sigingKeyCtx->pub.keyID, sigCtx->sig.issuerID);
	if(!isCorrectKey)
		RETERR(kS4Err_BadParams);
	
	err = S4Key_VerifyHash(sigingKeyCtx,
								  hash,hashLen,
								  sigCtx->sig.signature, sigCtx->sig.signatureLen);  CKERR;
	
done:
	
	return err;
	
	
}

#ifdef __clang__
#pragma mark -  Passcode to Key.
#endif

static S4Err sP2K_EncryptKeyToPassPhrase( const void 		*keyIn,
													  size_t 			keyInLen,
													  Cipher_Algorithm cipherAlgorithm,
													  const uint8_t    *passphrase,
													  size_t           passphraseLen,
													  P2K_Algorithm 	p2kAlgor,
													  S4KeyPropertyRef  propList,
													  uint8_t __NULLABLE_XFREE_P_P outAllocData,
													  size_t* __S4_NULLABLE 		outSize)
{
	const size_t kMaxCipherSize  = 32;
	
	S4Err  	err = kS4Err_NoErr;
	
	size_t              cipherSizeInBits = 0;
	size_t              cipherSizeInBytes = 0;
	const char*     	keySuiteString = "Invalid";
	
	uint8_t      		sessionKey[kMaxCipherSize] 	= {0};	// session key is what we use to encrypt the keyIn
	uint8_t             ESK[kMaxCipherSize] 		= {0};	//	session Key encrypted to unlockingKey
	uint8_t        		unlockingKey[kMaxCipherSize] = {0};	// unlockingKey is derived from passphrase
	uint8_t      		IV[kMaxCipherSize] = {0};
	
	uint8_t*			encryptedKey = NULL;		// KeyIn encypted to sessionKey
	size_t      		encryptedKeyLen = 0;
	
	CBC_ContextRef      cbc 			= kInvalidCBC_ContextRef;
	P2K_ContextRef 		p2K = kInvalidP2K_ContextRef;
	char*  				p2KParamStr = NULL;;
	
	uint8_t         	keyHash[kS4KeyESK_HashBytes] = {0};  // we use keyhash to check validity of decode
	
	// yajl encoding stuff
	yajl_gen_status     stat = yajl_gen_status_ok;
	
	uint8_t             *yajlBuf = NULL;
	size_t              yajlLen = 0;
	yajl_gen            g = NULL;
	uint8_t*          	tempBuf = NULL;
	size_t              tempBufAllocLen = 0;
	size_t              tempBufLen = 0;
	
	yajl_alloc_funcs allocFuncs = {
		yajlMalloc,
		yajlRealloc,
		yajlFree,
		(void *) NULL
	};
	
	ValidateParam(keyIn);
	ValidateParam(passphrase);
	
	// create a random session key
	err = Cipher_GetKeySize(cipherAlgorithm, &cipherSizeInBits); CKERR;
	cipherSizeInBytes = cipherSizeInBits / 8;
	ValidateParam(cipherSizeInBytes <= kMaxCipherSize);
	
	err = RNG_GetBytes(sessionKey,cipherSizeInBytes); CKERR;
	
	// encrypt the keyIn using CBC -- CBC_Encrypt checks for valid blocklen
	// we have to alloc the encryptedKey it's size if dependent on keyInLen
	encryptedKeyLen = keyInLen;
	encryptedKey = XMALLOC(encryptedKeyLen); CKNULL(encryptedKey);
	err = RNG_GetBytes(IV,cipherSizeInBytes); CKERR;
	err = CBC_Init(cipherAlgorithm, sessionKey, IV,  &cbc);CKERR;
	err = CBC_Encrypt(cbc, keyIn, keyInLen, encryptedKey, keyInLen); CKERR;
	keySuiteString = cipher_algor_table(cipherAlgorithm);
	
	// encrypt the session key to the passPhrase
	err = P2K_Init(p2kAlgor, &p2K); CKERR;
	
	err = P2K_EncodePassword(p2K, passphrase, passphraseLen, kS4KeyPBKDF2_SaltBytes,
									 cipherSizeInBytes, unlockingKey, &p2KParamStr); CKERR;
	
	err = sP2K_PASSPHRASE_HASH(unlockingKey, cipherSizeInBytes,
										p2KParamStr,
										keyHash, kS4KeyESK_HashBytes); CKERR;
	
	err =  ECB_Encrypt(cipherAlgorithm, unlockingKey,
							 sessionKey, cipherSizeInBytes,
							 ESK, cipherSizeInBytes); CKERR;
	
	
	g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
	
	// allocate some buffer space
	tempBufAllocLen =  MAX(encryptedKeyLen, kMaxCipherSize) * 4;
	tempBuf =  XMALLOC(tempBufAllocLen); CKNULL(tempBuf);
	
#if DEBUG
	yajl_gen_config(g, yajl_gen_beautify, 1);
#else
	yajl_gen_config(g, yajl_gen_beautify, 0);
	
#endif
	yajl_gen_config(g, yajl_gen_validate_utf8, 1);
	stat = yajl_gen_map_open(g);CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
	sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
	stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding_P2K, strlen(kS4KeyProp_Encoding_P2K)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_p2kParams, strlen(kS4KeyProp_p2kParams)) ; CKYJAL;
	stat = yajl_gen_string(g, (uint8_t *)p2KParamStr, strlen(p2KParamStr)) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
	tempBufLen = tempBufAllocLen;
	base64_encode(keyHash, kS4KeyESK_HashBytes, tempBuf, &tempBufLen);
	stat = yajl_gen_string(g, tempBuf, tempBufLen) ; CKYJAL;
	
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ESK, strlen(kS4KeyProp_ESK)) ; CKYJAL;
	tempBufLen = tempBufAllocLen;
	base64_encode(ESK, cipherSizeInBytes, tempBuf, &tempBufLen);
	stat = yajl_gen_string(g, tempBuf, tempBufLen) ; CKYJAL;
	
	//	kS4KeyProp_IV
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_IV, strlen(kS4KeyProp_IV)) ; CKYJAL;
	tempBufLen = tempBufAllocLen;
	base64_encode(IV, cipherSizeInBytes, tempBuf, &tempBufLen);
	stat = yajl_gen_string(g, tempBuf, tempBufLen) ; CKYJAL;
	
	// kS4KeyProp_EncryptedKey
	stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
	tempBufLen = tempBufAllocLen;
	base64_encode(encryptedKey, encryptedKeyLen, tempBuf, &tempBufLen);
	stat = yajl_gen_string(g, tempBuf, tempBufLen) ; CKYJAL;
	
	// add any additional properties
	err = sGenPropStrings(propList, g); CKERR;
	
	stat = yajl_gen_map_close(g); CKYJAL;
	stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
	
	
	if(outAllocData)
	{
		uint8_t  *outBuf = NULL;
		outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
		memcpy(outBuf, yajlBuf, yajlLen);
		outBuf[yajlLen] = 0;
		*outAllocData = outBuf;
	}
	
	if(outSize)
		*outSize = yajlLen;
	
done:
	// zeroize all the CSPs
	ZERO(sessionKey,sizeof(sessionKey));
	ZERO(ESK,sizeof(ESK));
	ZERO(unlockingKey,sizeof(unlockingKey));
	ZERO(IV,sizeof(IV));
	
	if(CBC_ContextRefIsValid(cbc))
		CBC_Free(cbc);
	
	if( P2K_ContextRefIsValid(p2K))
		P2K_Free(p2K);
	
	if(encryptedKey)
	{
		ZERO(encryptedKey,encryptedKeyLen);
		XFREE(encryptedKey);
	}
	
	if(tempBuf)
		XFREE(tempBuf);
	
	if(IsntNull(g))
		yajl_gen_free(g);
	
	if(p2KParamStr)
		XFREE(p2KParamStr);
	
	return err;
	
}


EXPORT_FUNCTION S4Err P2K_EncryptKeyToPassPhrase( const void 		*keyIn,
																 size_t 			keyInLen,
																 Cipher_Algorithm cipherAlgorithm,
																 const uint8_t    *passphrase,
																 size_t           passphraseLen,
																 P2K_Algorithm 	p2kAlgor,
																 uint8_t __NULLABLE_XFREE_P_P outAllocData,
																 size_t* __S4_NULLABLE 		outSize)
{
	return sP2K_EncryptKeyToPassPhrase(keyIn,keyInLen, cipherAlgorithm,
												  passphrase,passphraseLen, p2kAlgor, NULL,
												  outAllocData, outSize);
	
}

S4Err P2K_DecryptKeyFromPassPhrase(  uint8_t * __S4_NONNULL inData,
											  size_t inLen,
											  const uint8_t* __S4_NONNULL passphrase,
											  size_t           passphraseLen,
											  uint8_t __NULLABLE_XFREE_P_P outAllocKey,
											  size_t* __S4_NULLABLE 		outKeySize)
{
	const size_t kMaxCipherSize  = 32;
	
	S4Err  					err = kS4Err_NoErr;
	JSONParseContext* 		pctx = NULL;
	
	// data decoded from JSON
	Cipher_Algorithm		cipherAlgorithm = kCipher_Algorithm_Invalid;
	s4String	string =  {NULL, 0};	// non allocated strings, dont free
	
	s4Data iv 			= {NULL, 0};
	s4Data esk 			= {NULL, 0};
	s4Data encrypted 	= {NULL, 0};
	char	* p2kParams = NULL;
	
	CBC_ContextRef      	cbc 			= kInvalidCBC_ContextRef;
	uint8_t      			sessionKey[kMaxCipherSize] 		= {0};	// session key is what we use to encrypt the keyIn
	uint8_t         		unlockingKey[kMaxCipherSize] 	= {0};
	size_t          		unlockingKeylen 				= 0;
	uint8_t         		keyHash[kS4KeyESK_HashBytes] = {0};
	
	void 					*decryptedKey = NULL;
	size_t                  decryptedKeyLen = 0;
	
	ValidateParam(inData);
	ValidateParam(passphrase);
	
	// parse the JSON
	err = sParseJSON(inData, inLen, &pctx); CKERR;
	
	// check that we got a proper p2k block
	ASSERTERR(pctx->dictCount == 1 ,  kS4Err_BadParams);
	int dictTokenNum = pctx->dicts[0];
	
	// check the packet version
	{
		long longVal = 0;
		err = sGetTokenLong(pctx, dictTokenNum, kS4KeyProp_Version, &longVal); CKERR;
		ASSERTERR(longVal == kS4KeyProtocolVersion ,  kS4Err_BadParams);
	}
	
	// check the encoding is P2K
	{
		err = sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_Encoding, &string); CKERR;
		ASSERTERR(CMP2(string.str, string.len, kS4KeyProp_Encoding_P2K, strlen(kS4KeyProp_Encoding_P2K)) ,  kS4Err_BadParams);
	}
	
	// Get the cipher algorithm
	{
		S4KeyType   keyType = kS4KeyType_Invalid;
		
		err = sGetTokenStringPtr(pctx,dictTokenNum ,kS4KeyProp_KeySuite, &string); CKERR;
		err = sParseKeySuiteString(string.str, string.len, &keyType, &cipherAlgorithm); CKERR;
		ASSERTERR(keyType == kS4KeyType_Symmetric, kS4Err_BadParams);
	}
	
	
	// get the needed crypto material
	err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_IV, &iv);CKERR;
	err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_ESK, &esk);CKERR;
	err = sGetTokenBase64Data(pctx,dictTokenNum ,kS4KeyProp_EncryptedKey, &encrypted);CKERR;
	
	// we need the p2kParms as a null terminated string
	{
		err = sGetTokenStringPtr(pctx,dictTokenNum,kS4KeyProp_p2kParams, &string);CKERR;
		p2kParams =strndup((char*) string.str, string.len);
	}
	
	
	// do some crypto parameter checking
	size_t              cipherSizeInBits = 0;
	size_t              cipherSizeInBytes = 0;
	err = Cipher_GetKeySize(cipherAlgorithm, &cipherSizeInBits); CKERR;
	cipherSizeInBytes = cipherSizeInBits / 8;
	ASSERTERR(iv.len == cipherSizeInBytes ,  kS4Err_BadParams);
	ASSERTERR(esk.len == cipherSizeInBytes ,  kS4Err_BadParams);
	
	
	// check that the password is valid
	err = P2K_DecodePassword(passphrase, passphraseLen,
									 p2kParams,
									 unlockingKey,sizeof(unlockingKey) ,&unlockingKeylen);CKERR;
	
	ASSERTERR(unlockingKeylen == cipherSizeInBytes ,  kS4Err_BadParams);
	
	err = sP2K_PASSPHRASE_HASH(unlockingKey, unlockingKeylen,
										p2kParams,
										keyHash, kS4KeyESK_HashBytes); CKERR;
	
	ASSERTERR(CMP(keyHash, keyHash, kS4KeyESK_HashBytes), kS4Err_BadIntegrity);
	
	// decrypt the session key
	err =  ECB_Decrypt(cipherAlgorithm, unlockingKey,
							 esk.data, cipherSizeInBytes,
							 sessionKey,cipherSizeInBytes); CKERR;
	
	decryptedKeyLen = encrypted.len;
	decryptedKey = XMALLOC(encrypted.len);
	
	// decode the encrypted info
	err = CBC_Init(cipherAlgorithm, sessionKey, iv.data,  &cbc);CKERR;
	err = CBC_Decrypt(cbc,
							encrypted.data, encrypted.len,
							decryptedKey, encrypted.len); CKERR;
	
	if(outAllocKey)
		*outAllocKey = decryptedKey;
	
	if(outKeySize)
		*outKeySize = decryptedKeyLen;
	
done:
	
	// free up  data from JSON decoding
	
	if(p2kParams)
		XFREE(p2kParams);
	
	if(iv.data)
		XFREE(iv.data);
	
	if(esk.data)
		XFREE(esk.data);
	
	if(encrypted.data)
		XFREE(encrypted.data);
	
	sFreeParseContext(pctx);
	
	if(IsS4Err(err))
	{
		if(decryptedKey && decryptedKeyLen != 0)
		{
			ZERO(decryptedKey,decryptedKeyLen);
			XFREE(decryptedKey);
			decryptedKey = NULL;
			decryptedKeyLen = 0;
		}
	}
	
	
	if(CBC_ContextRefIsValid(cbc))
		CBC_Free(cbc);
	
	ZERO(sessionKey,sizeof(sessionKey));
	ZERO(keyHash,sizeof(keyHash));
	ZERO(unlockingKey,sizeof(unlockingKey));
	
	return err;
	
}

EXPORT_FUNCTION S4Err S4Key_SerializeToPassCode(S4KeyContextRef  ctx,
																const uint8_t* __S4_NONNULL passcode,
																size_t           passcodeLen,
																P2K_Algorithm 	p2kAlgorithm,
																uint8_t __NULLABLE_XFREE_P_P outAllocData,
																size_t* __S4_NULLABLE 		outSize)
{
	S4Err           err = kS4Err_NoErr;
	validateS4KeyContext(ctx);
	ValidateParam(passcode);
	ValidateParam(outAllocData);
	
	
	void*               keyToEncrypt = NULL;
	size_t              keyToEncryptLen = 0;
	
	Cipher_Algorithm    cipherAlgorithm = kCipher_Algorithm_Invalid;
	const char*         keySuiteString = "Invalid";
	S4KeyPropertyRef	propList = NULL;
	
	sClonePropertiesLists(ctx->propList, &propList);
	
	switch (ctx->type)
	{
		case kS4KeyType_Symmetric:
		{
			keyToEncryptLen = ctx->sym.keylen ;
			keyToEncrypt = ctx->sym.symKey;
			
			switch (ctx->sym.symAlgor) {
				case kCipher_Algorithm_2FISH256:
					cipherAlgorithm = kCipher_Algorithm_2FISH256;
					break;
					
				case kCipher_Algorithm_AES128:
					cipherAlgorithm = kCipher_Algorithm_AES128;
					break;
					
				case kCipher_Algorithm_AES192:
					cipherAlgorithm = kCipher_Algorithm_AES256;
					//  pad the end  (treat it like it was 256 bits)
					ZERO(&ctx->sym.symKey[24], 8);
					keyToEncryptLen = 32;
					break;
					
				case kCipher_Algorithm_AES256:
					cipherAlgorithm = kCipher_Algorithm_AES256;
					break;
					
				default:
					RETERR(kS4Err_BadCipherNumber);
					break;
			}
			
			keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
			
			sInsertPropertyInList(&propList,kS4KeyProp_EncodedObject, S4KeyPropertyType_UTF8String,
										 S4KeyPropertyExtendedType_None,
										 (void*)keySuiteString, strlen(keySuiteString));
		}
			break;
			
		case kS4KeyType_Tweekable:
		{
			keyToEncryptLen = ctx->tbc.keybits >> 3 ;
			cipherAlgorithm = kCipher_Algorithm_2FISH256;
			keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
			keyToEncrypt = ctx->tbc.key;
			
			sInsertPropertyInList(&propList,kS4KeyProp_EncodedObject, S4KeyPropertyType_UTF8String,
										 S4KeyPropertyExtendedType_None,
										 (void*)keySuiteString, strlen(keySuiteString));
			
		}
			break;
			
		case kS4KeyType_Share:
		{
			char tempBuf[1024];
			size_t tempLen;
			uint tempNum;
			
			keyToEncryptLen = (int)ctx->share.shareSecretLen ;
			cipherAlgorithm = kCipher_Algorithm_2FISH256;
			keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
			keyToEncrypt = ctx->share.shareSecret;
			
			// we only encode block sizes of 16, 32, 48 and 64
			ASSERTERR((keyToEncryptLen % 16) == 0, kS4Err_FeatureNotAvailable);
			ASSERTERR(keyToEncryptLen <= 64, kS4Err_FeatureNotAvailable);
			
			tempNum	= ctx->share.xCoordinate;
			sInsertPropertyInList(&propList,kS4KeyProp_ShareIndex, S4KeyPropertyType_Numeric,
										 S4KeyPropertyExtendedType_None,
										 &tempNum, sizeof(tempNum));
			
			tempNum	= ctx->share.threshold;
			sInsertPropertyInList(&propList,kS4KeyProp_ShareThreshold, S4KeyPropertyType_Numeric,
										 S4KeyPropertyExtendedType_None,
										 &tempNum, sizeof(tempNum));
			
			tempLen = sizeof(tempBuf);
			base64_encode(ctx->share.shareOwner, kS4ShareInfo_HashBytes,  (uint8_t *)tempBuf, &tempLen);
			sInsertPropertyInList(&propList,kS4KeyProp_ShareOwner, S4KeyPropertyType_UTF8String,
										 S4KeyPropertyExtendedType_None,
										 tempBuf, strlen(tempBuf));
			
			tempLen = sizeof(tempBuf);
			base64_encode(ctx->share.shareID, kS4ShareInfo_HashBytes,  (uint8_t *)tempBuf, &tempLen);
			sInsertPropertyInList(&propList,kS4KeyProp_ShareID, S4KeyPropertyType_UTF8String,
										 S4KeyPropertyExtendedType_None,
										 tempBuf, strlen(tempBuf));
			
			sInsertPropertyInList(&propList,kS4KeyProp_EncodedObject, S4KeyPropertyType_UTF8String,
										 S4KeyPropertyExtendedType_None,
										 (void*)keySuiteString, strlen(keySuiteString));
		}
			
			break;
			
		default:
			RETERR(kS4Err_BadParams);
			break;
	}
	
	
	
	err =  sP2K_EncryptKeyToPassPhrase(keyToEncrypt,keyToEncryptLen, cipherAlgorithm,
												  passcode,passcodeLen, p2kAlgorithm, propList,
												  outAllocData, outSize); CKERR;
	
done:
	
	sFreePropertyList(propList);
	propList = NULL;
	
	return err;
	
}

EXPORT_FUNCTION S4Err S4Key_DecryptFromPassCode(S4KeyContextRef  __S4_NONNULL	 passCtx,
																const uint8_t* __S4_NONNULL 	passcode,
																size_t           				passcodeLen,
																S4KeyContextRef __NULLABLE_REF_POINTER ctxOut)
{
	S4Err           err = kS4Err_NoErr;
	
	validateS4KeyContext(passCtx);
	ValidateParam(passcode);
	ValidateParam(passCtx->type == kS4KeyType_P2K_ESK);
	ValidateParam(passCtx->esk.objectAlgor != kCipher_Algorithm_Unknown);
	
	const 		size_t kMaxCipherSize  = 32;
	S4KeyESK* 	eskCtx =  &passCtx->esk;
	uint8_t		keyHash[kS4KeyESK_HashBytes] = {0};
	uint8_t  	unlockingKey[kMaxCipherSize] 	= {0};
	uint8_t  	sessionKey[kMaxCipherSize] 		= {0};	// session key is what we use to encrypt the keyIn
	size_t  	unlockingKeylen 				= 0;
	size_t  	cipherSizeInBits = 0;
	size_t   	cipherSizeInBytes = 0;
	
	void 		*decryptedKey = NULL;
	size_t  	decryptedKeyLen = 0;
	
	S4KeyContext*   keyCTX = NULL;
	
	CBC_ContextRef 	cbc 	= kInvalidCBC_ContextRef;
	
	// do some parameter checking
	err = Cipher_GetKeySize(eskCtx->cipherAlgor, &cipherSizeInBits); CKERR;
	cipherSizeInBytes = cipherSizeInBits / 8;
	
	err = P2K_DecodePassword(passcode, passcodeLen,
									 eskCtx->p2kParams,
									 unlockingKey,sizeof(unlockingKey) ,&unlockingKeylen);CKERR;
	
	ASSERTERR(unlockingKeylen == cipherSizeInBytes ,  kS4Err_BadParams);
	
	
	err = sP2K_PASSPHRASE_HASH(unlockingKey, unlockingKeylen,
										eskCtx->p2kParams,
										keyHash, kS4KeyESK_HashBytes); CKERR;
	
	ASSERTERR(CMP(keyHash, eskCtx->keyHash, kS4KeyESK_HashBytes), kS4Err_BadIntegrity)
	
	err =  ECB_Decrypt(eskCtx->cipherAlgor, unlockingKey,
							 eskCtx->esk, cipherSizeInBytes,
							 sessionKey, cipherSizeInBytes); CKERR;
	
	decryptedKeyLen = eskCtx->encryptedLen;
	decryptedKey = XMALLOC(eskCtx->encryptedLen);
	
	// attempt to decode the encrypted info
	err = CBC_Init(eskCtx->cipherAlgor, sessionKey, eskCtx->iv,  &cbc);CKERR;
	err = CBC_Decrypt(cbc, eskCtx->encrypted, eskCtx->encryptedLen,
							decryptedKey,decryptedKeyLen); CKERR;
	
	// create a key with the data
	
	keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
	ZERO(keyCTX, sizeof(S4KeyContext));
	
	keyCTX->magic = kS4KeyContextMagic;
	keyCTX->type = sGetKeyType(eskCtx->objectAlgor);
	
	if(keyCTX->type == kS4KeyType_Symmetric)
	{
		keyCTX->sym.symAlgor = eskCtx->objectAlgor;
		size_t  expectedKeyBytes = sGetKeyLength(kS4KeyType_Symmetric, eskCtx->objectAlgor);
		keyCTX->sym.keylen = expectedKeyBytes;
		COPY(decryptedKey, keyCTX->sym.symKey, expectedKeyBytes);
	}
	else  if(keyCTX->type == kS4KeyType_Tweekable)
	{
		keyCTX->tbc.tbcAlgor = eskCtx->objectAlgor;
		keyCTX->tbc.keybits = decryptedKeyLen << 3;
		COPY(decryptedKey, keyCTX->tbc.key, decryptedKeyLen);
	}
	else  if(keyCTX->type == kS4KeyType_Share)
	{
		//		COPY(eskCtx->shareHash, keyCTX->share.shareOwner, kS4ShareInfo_HashBytes);
		COPY(decryptedKey, keyCTX->share.shareSecret, decryptedKeyLen);
		keyCTX->share.shareSecretLen = decryptedKeyLen;
		keyCTX->share.threshold = eskCtx->threshold;
		keyCTX->share.xCoordinate = eskCtx->xCoordinate;
	}
	
	sClonePropertiesLists(passCtx->propList, &keyCTX->propList);
	sCloneSignatures(passCtx, keyCTX);
	
	if(ctxOut)
	{
		*ctxOut = keyCTX;
	}
	
done:
	
	if(decryptedKey && decryptedKeyLen != 0)
	{
		ZERO(decryptedKey,decryptedKeyLen);
		XFREE(decryptedKey);
		decryptedKey = NULL;
		decryptedKeyLen = 0;
	}
	
	
	if(CBC_ContextRefIsValid(cbc))
		CBC_Free(cbc);
	
	ZERO(sessionKey,sizeof(sessionKey));
	ZERO(keyHash,sizeof(keyHash));
	ZERO(unlockingKey,sizeof(unlockingKey));
	
	if(IsS4Err(err))
	{
		if(IsntNull(keyCTX))
		{
			memset(keyCTX, 0, sizeof (S4KeyContext));
			XFREE(keyCTX);
		}
	}
	
	
	return err;
	
}

EXPORT_FUNCTION S4Err S4Key_VerifyPassCode(S4KeyContextRef  __S4_NONNULL passCtx,
														 const uint8_t* 		__S4_NONNULL 	passcode,
														 size_t           				passcodeLen)
{
	S4Err   	err = kS4Err_NoErr;
	
	validateS4KeyContext(passCtx);
	ValidateParam(passcode);
	ValidateParam(passCtx->type == kS4KeyType_P2K_ESK);
	
	const 		size_t kMaxCipherSize  = 32;
	S4KeyESK* 	eskCtx =  &passCtx->esk;
	uint8_t		keyHash[kS4KeyESK_HashBytes] = {0};
	uint8_t  	unlockingKey[kMaxCipherSize] 	= {0};
	size_t  	unlockingKeylen 				= 0;
	size_t  	cipherSizeInBits = 0;
	size_t   	cipherSizeInBytes = 0;
	
	// do some parameter checking
	err = Cipher_GetKeySize(eskCtx->cipherAlgor, &cipherSizeInBits); CKERR;
	cipherSizeInBytes = cipherSizeInBits / 8;
	
	err = P2K_DecodePassword(passcode, passcodeLen,
									 eskCtx->p2kParams,
									 unlockingKey,sizeof(unlockingKey) ,&unlockingKeylen);CKERR;
	
	ASSERTERR(unlockingKeylen == cipherSizeInBytes ,  kS4Err_BadParams);
	
	
	err = sP2K_PASSPHRASE_HASH(unlockingKey, unlockingKeylen,
										eskCtx->p2kParams,
										keyHash, kS4KeyESK_HashBytes); CKERR;
	
	ASSERTERR(CMP(keyHash, eskCtx->keyHash, kS4KeyESK_HashBytes), kS4Err_BadIntegrity)
	
done:
	
	ZERO(keyHash,sizeof(keyHash));
	ZERO(unlockingKey,sizeof(unlockingKey));
	
	return err;
}
