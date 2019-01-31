//
//  S4.c
//  S4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include "S4Crypto.h"
#include "s4internal.h"
  

#ifndef EMSCRIPTEN
#include <string.h>
#else

//functions not defined in EMSCRIPTEN
 
/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char * strnstr(const char *haystack, const char *needle, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *needle++) != '\0') {
		len = strlen(needle);
		do {
			do {
				if ((sc = *haystack++) == '\0' || slen-- < 1)
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(haystack, needle, len) != 0);
		haystack--;
	}
	return ((char *)haystack);
}

#endif

#ifdef __clang__
#pragma mark - init
#endif

EXPORT_FUNCTION S4Err S4_Init()
{
    S4Err err = kS4Err_NoErr;
    
    ltc_mp = ltm_desc;

    register_prng (&sprng_desc);
    register_hash (&md5_desc);
    register_hash (&sha1_desc);
    register_hash (&sha256_desc);
    register_hash (&sha384_desc);
    register_hash (&sha512_desc);
    register_hash (&sha224_desc);
    register_hash (&skein256_desc);
    register_hash (&skein512_desc);
    register_hash (&skein1024_desc);
    register_hash (&sha512_256_desc);
    register_cipher (&aes_desc);
    register_cipher (&twofish_desc);
    
    return err;
}




#ifdef __clang__
#pragma mark - error handling
#endif

typedef struct {
    int 		code;
    S4Err       err;
    const   char *msg;
} error_map_entry;

static const error_map_entry error_map_table[] =
{
    { CRYPT_OK,     		kS4Err_NoErr,         "Successful" },
    { CRYPT_ERROR,  		kS4Err_UnknownError,  "Generic Error" },
    { CRYPT_NOP,    		kS4Err_NOP,         	"Non-fatal 'no-operation' requested."},
    { CRYPT_INVALID_ARG, 	kS4Err_BadParams,    	"Invalid argument provided."},
    
    
    { CRYPT_MEM,  			 kS4Err_OutOfMemory,          "Out of memory"},
    { CRYPT_BUFFER_OVERFLOW, kS4Err_BufferTooSmall,       "Not enough space for output"},
    
    { -1, 					kS4Err_UserAbort,             "User Abort"},
    { -1, 					kS4Err_UnknownRequest,        "Unknown Request"},
    { -1,					kS4Err_LazyProgrammer,        "Feature incomplete"},
    
    { -1,                     	kS4Err_FeatureNotAvailable,  "Feature not available" },
    { -1,                       kS4Err_ResourceUnavailable,  "Resource not available" },
    { -1,                       kS4Err_NotConnected,         "Not connected" },
    { -1,                       kS4Err_ImproperInitialization,  "Not Initialized" },
    { CRYPT_INVALID_PACKET,     kS4Err_CorruptData,           "Corrupt Data" },
    { CRYPT_FAIL_TESTVECTOR,    kS4Err_SelfTestFailed,        "Self Test Failed" },
    { -1, 						kS4Err_BadIntegrity,  		"Bad Integrity" },
    { CRYPT_INVALID_HASH, 		kS4Err_BadHashNumber,         "Invalid hash specified" },
    { CRYPT_INVALID_CIPHER, 	kS4Err_BadCipherNumber,       "Invalid cipher specified" },
    { CRYPT_INVALID_PRNG, 		kS4Err_BadPRNGNumber,  		"Invalid PRNG specified" },
    { -1            ,           kS4Err_SecretsMismatch,       "Shared Secret Mismatch" },
    { -1            ,           kS4Err_KeyNotFound,           "Key Not Found" },
    { -1            ,           kS4Err_ProtocolError,        "Protocol Error" },
    { -1            ,           kS4Err_KeyLocked     ,        "Key Locked" },
    { -1            ,           kS4Err_KeyExpired    ,        "Key Expired" },
    { -1            ,           kS4Err_OtherError    ,        "Other Error" },
    
    { -1            ,           kS4Err_NotEnoughShares    ,     "Not enough shares to recombine secret" },
	{ -1            ,           kS4Err_PropertyNotFound    ,     "Property not found" },
	{ -1            ,           kS4Err_ShareOwnerMismatch    ,	"Share does not belong to owner" },

};



#define ERROR_MAP_TABLE_SIZE (sizeof(error_map_table) / sizeof(error_map_entry))

S4Err sCrypt2S4Err(int t_err)
{
    int i;
    
    for(i = 0; i< ERROR_MAP_TABLE_SIZE; i++)
        if(error_map_table[i].code == t_err) return(error_map_table[i].err);
    
    return kS4Err_UnknownError;
}


EXPORT_FUNCTION S4Err  S4_GetErrorString( S4Err err,  char outString[256])
{
    int i;
    *outString = 0;
    
    for(i = 0; i< ERROR_MAP_TABLE_SIZE; i++)
        if(error_map_table[i].err == err)
        {
            strcpy(outString, error_map_table[i].msg);
            return kS4Err_NoErr;
        }
    
    return kS4Err_UnknownError;
}

#ifdef __clang__
#pragma mark - version
#endif


EXPORT_FUNCTION S4Err  S4_GetVersionString(char outString[256])
{
    S4Err                 err = kS4Err_NoErr;
    
    ValidateParam(outString);
    *outString = 0;
    
    char version_string[128];
    
    snprintf(version_string, sizeof(version_string), "%s%s (%03d) %s",
             S4_SHORT_VERSION_STRING,
#if _S4_USES_COMMON_CRYPTO_
             "CC",
#else
             "",
#endif
            S4_BUILD_NUMBER,
             GIT_COMMIT_HASH);
    
//    if(strlen(version_string) +1 > bufSize)
//        RETERR (kS4Err_BufferTooSmall);
//
    strcpy(outString, version_string);
    
done:
    return err;
}

const struct ltc_hash_descriptor* sDescriptorForHash(HASH_Algorithm algorithm)
{
    const struct ltc_hash_descriptor* desc = NULL;
    
    switch(algorithm)
    {
        case  kHASH_Algorithm_MD5:
            desc = &md5_desc;
            break;
            
        case  kHASH_Algorithm_SHA1:
            desc = &sha1_desc;
            break;
            
        case  kHASH_Algorithm_SHA224:
            desc = &sha224_desc;
            break;
            
        case  kHASH_Algorithm_SHA256:
            desc = &sha256_desc;
            break;
            
        case  kHASH_Algorithm_SHA384:
            desc = &sha384_desc;
            break;
            
        case  kHASH_Algorithm_SHA512_256:
            desc = &sha512_256_desc;
            break;
            
        case  kHASH_Algorithm_SHA512:
            desc = &sha512_desc;
            break;
            
        case  kHASH_Algorithm_SKEIN256:
            desc = &skein256_desc;
            break;
            
        case  kHASH_Algorithm_SKEIN512:
            desc = &skein512_desc;
            break;
            
        case  kHASH_Algorithm_SKEIN1024:
            desc = &skein1024_desc;
            break;
            
            // want more... put more descriptors here,
        default:
            break;
            
    }
    
    return desc;
}




static void bin2hex(  uint8_t* inBuf, size_t inLen, uint8_t* outBuf, size_t* outLen)
{
    static          char hexDigit[] = "0123456789ABCDEF";
    register        int    i;
    register        uint8_t* p = outBuf;
    
    for (i = 0; i < inLen; i++)
    {
        *p++  = hexDigit[ inBuf[i] >>4];
        *p++ =  hexDigit[ inBuf[i]  &0xF];
    }
    
    *outLen = p-outBuf;
    
}


EXPORT_FUNCTION S4Err RNG_GetPassPhrase(
                           size_t         bits,
                           char **         outPassPhrase )
{
    S4Err             err = kS4Err_NoErr;

	ValidateParam(outPassPhrase);
    
    size_t              passBytesLen = bits/8;
    uint8_t*            passBytes = XMALLOC(passBytesLen);
    
    size_t              passPhraseLen =   (passBytesLen *2) +1;
    uint8_t*            passPhrase = XMALLOC(passPhraseLen);
    
    err = RNG_GetBytes(passBytes,passBytesLen); CKERR;
    
    bin2hex(passBytes, passBytesLen, passPhrase, &passPhraseLen);
    passPhrase[passPhraseLen] =  '\0' ;
    
	*outPassPhrase = (char*) passPhrase;
    
    done:

	if(err)
		XFREE(passPhrase);
    
    ZERO(passBytes, passBytesLen);
    XFREE(passBytes);
    
    return err;
    
}


EXPORT_FUNCTION S4Err RNG_GetBytes(     void *         out,
                      size_t         outLen
                      )
{
    S4Err             err = kS4Err_NoErr;

#if _S4_USES_COMMON_CRYPTO_
   
   if(  CCRandomGenerateBytes(out, outLen) != kCCSuccess)
       err =  kS4Err_ResourceUnavailable;
 
#else
    unsigned long count  =  sprng_read(out,outLen,NULL);
    
    if(count != outLen)
        err =  kS4Err_ResourceUnavailable;
#endif
    
    return (err);
    
}


typedef struct S4CipherInfo_
{
	char      *const name;
	Cipher_Algorithm algorithm;
	size_t			keybits;
	size_t			blockSize;
	bool			isSymmetric;
	bool			available;
} S4CipherInfo;

static S4CipherInfo sCipherInfoTable[] = {

	{ "AES-128",  kCipher_Algorithm_AES128, 		128, 	16, 	true,true},
	{ "AES-192",  kCipher_Algorithm_AES192, 		192, 	16, 	true,true},
	{ "AES-256",  kCipher_Algorithm_AES256, 		256, 	16, 	true,true},

	{ "Twofish-256", kCipher_Algorithm_2FISH256, 	256, 	16, 	true,true},

 	{"ThreeFish-256", kCipher_Algorithm_3FISH256, 	256, 	32, 	true, true},
	{"ThreeFish-512", kCipher_Algorithm_3FISH512, 	512, 	64, 	true, true},
	{"ThreeFish-1024", kCipher_Algorithm_3FISH1024, 1024, 	128, 	true, true},

	{"ECC-384", 	kCipher_Algorithm_ECC384, 		384, 	48, 	false, true},
	{"Curve41417", 	kCipher_Algorithm_ECC414, 		414, 	52, 	false, true},

	{"SharedKey", 	kCipher_Algorithm_SharedKey, 		0, 	0, 	false, false},	// fill this in..

	{ NULL,    kCipher_Algorithm_Invalid, 			0, 		0, 		true, 	false},
};

 S4CipherInfo* sCipherInfoForAlgorithm(Cipher_Algorithm algorithm)
{
	S4CipherInfo* info = NULL;

	for(S4CipherInfo* cipherInfo = sCipherInfoTable; cipherInfo->name; cipherInfo++)
	{
		if(algorithm == cipherInfo->algorithm)
		{
			info = cipherInfo;
			break;
		}
	}
	return info;
}

EXPORT_FUNCTION bool Cipher_AlgorithmIsAvailable(Cipher_Algorithm algorithm)
{
	bool isAvailable = false;

	S4CipherInfo* cipherInfo = sCipherInfoForAlgorithm(algorithm);
	if(cipherInfo)
	{
		isAvailable = cipherInfo->available;
	}
	return isAvailable;
}


EXPORT_FUNCTION  S4Err Cipher_GetName(Cipher_Algorithm algorithm, const char **cipherName)
{
	S4Err err = kS4Err_FeatureNotAvailable;

	S4CipherInfo* cipherInfo = sCipherInfoForAlgorithm(algorithm);
	if(cipherInfo)
	{
 		if(cipherName)
			*cipherName = cipherInfo->name;
		err = kS4Err_NoErr;
	}

	return err;
}


EXPORT_FUNCTION S4Err Cipher_GetKeySize(Cipher_Algorithm algorithm, size_t *keyBits)
{
	S4Err err = kS4Err_FeatureNotAvailable;

	S4CipherInfo* cipherInfo = sCipherInfoForAlgorithm(algorithm);
	if(cipherInfo)
	{
		if(keyBits)
			*keyBits = cipherInfo->keybits;
		err = kS4Err_NoErr;
	}

	return err;
}

EXPORT_FUNCTION S4Err Cipher_GetBlockSize(Cipher_Algorithm algorithm, size_t *blockSize)
{
	S4Err err = kS4Err_FeatureNotAvailable;

	S4CipherInfo* cipherInfo = sCipherInfoForAlgorithm(algorithm);
	if(cipherInfo)
	{
		if(blockSize)
			*blockSize = cipherInfo->blockSize;
		err = kS4Err_NoErr;
	}

	return err;
}



EXPORT_FUNCTION S4Err Cipher_GetSize(Cipher_Algorithm  algorithm, size_t *bytesOut)
{
    S4Err       err = kS4Err_NoErr;
    size_t      bits = 0;

	err = Cipher_GetKeySize(algorithm, &bits ); CKERR;

    if(bytesOut)
        *bytesOut = bits >> 3;
    
done:
    return (err);
 }

