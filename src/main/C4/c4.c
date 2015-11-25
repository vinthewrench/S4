//
//  C4.c
//  C4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

 #include "c4.h"
#include "c4Internal.h"
  
#ifdef __clang__
#pragma mark - init
#endif


C4Err C4_Init()
{
    C4Err err = kC4Err_NoErr;
    
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
    C4Err       err;
    const   char *msg;
} error_map_entry;

static const error_map_entry error_map_table[] =
{
    { CRYPT_OK,     		kC4Err_NoErr,         "Successful" },
    { CRYPT_ERROR,  		kC4Err_UnknownError,  "Generic Error" },
    { CRYPT_NOP,    		kC4Err_NOP,         	"Non-fatal 'no-operation' requested."},
    { CRYPT_INVALID_ARG, 	kC4Err_BadParams,    	"Invalid argument provided."},
    
    
    { CRYPT_MEM,  			 kC4Err_OutOfMemory,          "Out of memory"},
    { CRYPT_BUFFER_OVERFLOW, kC4Err_BufferTooSmall,       "Not enough space for output"},
    
    { -1, 					kC4Err_UserAbort,             "User Abort"},
    { -1, 					kC4Err_UnknownRequest,        "Unknown Request"},
    { -1,					kC4Err_LazyProgrammer,        "Feature incomplete"},
    
    { -1,                     	kC4Err_FeatureNotAvailable,  "Feature not available" },
    { -1,                       kC4Err_ResourceUnavailable,  "Resource not available" },
    { -1,                       kC4Err_NotConnected,         "Not connected" },
    { -1,                       kC4Err_ImproperInitialization,  "Not Initialized" },
    { CRYPT_INVALID_PACKET,     kC4Err_CorruptData,           "Corrupt Data" },
    { CRYPT_FAIL_TESTVECTOR,    kC4Err_SelfTestFailed,        "Self Test Failed" },
    { -1, 						kC4Err_BadIntegrity,  		"Bad Integrity" },
    { CRYPT_INVALID_HASH, 		kC4Err_BadHashNumber,         "Invalid hash specified" },
    { CRYPT_INVALID_CIPHER, 	kC4Err_BadCipherNumber,       "Invalid cipher specified" },
    { CRYPT_INVALID_PRNG, 		kC4Err_BadPRNGNumber,  		"Invalid PRNG specified" },
    { -1            ,           kC4Err_SecretsMismatch,       "Shared Secret Mismatch" },
    { -1            ,           kC4Err_KeyNotFound,           "Key Not Found" },
    { -1            ,           kC4Err_ProtocolError,        "Protocol Error" },
    { -1            ,           kC4Err_KeyLocked     ,        "Key Locked" },
    { -1            ,           kC4Err_KeyExpired    ,        "Key Expired" },
    { -1            ,           kC4Err_OtherError    ,        "Other Error" },
    
    { -1            ,           kC4Err_NotEnoughShares    ,     "Not enough shares to recombine secret" },
    
    
    
    
};



#define ERROR_MAP_TABLE_SIZE (sizeof(error_map_table) / sizeof(error_map_entry))

C4Err sCrypt2C4Err(int t_err)
{
    int i;
    
    for(i = 0; i< ERROR_MAP_TABLE_SIZE; i++)
        if(error_map_table[i].code == t_err) return(error_map_table[i].err);
    
    return kC4Err_UnknownError;
}


C4Err  C4_GetErrorString( C4Err err,  size_t	bufSize, char *outString)
{
    int i;
    *outString = 0;
    
    for(i = 0; i< ERROR_MAP_TABLE_SIZE; i++)
        if(error_map_table[i].err == err)
        {
            if(strlen(error_map_table[i].msg) +1 > bufSize)
                return (kC4Err_BufferTooSmall);
            strcpy(outString, error_map_table[i].msg);
            return kC4Err_NoErr;
        }
    
    return kC4Err_UnknownError;
}

#ifdef __clang__
#pragma mark - version
#endif


C4Err  C4_GetVersionString(size_t	bufSize, char *outString)
{
    C4Err                 err = kC4Err_NoErr;
    
    ValidateParam(outString);
    *outString = 0;
    
    char version_string[128];
    
    snprintf(version_string, sizeof(version_string), "%s%s (%03d) %s",
             C4_SHORT_VERSION_STRING,
#if _USES_COMMON_CRYPTO_
             "CC",
#else
             "",
#endif
            C4_BUILD_NUMBER,
             GIT_COMMIT_HASH);
    
    if(strlen(version_string) +1 > bufSize)
        RETERR (kC4Err_BufferTooSmall);
    
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


C4Err RNG_GetPassPhrase(
                           size_t         bits,
                           char **         outPassPhrase )
{
    C4Err             err = kC4Err_NoErr;
    
    size_t              passBytesLen = bits/8;
    uint8_t*            passBytes = XMALLOC(passBytesLen);
    
    size_t              passPhraseLen =   (passBytesLen *2) +1;
    uint8_t*            passPhrase = XMALLOC(passPhraseLen);
    
    
    err = RNG_GetBytes(passBytes,passBytesLen); CKERR;
    
    bin2hex(passBytes, passBytesLen, passPhrase, &passPhraseLen);
    passPhrase[passPhraseLen] =  '\0' ;
    
    if(outPassPhrase) *outPassPhrase = (char*) passPhrase;
    
    done:
    
    ZERO(passBytes, passBytesLen);
    XFREE(passBytes);
    
    return err;
    
}


C4Err RNG_GetBytes(     void *         out,
                      size_t         outLen
                      )
{
    C4Err             err = kC4Err_NoErr;

#if _USES_COMMON_CRYPTO_
   
   if(  CCRandomGenerateBytes(out, outLen) != kCCSuccess)
       err =  kC4Err_ResourceUnavailable;
 
#else
    unsigned long count  =  sprng_read(out,outLen,NULL);
    
    if(count != outLen)
        err =  kC4Err_ResourceUnavailable;
#endif
    
    return (err);
    
}


C4Err Cipher_GetSize(Cipher_Algorithm  algorithm, size_t *bitsOut)
{
    C4Err       err = kC4Err_NoErr;
    size_t      bits = 0;
    
    switch(algorithm)
    {
        case kCipher_Algorithm_AES128: bits = 128; break;
        case kCipher_Algorithm_AES192: bits = 192; break;
        case kCipher_Algorithm_AES256: bits = 256; break;
        case kCipher_Algorithm_2FISH256: bits = 128; break;
        case kCipher_Algorithm_3FISH256: bits = 128; break;
        case kCipher_Algorithm_3FISH512: bits = 512; break;
        case kCipher_Algorithm_3FISH1024: bits = 1024; break;
        default:
            RETERR(kC4Err_ResourceUnavailable);
    };
    
    if(bitsOut)
        *bitsOut = bits >> 3;
    
done:
    return (err);
   
}



