//
//  C4.c
//  C4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//


#include <tomcrypt.h>
#include <skein_port.h>
#include <threefishApi.h>


#include "C4.h"

#ifdef __APPLE__
#import "git_version_hash.h"
#else
#define GIT_COMMIT_HASH __DATE__
#endif

#if _USES_COMMON_CRYPTO_
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonRandom.h>

#define kCCHmacAlgInvalid UINT32_MAX

#endif


#define CKSTAT {if (status != CRYPT_OK)  goto done; }

#ifndef roundup
#define	roundup(x, y)	((((x) % (y)) == 0) ? \
(x) : ((x) + ((y) - ((x) % (y)))))
#endif


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


#ifdef __clang__
#pragma mark - Hash
#endif

typedef struct HASH_Context    HASH_Context;

struct HASH_Context
{
#define kHASH_ContextMagic		0x63344861
    uint32_t                magic;
    HASH_Algorithm          algor;
    size_t                  hashsize;

#if _USES_COMMON_CRYPTO_
    CCHmacAlgorithm         ccAlgor;
#endif

     union
    {
        hash_state              tc_state;
#if _USES_COMMON_CRYPTO_
        CC_MD5_CTX              ccMD5_state;
        CC_SHA1_CTX             ccSHA1_state;
        CC_SHA256_CTX           ccSHA256_state;
        CC_SHA512_CTX           ccSHA512_state;
 #endif
        
    }state;

 
    int (*process)(void *ctx, const unsigned char *in, unsigned long inlen);
    
    int (*done)(void *ctx, unsigned char *out);

};


static bool
sHASH_ContextIsValid( const HASH_ContextRef  ref)
{
    bool	valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kHASH_ContextMagic;
    
    return( valid );
}

#define validateHASHContext( s )		\
ValidateParam( sHASH_ContextIsValid( s ) )

C4Err HASH_Import(void *inData, size_t bufSize, HASH_ContextRef * ctx)
{
    C4Err        err = kC4Err_NoErr;
    HASH_Context*   hashCTX = NULL;
    
    ValidateParam(ctx);
    *ctx = NULL;
    
    
    if(sizeof(HASH_Context) != bufSize)
        RETERR( kC4Err_BadParams);
    
    hashCTX = XMALLOC(sizeof (HASH_Context)); CKNULL(hashCTX);
    
    COPY( inData, hashCTX, sizeof(HASH_Context));
    
    validateHASHContext(hashCTX);
    
    *ctx = hashCTX;
    
done:
    
    if(IsC4Err(err))
    {
        if(IsntNull(hashCTX))
        {
            XFREE(hashCTX);
        }
    }
    
    return err;
}

C4Err HASH_Export(HASH_ContextRef ctx, void *outData, size_t bufSize, size_t *datSize)
{
    C4Err        err = kC4Err_NoErr;
    const struct    ltc_hash_descriptor* desc = NULL;
    
    validateHASHContext(ctx);
    ValidateParam(outData);
    ValidateParam(datSize);
    
    desc = sDescriptorForHash(ctx->algor);
    
    if(IsNull(desc))
        RETERR( kC4Err_BadHashNumber);
    
    if(sizeof(HASH_Context) > bufSize)
        RETERR( kC4Err_BufferTooSmall);
    
    COPY( ctx, outData, sizeof(HASH_Context));
    
    *datSize = sizeof(HASH_Context);
    
done:
    
    return err;
    
}

#if  _USES_COMMON_CRYPTO_

int sCCHashUpdateMD5(void *ctx, const unsigned char *in, unsigned long inlen)
{
    CC_MD5_Update(ctx, in, (CC_LONG)inlen);
    return CRYPT_OK;
}

int sCCHashUpdateSHA1(void *ctx, const unsigned char *in, unsigned long inlen)
{
    CC_SHA1_Update(ctx, in, (CC_LONG)inlen);
    return CRYPT_OK;
}

int sCCHashUpdateSHA224(void *ctx, const unsigned char *in, unsigned long inlen)
{
    CC_SHA224_Update(ctx, in, (CC_LONG)inlen);
    return CRYPT_OK;
}

int sCCHashUpdateSHA256(void *ctx, const unsigned char *in, unsigned long inlen)
{
    CC_SHA256_Update(ctx, in, (CC_LONG)inlen);
    return CRYPT_OK;
}

int sCCHashUpdateSHA384(void *ctx, const unsigned char *in, unsigned long inlen)
{
    CC_SHA384_Update(ctx, in, (CC_LONG)inlen);
    return CRYPT_OK;
}

int sCCHashUpdateSHA512(void *ctx, const unsigned char *in, unsigned long inlen)
{
    CC_SHA512_Update(ctx, in, (CC_LONG)inlen);
    return CRYPT_OK;
}


int sCCHashFinalMD5(void *ctx, unsigned char *out)
{
     CC_MD5_Final(out, ctx);
    
#ifdef LTC_CLEAN_STACK
    zeromem(ctx, sizeof(CC_SHA1_CTX));
#endif
    
    return CRYPT_OK;
}

int sCCHashFinalSHA1(void *ctx, unsigned char *out)
{
    CC_SHA1_Final(out, ctx);
    
#ifdef LTC_CLEAN_STACK
    zeromem(ctx, sizeof(CC_SHA1_CTX));
#endif
    
    return CRYPT_OK;
 }

int sCCHashFinalSHA224(void *ctx, unsigned char *out)
{
    CC_SHA224_Final(out, ctx);
    
#ifdef LTC_CLEAN_STACK
    zeromem(ctx, sizeof(CC_SHA1_CTX));
#endif
    
    return CRYPT_OK;
}

int sCCHashFinalSHA256(void *ctx, unsigned char *out)
{
    CC_SHA256_Final(out, ctx);
    
#ifdef LTC_CLEAN_STACK
    zeromem(ctx, sizeof(CC_SHA1_CTX));
#endif
    
    return CRYPT_OK;
}


int sCCHashFinalSHA384(void *ctx, unsigned char *out)
{
    CC_SHA384_Final(out, ctx);
    
#ifdef LTC_CLEAN_STACK
    zeromem(ctx, sizeof(CC_SHA1_CTX));
#endif
    
    return CRYPT_OK;
}


int sCCHashFinalSHA512(void *ctx, unsigned char *out)
{
    CC_SHA512_Final(out, ctx);
    
#ifdef LTC_CLEAN_STACK
    zeromem(ctx, sizeof(CC_SHA1_CTX));
#endif
    
    return CRYPT_OK;
}

#endif


C4Err HASH_Init(HASH_Algorithm algorithm, HASH_ContextRef * ctx)
{
    int             err = kC4Err_NoErr;
    HASH_Context*   hashCTX = NULL;
    const struct ltc_hash_descriptor* desc = NULL;
    
    ValidateParam(ctx);
    *ctx = NULL;
    
    hashCTX = XMALLOC(sizeof (HASH_Context)); CKNULL(hashCTX);
    
    hashCTX->magic = kHASH_ContextMagic;
    hashCTX->algor = algorithm;
    
#if _USES_COMMON_CRYPTO_
    
    switch(algorithm)
    {
        case kHASH_Algorithm_MD5:
            hashCTX->ccAlgor = kCCHmacAlgMD5;
            hashCTX->process = (void*) sCCHashUpdateMD5;
            hashCTX->done = (void*) sCCHashFinalMD5;
            hashCTX->hashsize = 16;
            CC_MD5_Init(&hashCTX->state.ccMD5_state);
             break;
            
        case kHASH_Algorithm_SHA1:
            hashCTX->ccAlgor = kCCHmacAlgSHA1;
            hashCTX->hashsize = 20;
            hashCTX->process = (void*) sCCHashUpdateSHA1;
            hashCTX->done = (void*) sCCHashFinalSHA1;;
           CC_SHA1_Init(&hashCTX->state.ccSHA1_state);
            break;
            
        case kHASH_Algorithm_SHA224:
            hashCTX->ccAlgor = kCCHmacAlgSHA224;
            hashCTX->hashsize = 28;
            hashCTX->process = (void*) sCCHashUpdateSHA224;
            hashCTX->done = (void*) sCCHashFinalSHA224;
            CC_SHA224_Init(&hashCTX->state.ccSHA256_state);
            break;
            
        case kHASH_Algorithm_SHA256:
            hashCTX->ccAlgor = kCCHmacAlgSHA256;
            hashCTX->hashsize = 32;
            hashCTX->process = (void*) sCCHashUpdateSHA256;
            hashCTX->done = (void*) sCCHashFinalSHA256;;
           CC_SHA256_Init(&hashCTX->state.ccSHA256_state);
            break;
            
        case kHASH_Algorithm_SHA384:
            hashCTX->ccAlgor = kCCHmacAlgSHA384;
            hashCTX->hashsize = 48;
            hashCTX->process = (void*) sCCHashUpdateSHA384;
            hashCTX->done = (void*) sCCHashFinalSHA384;
           CC_SHA384_Init(&hashCTX->state.ccSHA512_state);
            break;
            
        case kHASH_Algorithm_SHA512:
            hashCTX->ccAlgor = kCCHmacAlgSHA512;
            hashCTX->hashsize = 64;
            hashCTX->process = (void*) sCCHashUpdateSHA512;
            hashCTX->done = (void*) sCCHashFinalSHA512;
            CC_SHA512_Init(&hashCTX->state.ccSHA512_state);
            break;
            
        default:
            hashCTX->ccAlgor =  kCCHmacAlgInvalid;
            break;
    }
    
      if(hashCTX->ccAlgor == kCCHmacAlgInvalid)
    {
        desc = sDescriptorForHash(algorithm);
        hashCTX->hashsize = desc->hashsize;
        hashCTX->process = (void*) desc->process;
        hashCTX->done =     (void*) desc->done;
        
        if(IsNull(desc))
            RETERR( kC4Err_BadHashNumber);
        
        if(desc->init)
            err = (desc->init)(&hashCTX->state.tc_state);
        CKERR;
        
    }
    
#else
    
    desc = sDescriptorForHash(algorithm);
    hashCTX->hashsize = desc->hashsize;
    hashCTX->process = (void*) desc->process;
    hashCTX->done =     (void*) desc->done;
    
    if(IsNull(desc))
        RETERR( kC4Err_BadHashNumber);
 
    
    if(desc->init)
        err = (desc->init)(&hashCTX->state.tc_state);
    CKERR;
    
#endif

    *ctx = hashCTX;
    
done:
    
    
    if(IsC4Err(err))
    {
        if(IsntNull(hashCTX))
        {
            XFREE(hashCTX);
        }
    }
    
    return err;
    
}

C4Err HASH_Update(HASH_ContextRef ctx, const void *data, size_t dataLength)
{
    int             err = kC4Err_NoErr;
//    const struct    ltc_hash_descriptor* desc = NULL;
    
    validateHASHContext(ctx);
    ValidateParam(data);
    
    if(ctx->process)
        err = (ctx->process)(&ctx->state,  data, dataLength );
//    
//
//    desc = sDescriptorForHash(ctx->algor);
//    
//    if(IsNull(desc))
//        RETERR( kC4Err_BadHashNumber);
//    
//    if(desc->process)
//        err = (desc->process)(&ctx->state.tc_state,data,  dataLength );
//    CKERR;
//    
//done:
    
    return err;
    
}



C4Err HASH_Final(HASH_ContextRef  ctx, void *hashOut)
{
    int             err = kC4Err_NoErr;
//    const struct    ltc_hash_descriptor* desc = NULL;
    
    validateHASHContext(ctx);
    
    if(ctx->done)
        err = (ctx->done)(&ctx->state, hashOut );
//    
//    
//    desc = sDescriptorForHash(ctx->algor);
//    
//    if(IsNull(desc))
//        RETERR( kC4Err_BadHashNumber);
//    
//    if(desc->done)
//        err = (desc->done)(&ctx->state.tc_state, hashOut );
//    CKERR;
//    
//done:
//    
    return err;
}

void HASH_Free(HASH_ContextRef  ctx)
{
    if(sHASH_ContextIsValid(ctx))
    {
        ZERO(ctx, sizeof(HASH_Context));
        XFREE(ctx);
    }
}

C4Err HASH_GetSize(HASH_ContextRef  ctx, size_t *hashSize)
{
    int             err = kC4Err_NoErr;
    
     validateHASHContext(ctx);
    
    *hashSize = ctx->hashsize;
    
    return err;
}


C4Err HASH_DO(HASH_Algorithm algorithm, const unsigned char *in, unsigned long inlen, unsigned long outLen, uint8_t *out)
{
    
    C4Err             err         = kC4Err_NoErr;
    HASH_ContextRef     hashRef     = kInvalidHASH_ContextRef;
    uint8_t             hashBuf[128];
    uint8_t             *p = (outLen < sizeof(hashBuf))?hashBuf:out;
    
    
#if  _USES_COMMON_CRYPTO_

/* use apple algorithms if possible*/
    switch(algorithm)
    {
        case kHASH_Algorithm_MD5:
            CC_MD5(in, (CC_LONG) inlen, hashBuf);
            goto complete;
            break;
            
          case  kHASH_Algorithm_SHA1:
            CC_SHA1(in, (CC_LONG) inlen, hashBuf);
            goto complete;
            break;
            
        case  kHASH_Algorithm_SHA224:
            CC_SHA224(in, (CC_LONG) inlen, hashBuf);
            goto complete;
            break;
            
        case  kHASH_Algorithm_SHA256:
            CC_SHA256(in, (CC_LONG) inlen, hashBuf);
            goto complete;
            break;
         
        case  kHASH_Algorithm_SHA384:
            CC_SHA384(in, (CC_LONG) inlen, hashBuf);
            goto complete;
            break;
          
        case  kHASH_Algorithm_SHA512:
            CC_SHA512(in, (CC_LONG) inlen, hashBuf);
            goto complete;
            break;
            
      default:
            break;
    }
    
#endif
    
    err = HASH_Init( algorithm, & hashRef); CKERR;
    err = HASH_Update( hashRef, in,  inlen); CKERR;
    err = HASH_Final( hashRef, p); CKERR;
 
complete:
    if((err == kC4Err_NoErr) & (p!= out))
        COPY(hashBuf, out, outLen);
    
done:
    if(!IsNull(hashRef))
        HASH_Free(hashRef);
    
    return err;
}



#ifdef __clang__
#pragma mark - MAC
#endif


typedef struct MAC_Context    MAC_Context;

struct MAC_Context
{
#define kMAC_ContextMagic		0x63344D61
    uint32_t                magic;
    MAC_Algorithm           macAlgor;
    
#if  _USES_COMMON_CRYPTO_
    CCHmacAlgorithm         ccAlgor;
#endif
    
    size_t                  hashsize;
    
    union
    {
        hmac_state              hmac;
        skeinmac_state          skeinmac;
#if  _USES_COMMON_CRYPTO_
        CCHmacContext           ccMac;
#endif
   }state;
    
    int (*process)(void *ctx, const unsigned char *in, unsigned long inlen);
    
    int (*done)(void *ctx, unsigned char *out, unsigned long *outlen);
    
};


/*____________________________________________________________________________
 validity test
 ____________________________________________________________________________*/

static bool sMAC_ContextIsValid( const MAC_ContextRef  ref)
{
    bool	valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kMAC_ContextMagic;
    
    return( valid );
}

#define validateMACContext( s )		\
ValidateParam( sMAC_ContextIsValid( s ) )

#if  _USES_COMMON_CRYPTO_


int sCCMacUpdate(CCHmacContext *ctx, const unsigned char *in, unsigned long inlen)
{
    CCHmacUpdate(ctx, in, inlen);
    
    return CRYPT_OK;
}


int sCCMacFinal(CCHmacContext *ctx, unsigned char *out, unsigned long *outlen)
{
    
    u08b_t    macBuf[64];
    u08b_t    *p = (*outlen < sizeof(macBuf))?macBuf:out;
    
    CCHmacFinal(ctx, p);
    
    if(p!= out)
        memcpy( out,macBuf, *outlen);
    
    
#ifdef LTC_CLEAN_STACK
    zeromem(ctx, sizeof(CCHmacContext));
    zeromem(macBuf, sizeof(macBuf));
#endif
    
    return CRYPT_OK;
}


#endif

C4Err MAC_Init(MAC_Algorithm mac, HASH_Algorithm hash, const void *macKey, size_t macKeyLen, MAC_ContextRef * ctx)
{
    int             err = kC4Err_NoErr;
    const struct    ltc_hash_descriptor* hashDesc = NULL;
    MAC_Context*   macCTX = NULL;
    
    ValidateParam(ctx);
    *ctx = NULL;
    
    hashDesc = sDescriptorForHash(hash);
    
    if(IsNull(hashDesc))
        RETERR( kC4Err_BadHashNumber);
    
    
    macCTX = XMALLOC(sizeof (MAC_Context)); CKNULL(macCTX);
    
    macCTX->magic = kMAC_ContextMagic;
    macCTX->macAlgor = mac;
    macCTX->hashsize = 0;

 
    switch(mac)
    {
        case  kMAC_Algorithm_HMAC:
            
#if  _USES_COMMON_CRYPTO_
     
        switch(hash)
        {
            case kHASH_Algorithm_MD5:
                macCTX->ccAlgor = kCCHmacAlgMD5;
                macCTX->hashsize = 16;
                break;
                
            case kHASH_Algorithm_SHA1:
                macCTX->ccAlgor = kCCHmacAlgSHA1;
                macCTX->hashsize = 20;
                break;
                
            case kHASH_Algorithm_SHA224:
                macCTX->ccAlgor = kCCHmacAlgSHA224;
                macCTX->hashsize = 28;
                break;
                
            case kHASH_Algorithm_SHA384:
                macCTX->ccAlgor = kCCHmacAlgSHA384;
                macCTX->hashsize = 48;
                break;
                
            case kHASH_Algorithm_SHA256:
                macCTX->ccAlgor = kCCHmacAlgSHA256;
                macCTX->hashsize = 32;
                break;
                
            case kHASH_Algorithm_SHA512:
                macCTX->ccAlgor = kCCHmacAlgSHA512;
                macCTX->hashsize = 64;
                break;
                
            default:
                macCTX->ccAlgor =  kCCHmacAlgInvalid;
                break;
        }

        if(macCTX->ccAlgor != kCCHmacAlgInvalid)
        {
            CCHmacInit(&macCTX->state.ccMac, macCTX->ccAlgor, macKey, macKeyLen);
            macCTX->process = (void*) sCCMacUpdate;
            macCTX->done = (void*) sCCMacFinal;
        }
        else
        {
            err = hmac_init(&macCTX->state.hmac,  find_hash_id(hashDesc->ID) , macKey, macKeyLen) ; CKERR;
            macCTX->process = (void*) hmac_process;
            macCTX->done = (void*) hmac_done;
            macCTX->hashsize = hashDesc->hashsize;
        }
                
#else
            
            err = hmac_init(&macCTX->state.hmac,  find_hash_id(hashDesc->ID) , macKey, macKeyLen) ; CKERR;
            macCTX->process = (void*) hmac_process;
            macCTX->done = (void*) hmac_done;
            macCTX->hashsize = hashDesc->hashsize;
            
#endif
            break;
            
        case  kMAC_Algorithm_SKEIN:
        {
            switch(hash)
            {
                    
                case kHASH_Algorithm_SKEIN256:
                    err = skeinmac_init(&macCTX->state.skeinmac, Skein256, macKey, macKeyLen);
                    macCTX->process = (void*) skeinmac_process;
                    macCTX->done = (void*) skeinmac_done;
                    macCTX->hashsize = 32;
                    break;
                    
                case kHASH_Algorithm_SKEIN512:
                    err = skeinmac_init(&macCTX->state.skeinmac, Skein512, macKey, macKeyLen);
                    macCTX->process = (void*) skeinmac_process;
                    macCTX->done = (void*) skeinmac_done;
                    macCTX->hashsize = 64;
                    break;
                    
                default:
                    RETERR( kC4Err_BadHashNumber) ;
            }
        }
            break;
            
        default:
            RETERR( kC4Err_BadHashNumber) ;
    }
    
    *ctx = macCTX;
    
done:
    
    if(IsC4Err(err))
    {
        if(IsntNull(macCTX))
        {
            XFREE(macCTX);
        }
    }
    return err;
    
}


C4Err MAC_HashSize( MAC_ContextRef  ctx, size_t * bytes)
{
    int  err = kC4Err_NoErr;
    
    validateMACContext(ctx);
    
    *bytes = ctx->hashsize;
    
    // done:
    
    return (err);
}


C4Err MAC_Update(MAC_ContextRef  ctx, const void *data, size_t dataLength)
{
    int             err = kC4Err_NoErr;
    
    validateMACContext(ctx);
    
    if(ctx->process)
        err = (ctx->process)(&ctx->state,  data, dataLength );
    
    return (err);
}

C4Err MAC_Final(MAC_ContextRef  ctx, void *macOut,  size_t *resultLen)
{
    int             err = kC4Err_NoErr;
    unsigned long  outlen = *resultLen;
    
    validateMACContext(ctx);
    
    if(ctx->done)
        err = (ctx->done)(&ctx->state,  macOut, &outlen );
    
    return err;
    
}



void MAC_Free(MAC_ContextRef  ctx)
{
    
    if(sMAC_ContextIsValid(ctx))
    {
        ZERO(ctx, sizeof(MAC_Context));
        XFREE(ctx);
    }
}


C4Err  MAC_KDF(  MAC_Algorithm      mac,
                 HASH_Algorithm     hash,
                 uint8_t*           K,
                 unsigned long      Klen,
                 const char*        label,
                 const uint8_t*     context,
                 unsigned long      contextLen,
                 uint32_t           hashLen,
                 unsigned long      outLen,
                 uint8_t            *out)
{
    C4Err             err = kC4Err_NoErr;
    MAC_ContextRef       macRef = kInvalidMAC_ContextRef;
    uint8_t              L[4];
    size_t               resultLen = 0;
    
    L[0] = (hashLen >> 24) & 0xff;
    L[1] = (hashLen >> 16) & 0xff;
    L[2] = (hashLen >> 8) & 0xff;
    L[3] = hashLen & 0xff;
    
    err  = MAC_Init( mac,
                    hash,
                    K, Klen, &macRef); CKERR;
    
    MAC_Update(macRef,  "\x00\x00\x00\x01",  4);
    MAC_Update(macRef,  label,  strlen(label));
    MAC_Update(macRef,  "\x00",  1);
    MAC_Update(macRef,  context, contextLen);
    MAC_Update(macRef,  L,  4);
    
    resultLen = outLen;
    MAC_Final( macRef, out, &resultLen);
    
done:
    
    if(IsntNull(macRef))
        MAC_Free(macRef);
    
    return err;
}


#ifdef __clang__
#pragma mark - EBC Symmetric Crypto
#endif

C4Err ECB_Encrypt(Cipher_Algorithm algorithm,
                     const void *	key,
                     const void *	in,
                     size_t         bytesIn,
                     void *         out )
{
    int             err = kC4Err_NoErr;
    int             status  =  CRYPT_OK;
    symmetric_ECB   ECB;
    
    int             keylen  = 0;
    int             cipher  = -1;
    
    switch(algorithm)
    {
        case kCipher_Algorithm_AES128:
            keylen = 128 >> 3;
            cipher = find_cipher("aes");
            
            break;
        case kCipher_Algorithm_AES192:
            keylen = 192 >> 3;
            cipher = find_cipher("aes");
            
            break;
        case kCipher_Algorithm_AES256:
            keylen = 256 >> 3;
            cipher = find_cipher("aes");
            break;
            
        case kCipher_Algorithm_2FISH256:
            keylen = 256 >> 3;
            cipher = find_cipher("twofish");
            break;
            
        default:
            RETERR(kC4Err_BadCipherNumber);
    }
    
    status  = ecb_start(cipher, key, keylen, 0, &ECB ); CKSTAT;
    
    status  = ecb_encrypt(in, out, bytesIn, &ECB); CKSTAT;
    
    
done:
    
    ecb_done(&ECB);
    
    if(status != CRYPT_OK)
        err = sCrypt2C4Err(status);
    
    return err;
    
}


C4Err ECB_Decrypt(Cipher_Algorithm algorithm,
                     const void *	key,
                     const void *	in,
                     size_t         bytesIn,
                     void *         out )
{
    int             err = kC4Err_NoErr;
    int             status  =  CRYPT_OK;
    symmetric_ECB   ECB;
    
    int             keylen  = 0;
    int             cipher  = -1;
    
    switch(algorithm)
    {
        case kCipher_Algorithm_AES128:
            keylen = 128 >> 3;
            cipher = find_cipher("aes");
            
            break;
        case kCipher_Algorithm_AES192:
            keylen = 192 >> 3;
            cipher = find_cipher("aes");
            
            break;
        case kCipher_Algorithm_AES256:
            keylen = 256 >> 3;
            cipher = find_cipher("aes");
            break;
            
        case kCipher_Algorithm_2FISH256:
            keylen = 256 >> 3;
            cipher = find_cipher("twofish");
            break;
            
        default:
            RETERR(kC4Err_BadCipherNumber);
    }
    
    status  = ecb_start(cipher, key, keylen, 0, &ECB ); CKSTAT;
    
    status  = ecb_decrypt(in, out, bytesIn, &ECB); CKSTAT;
    
    
done:
    
    ecb_done(&ECB);
    
    if(status != CRYPT_OK)
        err = sCrypt2C4Err(status);
    
    return err;
}


#ifdef __clang__
#pragma mark - tweakable block cipher functions
#endif

typedef struct TBC_Context    TBC_Context;

struct TBC_Context
{
#define kTBC_ContextMagic		0x43347462
    uint32_t            magic;
    TBC_Algorithm       algor;
    
    int                 keybits;
     u64b_t             key[16];        // need a copy of key to reset the state
    
    ThreefishKey_t       state;
};


static bool sTBC_ContextIsValid( const TBC_ContextRef  ref)
{
    bool       valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kTBC_ContextMagic;
    
    return( valid );
}



#define validateTBCContext( s )		\
ValidateParam( sTBC_ContextIsValid( s ) )


C4Err TBC_Init(TBC_Algorithm algorithm,
               const void *key,
               TBC_ContextRef * ctxOut)
{
    int             err     = kC4Err_NoErr;
    TBC_Context*    tbcCTX  = NULL;
    int             keybits  = 0;
    u64b_t          tweek[3] = {0L,0L };

    ValidateParam(ctxOut);
    
    switch(algorithm)
    {
        case kTBC_Algorithm_3FISH256:
            keybits = Threefish256;
             break;
            
        case kTBC_Algorithm_3FISH512:
            keybits = Threefish512;
             break;
  
        case kTBC_Algorithm_3FISH1024:
            keybits = Threefish1024 ;
            break;
            
          default:
            RETERR(kC4Err_BadCipherNumber);
    }
    
    
    tbcCTX = XMALLOC(sizeof (TBC_Context)); CKNULL(tbcCTX);
    
    tbcCTX->magic = kTBC_ContextMagic;
    tbcCTX->algor = algorithm;
    tbcCTX->keybits = keybits;
    
    Skein_Get64_LSB_First(tbcCTX->key, key, tbcCTX->keybits >>5);   /* bytes to words */
    
    threefishSetKey(&tbcCTX->state, tbcCTX->keybits, tbcCTX->key, tweek);
    
    *ctxOut = tbcCTX;
    
done:
    
    if(IsC4Err(err))
    {
        if(tbcCTX)
        {
            memset(tbcCTX, sizeof (TBC_Context), 0);
            XFREE(tbcCTX);
        }
     }
    
    return err;
  
}

void TBC_Free(TBC_ContextRef  ctx)
{
    
    if(sTBC_ContextIsValid(ctx))
    {
        ZERO(ctx, sizeof(TBC_Context));
        XFREE(ctx);
    }
}


C4Err TBC_SetTweek(TBC_ContextRef ctx,
                   const void *	tweekIn)
{
    C4Err       err = kC4Err_NoErr;
    u64b_t      tweek[2] = {0L,0L};
    
    validateTBCContext(ctx);
    
    Skein_Get64_LSB_First(tweek, tweekIn, 2);   /* bytes to words */
    
    threefishSetKey(&ctx->state, ctx->keybits, ctx->key, tweek);
 
    return (err);
   
}

C4Err TBC_Encrypt(TBC_ContextRef ctx,
                  const void *	in,
                  void *         out )
{
    C4Err       err = kC4Err_NoErr;
   
    validateTBCContext(ctx);
    
    threefishEncryptBlockBytes(&ctx->state,(uint8_t*) in, out);
    
    return (err);

}

C4Err TBC_Decrypt(TBC_ContextRef ctx,
                  const void *	in,
                  void *         out )
{
    C4Err       err = kC4Err_NoErr;
    
    validateTBCContext(ctx);
    
    threefishDecryptBlockBytes(&ctx->state,(uint8_t*) in, out);
    
    return (err);
}


#ifdef __clang__
#pragma mark - CBC Symmetric crypto
#endif

typedef struct CBC_Context    CBC_Context;

struct CBC_Context
{
#define kCBC_ContextMagic		0x43346362 
    uint32_t            magic;
    Cipher_Algorithm    algor;
    symmetric_CBC       state;
};



static bool sCBC_ContextIsValid( const CBC_ContextRef  ref)
{
    bool       valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kCBC_ContextMagic;
    
    return( valid );
}





#define validateCBCContext( s )		\
ValidateParam( sCBC_ContextIsValid( s ) )


C4Err CBC_Init(Cipher_Algorithm algorithm,
                  const void *key,
                  const void *iv,
                  CBC_ContextRef * ctxOut)
{
    int             err     = kC4Err_NoErr;
    CBC_Context*    cbcCTX  = NULL;
    int             keylen  = 0;
    int             cipher  = -1;
    int             status  =  CRYPT_OK;
    
    ValidateParam(ctxOut);
    
    switch(algorithm)
    {
        case kCipher_Algorithm_AES128:
            keylen = 128 >> 3;
            cipher = find_cipher("aes");
            
            break;
        case kCipher_Algorithm_AES192:
            keylen = 192 >> 3;
            cipher = find_cipher("aes");
            
            break;
        case kCipher_Algorithm_AES256:
            keylen = 256 >> 3;
            cipher = find_cipher("aes");
            break;
            
        case kCipher_Algorithm_2FISH256:
            keylen = 256 >> 3;
            cipher = find_cipher("twofish");
            break;
            
        default:
            RETERR(kC4Err_BadCipherNumber);
    }
    
    
    cbcCTX = XMALLOC(sizeof (CBC_Context)); CKNULL(cbcCTX);
    
    cbcCTX->magic = kCBC_ContextMagic;
    cbcCTX->algor = algorithm;
    
    status = cbc_start(cipher, iv, key, keylen, 0, &cbcCTX->state); CKSTAT;
    
    *ctxOut = cbcCTX;
    
done:
    
    if(status != CRYPT_OK)
    {
        if(cbcCTX)
        {
            memset(cbcCTX, sizeof (CBC_Context), 0);
            XFREE(cbcCTX);
        }
        err = sCrypt2C4Err(status);
    }
    
    return err;
}

C4Err CBC_Encrypt(CBC_ContextRef ctx,
                     const void *	in,
                     size_t         bytesIn,
                     void *         out )
{
    C4Err           err = kC4Err_NoErr;
    int             status  =  CRYPT_OK;
    
    validateCBCContext(ctx);
    
    
    status = cbc_encrypt(in, out, bytesIn, &ctx->state);
    
    err = sCrypt2C4Err(status);
    
    return (err);
    
}

C4Err CBC_Decrypt(CBC_ContextRef ctx,
                     const void *	in,
                     size_t         bytesIn,
                     void *         out )
{
    C4Err           err = kC4Err_NoErr;
    int             status  =  CRYPT_OK;
    
    validateCBCContext(ctx);
    
    
    status = cbc_decrypt(in, out, bytesIn, &ctx->state);
    
    err = sCrypt2C4Err(status);
    
    return (err);
    
}

void CBC_Free(CBC_ContextRef  ctx)
{
    
    if(sCBC_ContextIsValid(ctx))
    {
        cbc_done(&ctx->state);
        ZERO(ctx, sizeof(CBC_Context));
        XFREE(ctx);
    }
}



#define MIN_MSG_BLOCKSIZE   32
#define MSG_BLOCKSIZE   16

C4Err CBC_EncryptPAD(Cipher_Algorithm algorithm,
                     uint8_t *key, size_t key_len,
                     const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t **outData, size_t *outSize)
{
    C4Err    err     = kC4Err_NoErr;
    CBC_ContextRef      cbc = kInvalidCBC_ContextRef;
    
    uint8_t     bytes2Pad;
    uint8_t     *buffer = NULL;
    size_t      buffLen = 0;
    
    /* check Key length and algorithm */
    switch(algorithm)
    {
        case kCipher_Algorithm_AES128:
            ValidateParam (key_len == 16); break;
            
        case kCipher_Algorithm_AES192:
            ValidateParam (key_len == 24); break;
            
        case kCipher_Algorithm_AES256:
            ValidateParam (key_len == 32); break;
            
        case kCipher_Algorithm_2FISH256:
            ValidateParam (key_len == 32); break;
            
        default:
            RETERR(kC4Err_BadParams);
    }
    
    
    /* calclulate Pad byte */
    if(in_len < MIN_MSG_BLOCKSIZE)
    {
        bytes2Pad =  MIN_MSG_BLOCKSIZE - in_len;
    }
    else
    {
        bytes2Pad =  roundup(in_len, MSG_BLOCKSIZE) +  MSG_BLOCKSIZE - in_len;
    };
    
    buffLen = in_len + bytes2Pad;
    buffer = XMALLOC(buffLen);
    
    memcpy(buffer, in, in_len);
    memset(buffer+in_len, bytes2Pad, bytes2Pad);
    
    err = CBC_Init(algorithm, key, iv,  &cbc);CKERR;
    
    err = CBC_Encrypt(cbc, buffer, buffLen, buffer); CKERR;
    
    
    *outData = buffer;
    *outSize = buffLen;
    
done:
    
    if(IsC4Err(err))
    {
        if(buffer)
        {
            memset(buffer, buffLen, 0);
            XFREE(buffer);
        }
    }
    
    CBC_Free(cbc);
    
    return err;
}



C4Err CBC_DecryptPAD(Cipher_Algorithm algorithm,
                     uint8_t *key, size_t key_len,
                     const uint8_t *iv,
                     const uint8_t *in, size_t in_len,
                     uint8_t **outData, size_t *outSize)

{
    C4Err err = kC4Err_NoErr;
    CBC_ContextRef      cbc = kInvalidCBC_ContextRef;
    
    uint8_t *buffer = NULL;
    size_t buffLen = in_len;
    uint8_t  bytes2Pad = 0;
    
    /* check Key length and algorithm */
    switch(algorithm)
    {
        case kCipher_Algorithm_AES128:
            ValidateParam (key_len == 16); break;
            
        case kCipher_Algorithm_AES192:
            ValidateParam (key_len == 24); break;
            
        case kCipher_Algorithm_AES256:
            ValidateParam (key_len == 32); break;
            
        case kCipher_Algorithm_2FISH256:
            ValidateParam (key_len == 32); break;
            
        default:
            RETERR(kC4Err_BadParams);
    }
    
    buffer = XMALLOC(buffLen);
    
    err = CBC_Init(algorithm, key, iv,  &cbc);CKERR;
    
    err = CBC_Decrypt(cbc, in, buffLen, buffer); CKERR;
    
    bytes2Pad = *(buffer+buffLen-1);
    
    if(bytes2Pad > buffLen)
        RETERR(kC4Err_CorruptData);
    
    *outData = buffer;
    *outSize = buffLen- bytes2Pad;
    
    
done:
    if(IsC4Err(err))
    {
        if(buffer)
        {
            memset(buffer, buffLen, 0);
            XFREE(buffer);
        }
    }
    
    CBC_Free(cbc);
    
    return err;
    
}


#ifdef __clang__
#pragma mark - ECC / Public Key
#endif


/*____________________________________________________________________________
 ECC wrappers
 ____________________________________________________________________________*/



typedef struct ECC_Context    ECC_Context;

struct ECC_Context
{
#define kECC_ContextMagic		0x63344543
    uint32_t                    magic;
    ecc_key                     key;
    bool                        isInited;
    bool                        isBLCurve;
};


/*____________________________________________________________________________
 validity test
 ____________________________________________________________________________*/

static bool
sECC_ContextIsValid( const ECC_ContextRef  ref)
{
    bool       valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kECC_ContextMagic;
    
    return( valid );
}

#define validateECCContext( s )		\
ValidateParam( sECC_ContextIsValid( s ) )


C4Err ECC_Init(ECC_ContextRef * ctx)
{
    C4Err           err = kC4Err_NoErr;
    ECC_Context*    eccCTX = kInvalidECC_ContextRef;
    
    ValidateParam(ctx);
    
    eccCTX = XMALLOC(sizeof (ECC_Context)); CKNULL(eccCTX);
    
    eccCTX->magic = kECC_ContextMagic;
    
    CKERR;
    
    *ctx = eccCTX;
    
done:
    
    return err;
    
}


C4Err ECC_Generate(ECC_ContextRef  ctx, size_t keysize )
{
    C4Err   err = kC4Err_NoErr;
    
    validateECCContext(ctx);
    
    if(keysize == 414)
    {
        ctx->isBLCurve = true;
        err = ecc_bl_make_key(NULL, find_prng("sprng"),  (int) keysize/8, &ctx->key);CKERR;
        
    }
    else
    {
        ctx->isBLCurve = false;
        err = ecc_make_key(NULL, find_prng("sprng"),   (int)keysize/8, &ctx->key);CKERR;
    }
    
    ctx->isInited = true;
    
done:
    
    return (err);
    
}

bool ECC_isPrivate(ECC_ContextRef  ctx )
{
    bool isPrivate = false;
    
    if(sECC_ContextIsValid(ctx))
        isPrivate = ctx->key.type == PK_PRIVATE;
    
    return (isPrivate);
    
}



void ECC_Free(ECC_ContextRef  ctx)
{
    
    if(sECC_ContextIsValid(ctx))
    {
        
        if(ctx->isInited) ecc_free( &ctx->key);
        ZERO(ctx, sizeof(ECC_Context));
        XFREE(ctx);
    }
}

C4Err ECC_Export_ANSI_X963(ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *datSize)
{
    C4Err           err = kC4Err_NoErr;
    unsigned long   length = bufSize;
    
    validateECCContext(ctx);
    
    ValidateParam(ctx->isInited);
    
    err = ecc_ansi_x963_export(&ctx->key, outData, &length); CKERR;
    
    *datSize = length;
    
done:
    
    return (err);
    
}


C4Err ECC_Import_ANSI_X963(ECC_ContextRef  ctx,   void *in, size_t inlen )
{
    C4Err       err = kC4Err_NoErr;
    
    validateECCContext(ctx);
    
    
    bool isPrivate = false;
    size_t  importKeySize = 0;
    bool isANSIx963 = false;
    
    err = ECC_Import_Info( in, inlen, &isPrivate, &isANSIx963, &importKeySize );CKERR;
    
    ValidateParam(isANSIx963 && !isPrivate)
    
    if(importKeySize > 384)
    {
        err = ecc_bl_ansi_x963_import(in, inlen, &ctx->key); CKERR;
        ctx->isBLCurve = true;
    }
    else
    {
        err = ecc_ansi_x963_import(in, inlen, &ctx->key); CKERR;
        ctx->isBLCurve = false;
    }
    ctx->isInited = true;
    
    
done:
    
    return (err);
    
}

C4Err ECC_Export(ECC_ContextRef  ctx, int exportPrivate, void *outData, size_t bufSize, size_t *datSize)
{
    C4Err           err = kC4Err_NoErr;
    unsigned long   length = bufSize;
    int             keyType = PK_PUBLIC;
    
    validateECCContext(ctx);
    
    ValidateParam(ctx->isInited);
    
    keyType =  exportPrivate?PK_PRIVATE:PK_PUBLIC;
    
    err = ecc_export(outData, &length, keyType, &ctx->key); CKERR;
    
    *datSize = length;
    
done:
    
    return (err);
    
}


C4Err ECC_Import(ECC_ContextRef  ctx,   void *in, size_t inlen )
{
    C4Err       err = kC4Err_NoErr;
    
    validateECCContext(ctx);
    
    
    bool isPrivate = false;
    size_t  importKeySize = 0;
    bool isANSIx963 = false;
    
    err = ECC_Import_Info( in, inlen, &isPrivate, &isANSIx963, &importKeySize );CKERR;
    
    ValidateParam(!isANSIx963 )
    
    if(importKeySize > 384)
    {
        err = ecc_bl_import(in, inlen, &ctx->key); CKERR;
        ctx->isBLCurve = true;
    }
    else
    {
        err = ecc_import(in, inlen, &ctx->key); CKERR;
        ctx->isBLCurve = false;
    }
    
    
    ctx->isInited = true;
    
    
done:
    
    return (err);
    
}

C4Err ECC_Import_Info( void *in, size_t inlen,
                         bool *isPrivate,
                         bool *isANSIx963,
                         size_t *keySizeOut  )
{
    C4Err           err = kC4Err_NoErr;
    int             status  =  CRYPT_OK;
    
    uint8_t*        inByte = in;
    
    unsigned long   key_size   = 0;
    int             key_type = PK_PUBLIC;
    bool            ANSIx963 = false;
    
    void *x = NULL;
    
    LTC_ARGCHK(in  != NULL);
    LTC_ARGCHK(ltc_mp.name != NULL);
    
    if (inByte[0] != 4 && inByte[0] != 6 && inByte[0] != 7)
    {
        /* find out what type of key it is */
        unsigned char   flags[1];
        unsigned long   key_bytes  = 0;
        
        status = der_decode_sequence_multi(in, inlen,
                                           LTC_ASN1_BIT_STRING, 1UL, &flags,
                                           LTC_ASN1_SHORT_INTEGER,   1UL, &key_bytes,
                                           
                                           LTC_ASN1_EOL,        0UL, NULL); CKSTAT;
        
        key_size = key_bytes * 8;
        key_type = (flags[0] == 1)?PK_PRIVATE:PK_PUBLIC;
        
    }
    else
    {
        
        
        mp_init(&x);
        status = mp_read_unsigned_bin(x, (unsigned char *)inByte+1, (inlen-1)>>1); CKSTAT;
        
        
        ANSIx963 = true;
        key_type = PK_PUBLIC;
        key_size  = mp_count_bits(x);
        
    }
    
    
    if(isPrivate)
        *isPrivate = key_type == PK_PRIVATE;
    
    if(keySizeOut)
        *keySizeOut = (size_t) key_size;
    
    if(isANSIx963)
        *isANSIx963 = ANSIx963 ;
    
    
done:
    
    if(status != CRYPT_OK)
    {
        err = sCrypt2C4Err(status);
    }
    
    if(x) mp_clear(x);
    
    return (err);
    
}





C4Err ECC_SharedSecret(ECC_ContextRef  privCtx, ECC_ContextRef  pubCtx, void *outData, size_t bufSize, size_t *datSize)
{
    C4Err           err = kC4Err_NoErr;
    unsigned long   length = bufSize;
    
    validateECCContext(privCtx);
    validateECCContext(pubCtx);
    
    ValidateParam(privCtx->isInited);
    ValidateParam(pubCtx->isInited);
    
    // test that both keys are same kind */
    ValidateParam(!( !pubCtx->isBLCurve != !privCtx->isBLCurve ));
    
    if(pubCtx->isBLCurve)
        err = ecc_bl_shared_secret(&privCtx->key, &pubCtx->key, outData, &length);
    else
        err = ecc_shared_secret(&privCtx->key, &pubCtx->key, outData, &length);
    
    *datSize = length;
    
    //done:
    
    return (err);
}

C4Err ECC_KeySize( ECC_ContextRef  ctx, size_t * bits)
{
    C4Err  err = kC4Err_NoErr;
    
    validateECCContext(ctx);
    ValidateParam(ctx->isInited);
    
    *bits = ctx->key.dp->size *8;
    
    //done:
    
    return (err);
}

C4Err ECC_CurveName( ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *outDataLen)
{
    C4Err  err = kC4Err_NoErr;
    
    validateECCContext(ctx);
    ValidateParam(ctx->isInited);
    ValidateParam(outData);
    
    char* curveName =  ctx->key.dp->name;
    
    if(bufSize < strlen(curveName))
        RETERR (kC4Err_BufferTooSmall);
    
    strncpy(outData, curveName, bufSize);
    
    if(outDataLen)
        *outDataLen = strlen(curveName);
    
done:
    return err;
}




C4Err ECC_Encrypt(ECC_ContextRef  pubCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen)
{
    C4Err     err = kC4Err_NoErr;
    int          status  =  CRYPT_OK;
    unsigned long   length = bufSize;
    
    validateECCContext(pubCtx);
    ValidateParam(pubCtx->isInited);
    
    if(pubCtx->isBLCurve)
    {
        status = ecc_bl_encrypt_key(inData, inDataLen, outData,  &length,
                                    NULL,
                                    find_prng("sprng"),
                                    find_hash(inDataLen > 32?"sha512":"sha256"),
                                    &pubCtx->key);
        
    }
    else
    {
        status = ecc_encrypt_key(inData, inDataLen, outData,  &length,
                                 NULL,
                                 find_prng("sprng"),
                                 find_hash(inDataLen > 32?"sha512":"sha256"),
                                 &pubCtx->key);
        
    }CKSTAT;
    
    if(status != CRYPT_OK)
    {
        err = sCrypt2C4Err(status); CKERR;
    }
    
    *outDataLen = length;
    
done:
    
    return err;
}


C4Err ECC_Decrypt(ECC_ContextRef  privCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen)
{
    C4Err     err = kC4Err_NoErr;
    int          status  =  CRYPT_OK;
    unsigned long   length = bufSize;
    
    validateECCContext(privCtx);
    ValidateParam(privCtx->isInited);
    
    if(privCtx->isBLCurve)
    {
        status = ecc_bl_decrypt_key(inData, inDataLen, outData,  &length, &privCtx->key);
        
    }
    else
    {
        
        status = ecc_decrypt_key(inData, inDataLen, outData,  &length, &privCtx->key);
    }
    
    if(status != CRYPT_OK)
    {
        err = sCrypt2C4Err(status); CKERR;
    }
    
    *outDataLen = length;
    
done:
    
    return err;
}


C4Err ECC_Sign(ECC_ContextRef  privCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen)
{
    C4Err     err = kC4Err_NoErr;
    int          status  =  CRYPT_OK;
    unsigned long   length = bufSize;
    
    validateECCContext(privCtx);
    ValidateParam(privCtx->isInited);
    
    if(privCtx->isBLCurve)
    {
        status = ecc_bl_sign_hash(inData, inDataLen, outData,  &length,
                                  0, find_prng("sprng"),
                                  &privCtx->key);
        
    }
    else
    {
        
        status = ecc_sign_hash(inData, inDataLen, outData,  &length,
                               0, find_prng("sprng"),
                               &privCtx->key);
    }
    
    if(status != CRYPT_OK)
    {
        err = sCrypt2C4Err(status); CKERR;
    }
    
    *outDataLen = length;
    
done:
    
    return err;
}


C4Err ECC_Verify(ECC_ContextRef  pubCtx, void *sig, size_t sigLen,  void *hash, size_t hashLen)
{
    C4Err     err = kC4Err_NoErr;
    int          status  =  CRYPT_OK;
    int           valid = 0;
    
    validateECCContext(pubCtx);
    ValidateParam(pubCtx->isInited);
    
    
    if(pubCtx->isBLCurve)
    {
        status = ecc_bl_verify_hash(sig, sigLen, hash, hashLen, &valid, &pubCtx->key);
        
    }
    else
    {
        
        status = ecc_verify_hash(sig, sigLen, hash, hashLen, &valid, &pubCtx->key);
    }
    
    
    
    if(status != CRYPT_OK)
    {
        err = sCrypt2C4Err(status); CKERR;
    }
    
    if(!valid) err = kC4Err_BadIntegrity;
    
    
done:
    
    return err;
}



#ifdef __clang__
#pragma mark - PBKDF2  Password to Key
#endif


#define ROUNDMEASURE 10000
#define MIN_ROUNDS 1500

C4Err PASS_TO_KEY_SETUP(   unsigned long  password_len,
                           unsigned long  key_len,
                           uint8_t        *salt,
                           unsigned long  salt_len,
                           uint32_t       *rounds_out)
{
    C4Err    err         = kC4Err_NoErr;
    uint8_t     *password   = NULL;
    uint8_t     *key        = NULL;
    uint32_t    rounds = MIN_ROUNDS;
   
#if _USES_COMMON_CRYPTO_
    
    rounds = CCCalibratePBKDF(kCCPBKDF2,password_len, salt_len, kCCPRFHmacAlgSHA256, key_len, 100 );

    rounds = rounds > MIN_ROUNDS?rounds:MIN_ROUNDS;
    
    *rounds_out = rounds;
#else
   
    uint64_t	startTime, endTime, elapsedTime;
    
    
    uint64_t    msec = 100;   // 0.1s ?
    int i;
    
    // random password and salt
    password = XMALLOC(password_len);        CKNULL(password);
    key = XMALLOC(key_len);                  CKNULL(key);
    err = RNG_GetBytes( password, password_len ); CKERR;
    err = RNG_GetBytes( salt, salt_len ); CKERR;
    
    // run and calculate elapsed time.
    for(elapsedTime = 0, i=0; i < 10 && elapsedTime == 0; i++)
    {
        startTime = clock();
        
        err = PASS_TO_KEY (password, password_len, salt, salt_len, ROUNDMEASURE, key, key_len); CKERR;
        
        endTime = clock();
        
        elapsedTime = endTime - startTime;
    }
    
    if(elapsedTime == 0)
        RETERR(kC4Err_UnknownError);
    
    // How many rounds to use so that it takes 0.1s ?
    rounds = (uint32_t) ((uint64_t)(msec * ROUNDMEASURE * 1000) / elapsedTime);
    rounds = rounds > MIN_ROUNDS?rounds:MIN_ROUNDS;
    
    *rounds_out = rounds;
    
#endif
    
done:
    
    if(password) XFREE(password);
    if(key) XFREE(key);
    
    return err;
    
} // PASS_TO_KEY_SETUP()



C4Err PASS_TO_KEY (   const char  *password,
                      unsigned long  password_len,
                      uint8_t       *salt,
                      unsigned long  salt_len,
                      unsigned int   rounds,
                      uint8_t        *key_buf,
                      unsigned long  key_len )

{
    C4Err    err     = kC4Err_NoErr;
    
#if _USES_COMMON_CRYPTO_
     
   if( CCKeyDerivationPBKDF( kCCPBKDF2, (const char*)password,  password_len,
                         salt, salt_len,
                         kCCPRFHmacAlgSHA256, rounds,
                            key_buf,   key_len)
      != kCCSuccess)
        err = kC4Err_BadParams;
   
    
#else
    int         status  = CRYPT_OK;
    
    status = pkcs_5_alg2(password, password_len,
                         salt,      salt_len,
                         rounds,    find_hash("sha256"),
                         key_buf,   &key_len); CKSTAT;
    
    
done:
    if(status != CRYPT_OK)
        err = sCrypt2C4Err(status);
   
#endif
    
    return err;
    
    
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


C4Err RNG_GetBytes(
                      void *         out,
                      size_t         outLen
                      )
{
    int             err = kC4Err_NoErr;
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


#ifdef __clang__
#pragma mark - Hash word Encoding
#endif


/* 
  
 Zimmermann/Juola list as described in   https://en.wikipedia.org/wiki/PGP_word_list
 
 */

static char pgpWordListOdd[256][12] =
{
    "adroitness",
    "adviser",
    "aftermath",
    "aggregate",
    "alkali",
    "almighty",
    "amulet",
    "amusement",
    "antenna",
    "applicant",
    "Apollo",
    "armistice",
    "article",
    "asteroid",
    "Atlantic",
    "atmosphere",
    "autopsy",
    "Babylon",
    "backwater",
    "barbecue",
    "belowground",
    "bifocals",
    "bodyguard",
    "bookseller",
    "borderline",
    "bottomless",
    "Bradbury",
    "bravado",
    "Brazilian",
    "breakaway",
    "Burlington",
    "businessman",
    "butterfat",
    "Camelot",
    "candidate",
    "cannonball",
    "Capricorn",
    "caravan",
    "caretaker",
    "celebrate",
    "cellulose",
    "certify",
    "chambermaid",
    "Cherokee",
    "Chicago",
    "clergyman",
    "coherence",
    "combustion",
    "commando",
    "company",
    "component",
    "concurrent",
    "confidence",
    "conformist",
    "congregate",
    "consensus",
    "consulting",
    "corporate",
    "corrosion",
    "councilman",
    "crossover",
    "crucifix",
    "cumbersome",
    "customer",
    "Dakota",
    "decadence",
    "December",
    "decimal",
    "designing",
    "detector",
    "detergent",
    "determine",
    "dictator",
    "dinosaur",
    "direction",
    "disable",
    "disbelief",
    "disruptive",
    "distortion",
    "document",
    "embezzle",
    "enchanting",
    "enrollment",
    "enterprise",
    "equation",
    "equipment",
    "escapade",
    "Eskimo",
    "everyday",
    "examine",
    "existence",
    "exodus",
    "fascinate",
    "filament",
    "finicky",
    "forever",
    "fortitude",
    "frequency",
    "gadgetry",
    "Galveston",
    "getaway",
    "glossary",
    "gossamer",
    "graduate",
    "gravity",
    "guitarist",
    "hamburger",
    "Hamilton",
    "handiwork",
    "hazardous",
    "headwaters",
    "hemisphere",
    "hesitate",
    "hideaway",
    "holiness",
    "hurricane",
    "hydraulic",
    "impartial",
    "impetus",
    "inception",
    "indigo",
    "inertia",
    "infancy",
    "inferno",
    "informant",
    "insincere",
    "insurgent",
    "integrate",
    "intention",
    "inventive",
    "Istanbul",
    "Jamaica",
    "Jupiter",
    "leprosy",
    "letterhead",
    "liberty",
    "maritime",
    "matchmaker",
    "maverick",
    "Medusa",
    "megaton",
    "microscope",
    "microwave",
    "midsummer",
    "millionaire",
    "miracle",
    "misnomer",
    "molasses",
    "molecule",
    "Montana",
    "monument",
    "mosquito",
    "narrative",
    "nebula",
    "newsletter",
    "Norwegian",
    "October",
    "Ohio",
    "onlooker",
    "opulent",
    "Orlando",
    "outfielder",
    "Pacific",
    "pandemic",
    "Pandora",
    "paperweight",
    "paragon",
    "paragraph",
    "paramount",
    "passenger",
    "pedigree",
    "Pegasus",
    "penetrate",
    "perceptive",
    "performance",
    "pharmacy",
    "phonetic",
    "photograph",
    "pioneer",
    "pocketful",
    "politeness",
    "positive",
    "potato",
    "processor",
    "provincial",
    "proximate",
    "puberty",
    "publisher",
    "pyramid",
    "quantity",
    "racketeer",
    "rebellion",
    "recipe",
    "recover",
    "repellent",
    "replica",
    "reproduce",
    "resistor",
    "responsive",
    "retraction",
    "retrieval",
    "retrospect",
    "revenue",
    "revival",
    "revolver",
    "sandalwood",
    "sardonic",
    "Saturday",
    "savagery",
    "scavenger",
    "sensation",
    "sociable",
    "souvenir",
    "specialist",
    "speculate",
    "stethoscope",
    "stupendous",
    "supportive",
    "surrender",
    "suspicious",
    "sympathy",
    "tambourine",
    "telephone",
    "therapist",
    "tobacco",
    "tolerance",
    "tomorrow",
    "torpedo",
    "tradition",
    "travesty",
    "trombonist",
    "truncated",
    "typewriter",
    "ultimate",
    "undaunted",
    "underfoot",
    "unicorn",
    "unify",
    "universe",
    "unravel",
    "upcoming",
    "vacancy",
    "vagabond",
    "vertigo",
    "Virginia",
    "visitor",
    "vocalist",
    "voyager",
    "warranty",
    "Waterloo",
    "whimsical",
    "Wichita",
    "Wilmington",
    "Wyoming",
    "yesteryear",
    "Yucatan"
};

/* These 2-syllable words are no longer than 9 characters. */
static char pgpWordListEven[256][10] =
{
    "aardvark",
    "absurd",
    "accrue",
    "acme",
    "adrift",
    "adult",
    "afflict",
    "ahead",
    "aimless",
    "Algol",
    "allow",
    "alone",
    "ammo",
    "ancient",
    "apple",
    "artist",
    "assume",
    "Athens",
    "atlas",
    "Aztec",
    "baboon",
    "backfield",
    "backward",
    "banjo",
    "beaming",
    "bedlamp",
    "beehive",
    "beeswax",
    "befriend",
    "Belfast",
    "berserk",
    "billiard",
    "bison",
    "blackjack",
    "blockade",
    "blowtorch",
    "bluebird",
    "bombast",
    "bookshelf",
    "brackish",
    "breadline",
    "breakup",
    "brickyard",
    "briefcase",
    "Burbank",
    "button",
    "buzzard",
    "cement",
    "chairlift",
    "chatter",
    "checkup",
    "chisel",
    "choking",
    "chopper",
    "Christmas",
    "clamshell",
    "classic",
    "classroom",
    "cleanup",
    "clockwork",
    "cobra",
    "commence",
    "concert",
    "cowbell",
    "crackdown",
    "cranky",
    "crowfoot",
    "crucial",
    "crumpled",
    "crusade",
    "cubic",
    "dashboard",
    "deadbolt",
    "deckhand",
    "dogsled",
    "dragnet",
    "drainage",
    "dreadful",
    "drifter",
    "dropper",
    "drumbeat",
    "drunken",
    "Dupont",
    "dwelling",
    "eating",
    "edict",
    "egghead",
    "eightball",
    "endorse",
    "endow",
    "enlist",
    "erase",
    "escape",
    "exceed",
    "eyeglass",
    "eyetooth",
    "facial",
    "fallout",
    "flagpole",
    "flatfoot",
    "flytrap",
    "fracture",
    "framework",
    "freedom",
    "frighten",
    "gazelle",
    "Geiger",
    "glitter",
    "glucose",
    "goggles",
    "goldfish",
    "gremlin",
    "guidance",
    "hamlet",
    "highchair",
    "hockey",
    "indoors",
    "indulge",
    "inverse",
    "involve",
    "island",
    "jawbone",
    "keyboard",
    "kickoff",
    "kiwi",
    "klaxon",
    "locale",
    "lockup",
    "merit",
    "minnow",
    "miser",
    "Mohawk",
    "mural",
    "music",
    "necklace",
    "Neptune",
    "newborn",
    "nightbird",
    "Oakland",
    "obtuse",
    "offload",
    "optic",
    "orca",
    "payday",
    "peachy",
    "pheasant",
    "physique",
    "playhouse",
    "Pluto",
    "preclude",
    "prefer",
    "preshrunk",
    "printer",
    "prowler",
    "pupil",
    "puppy",
    "python",
    "quadrant",
    "quiver",
    "quota",
    "ragtime",
    "ratchet",
    "rebirth",
    "reform",
    "regain",
    "reindeer",
    "rematch",
    "repay",
    "retouch",
    "revenge",
    "reward",
    "rhythm",
    "ribcage",
    "ringbolt",
    "robust",
    "rocker",
    "ruffled",
    "sailboat",
    "sawdust",
    "scallion",
    "scenic",
    "scorecard",
    "Scotland",
    "seabird",
    "select",
    "sentence",
    "shadow",
    "shamrock",
    "showgirl",
    "skullcap",
    "skydive",
    "slingshot",
    "slowdown",
    "snapline",
    "snapshot",
    "snowcap",
    "snowslide",
    "solo",
    "southward",
    "soybean",
    "spaniel",
    "spearhead",
    "spellbind",
    "spheroid",
    "spigot",
    "spindle",
    "spyglass",
    "stagehand",
    "stagnate",
    "stairway",
    "standard",
    "stapler",
    "steamship",
    "sterling",
    "stockman",
    "stopwatch",
    "stormy",
    "sugar",
    "surmount",
    "suspense",
    "sweatband",
    "swelter",
    "tactics",
    "talon",
    "tapeworm",
    "tempest",
    "tiger",
    "tissue",
    "tonic",
    "topmost",
    "tracker",
    "transit",
    "trauma",
    "treadmill",
    "Trojan",
    "trouble",
    "tumor",
    "tunnel",
    "tycoon",
    "uncut",
    "unearth",
    "unwind",
    "uproot",
    "upset",
    "upshot",
    "vapor",
    "village",
    "virus",
    "Vulcan",
    "waffle",
    "wallet",
    "watchword",
    "wayside",
    "willow",
    "woodlark",
    "Zulu"
};

void PGPWordEncode(uint32_t in, char* out, size_t *outLen)
{
     *outLen =  snprintf(out, *outLen, "%s %s",
                        pgpWordListOdd[(in >>12)&0xFF],  pgpWordListEven[(in >>4)&0xFF]  );
    
}

void PGPWordEncode64(uint64_t in, char* out, size_t *outLen)
{
    
    in = in >> 32;
    
    *outLen =  snprintf(out, *outLen, "%s %s %s %s",
                        pgpWordListOdd[(in >>24)&0xFF],
                        pgpWordListEven[(in >>16)&0xFF],
                        pgpWordListOdd[(in >> 8)&0xFF],
                        pgpWordListEven[(in >>0)&0xFF]  );
    
}

