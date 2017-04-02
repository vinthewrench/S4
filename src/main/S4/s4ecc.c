//
//  s4ECC.c
//  S4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//


#include "s4internal.h"


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

bool sECC_ContextIsValid( const ECC_ContextRef  ref)
{
    bool       valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kECC_ContextMagic;
    
    return( valid );
}



S4Err ECC_Init(ECC_ContextRef * ctx)
{
    S4Err           err = kS4Err_NoErr;
    ECC_Context*    eccCTX = kInvalidECC_ContextRef;
    
    ValidateParam(ctx);
    
    eccCTX = XMALLOC(sizeof (ECC_Context)); CKNULL(eccCTX);
    
    eccCTX->magic = kECC_ContextMagic;
    
    CKERR;
    
    *ctx = eccCTX;
    
done:
    
    return err;
    
}


S4Err ECC_Generate(ECC_ContextRef  ctx, size_t keysize )
{
    S4Err   err = kS4Err_NoErr;
    
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

S4Err ECC_Export_ANSI_X963(ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *datSize)
{
    S4Err           err = kS4Err_NoErr;
    unsigned long   length = bufSize;
    
    validateECCContext(ctx);
    
    ValidateParam(ctx->isInited);
    
    err = ecc_ansi_x963_export(&ctx->key, outData, &length); CKERR;
    
    *datSize = length;
    
done:
    
    return (err);
    
}


S4Err ECC_Import_ANSI_X963(ECC_ContextRef  ctx,   void *in, size_t inlen )
{
    S4Err       err = kS4Err_NoErr;
    
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

S4Err ECC_Export(ECC_ContextRef  ctx, int exportPrivate, void *outData, size_t bufSize, size_t *datSize)
{
    S4Err           err = kS4Err_NoErr;
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


S4Err ECC_Import(ECC_ContextRef  ctx,   void *in, size_t inlen )
{
    S4Err       err = kS4Err_NoErr;
    
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

S4Err ECC_Import_Info( void *in, size_t inlen,
                      bool *isPrivate,
                      bool *isANSIx963,
                      size_t *keySizeOut  )
{
    S4Err           err = kS4Err_NoErr;
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
        err = sCrypt2S4Err(status);
    }
    
    if(x) mp_clear(x);
    
    return (err);
    
}





S4Err ECC_SharedSecret(ECC_ContextRef  privCtx, ECC_ContextRef  pubCtx, void *outData, size_t bufSize, size_t *datSize)
{
    S4Err           err = kS4Err_NoErr;
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

S4Err ECC_KeySize( ECC_ContextRef  ctx, size_t * bits)
{
    S4Err  err = kS4Err_NoErr;
    
    validateECCContext(ctx);
    ValidateParam(ctx->isInited);
    
    *bits = ctx->key.dp->size *8;
    
    //done:
    
    return (err);
}

S4Err  ECC_CipherAlgorithm( ECC_ContextRef  ctx, Cipher_Algorithm* algOut)
{
    S4Err  err = kS4Err_NoErr;
    
    validateECCContext(ctx);
    ValidateParam(ctx->isInited);
  
    Cipher_Algorithm algorith =  kCipher_Algorithm_Invalid;
      char* curveName =  ctx->key.dp->name;
    
    if( strcmp(curveName, "ECC-384" ) == 0)
        algorith = kCipher_Algorithm_ECC384;
    
    else if( strcmp(curveName, "Curve41417" ) == 0)
        algorith = kCipher_Algorithm_ECC414;
    
    if(algOut)
        *algOut = algorith;
    
    return (err);
}


S4Err ECC_CurveName( ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *outDataLen)
{
    S4Err  err = kS4Err_NoErr;
    
    validateECCContext(ctx);
    ValidateParam(ctx->isInited);
    ValidateParam(outData);
    
    char* curveName =  ctx->key.dp->name;
    
    if(bufSize < strlen(curveName))
        RETERR (kS4Err_BufferTooSmall);
    
    strncpy(outData, curveName, bufSize);
    
    if(outDataLen)
        *outDataLen = strlen(curveName);
    
done:
    return err;
}


S4Err ECC_PubKeyHash( ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *outDataLen)
{
    S4Err  err = kS4Err_NoErr;
    HASH_ContextRef hash = kInvalidHASH_ContextRef;
    
    Cipher_Algorithm cipherAlgor =  kCipher_Algorithm_Invalid;
    HASH_Algorithm  hashAlgor =  kHASH_Algorithm_Invalid;
    
     uint8_t         pubKey[256];
    size_t          pubKeyLen = 0;
    
    u08b_t          hashBuf[32];
    size_t          hashBytes = 0;
   
    validateECCContext(ctx);
    ValidateParam(sECC_ContextIsValid(ctx))
    ValidateParam(ctx->isInited);
    ValidateParam(outData);
    
    err = ECC_CipherAlgorithm(ctx, &cipherAlgor); CKERR;
    
    switch (cipherAlgor) {
        case kCipher_Algorithm_ECC384:
            hashAlgor = kHASH_Algorithm_SHA256;
            break;
            
        case kCipher_Algorithm_ECC414:
            hashAlgor = kHASH_Algorithm_SKEIN256;
            break;
            
         default:
            RETERR (kS4Err_LazyProgrammer);
           break;
    }
    
    err  = HASH_Init(hashAlgor, &hash); CKERR;
    err =  ECC_Export_ANSI_X963( ctx, pubKey, sizeof(pubKey), &pubKeyLen);CKERR;
    
    err  = HASH_Update(hash, pubKey, pubKeyLen) ;CKERR;
    err = HASH_Final(hash,hashBuf);
    err = HASH_GetSize(hash, &hashBytes);
    
    hashBytes = bufSize < hashBytes ? bufSize :hashBytes;
    
    memcpy( outData,hashBuf, hashBytes);
   
    if(outDataLen)
        *outDataLen = hashBytes;
    
done:
    
    if(HASH_ContextRefIsValid(hash))
        HASH_Free(hash);

    return err;
}




S4Err ECC_Encrypt(ECC_ContextRef  pubCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen)
{
    S4Err     err = kS4Err_NoErr;
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
        
    }; 
    
    if(status != CRYPT_OK)
    {
        err = sCrypt2S4Err(status); CKERR;
    }
    
    *outDataLen = length;
    
done:
    
    return err;
}


S4Err ECC_Decrypt(ECC_ContextRef  privCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen)
{
    S4Err     err = kS4Err_NoErr;
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
        err = sCrypt2S4Err(status); CKERR;
    }
    
    *outDataLen = length;
    
done:
    
    return err;
}


S4Err ECC_Sign(ECC_ContextRef  privCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen)
{
    S4Err     err = kS4Err_NoErr;
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
        err = sCrypt2S4Err(status); CKERR;
    }
    
    *outDataLen = length;
    
done:
    
    return err;
}


S4Err ECC_Verify(ECC_ContextRef  pubCtx, void *sig, size_t sigLen,  void *hash, size_t hashLen)
{
    S4Err     err = kS4Err_NoErr;
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
        err = sCrypt2S4Err(status); CKERR;
    }
    
    if(!valid) err = kS4Err_BadIntegrity;
    
    
done:
    
    return err;
}

