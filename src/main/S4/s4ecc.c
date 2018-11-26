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


typedef struct S4ECCInfo_
{
	char      		*const name;
	ECC_Algorithm	algorithm;
	size_t			keyBytes;
	bool			available;
} S4ECCinfo;

static S4ECCinfo sEccInfoTable[] = {

	{ "ECC-384",  		kECC_Algorithm_ECC384, 		48,									true},
	{ "Curve41417", 	kECC_Algorithm_Curve41417, 	52 	/* Actually 51.75 bytes */, 	true},
	{ NULL,   			kECC_Algorithm_Invalid,	 0, 								false},
};


static S4ECCinfo* sECCInfoForAlgorithm(ECC_Algorithm algorithm)
{
	S4ECCinfo* info = NULL;

	for(S4ECCinfo* eccInfo = sEccInfoTable; eccInfo->name; eccInfo++)
	{
		if(algorithm == eccInfo->algorithm)
		{
			info = eccInfo;
			break;
		}
	}

	return info;
}

// Get an malloc array of available algorithms
// calller must deallocate the outAlgorithms typically with XFREE
//

EXPORT_FUNCTION S4Err ECC_GetAvailableAlgorithms(ECC_Algorithm **outAlgorithms, size_t *outCount)
{
	S4Err err = kS4Err_NoErr;

	size_t 			algorCount = 0;
	ECC_Algorithm 		*eccTable  =  NULL;

	for(S4ECCinfo* eccInfo = sEccInfoTable; eccInfo->name; eccInfo++)
		if(eccInfo->name && eccInfo->available)
			algorCount ++;

	if(algorCount)
		eccTable = XMALLOC(algorCount * sizeof(ECC_Algorithm) );

	int i = 0;
	for(S4ECCinfo* eccInfo = sEccInfoTable; eccInfo->name; eccInfo++)
		if(eccInfo->name && eccInfo->available)
			eccTable[i++] = eccInfo->algorithm;

	if(outAlgorithms)
		*outAlgorithms = eccTable;
	else
		if(eccTable) XFREE(eccTable);

	if(outCount)
		*outCount = algorCount;

	return err;
}

EXPORT_FUNCTION bool ECC_AlgorithmIsAvailable(ECC_Algorithm algorithm)
{
	bool isAvailable = false;

 	S4ECCinfo* eccInfo = sECCInfoForAlgorithm(algorithm);
	if(eccInfo)
	{
		isAvailable = eccInfo->available;
	}
	return isAvailable;
}


EXPORT_FUNCTION S4Err ECC_GetKeySizeInBytes(ECC_Algorithm algorithm, size_t *keySizeBytes)
{
	S4Err err = kS4Err_FeatureNotAvailable;

	S4ECCinfo* eccInfo = sECCInfoForAlgorithm(algorithm);
	if(eccInfo)
	{
		if(keySizeBytes)
			*keySizeBytes = eccInfo->keyBytes;
		err = kS4Err_NoErr;
	}

	return err;
}

EXPORT_FUNCTION  S4Err ECC_GetName(ECC_Algorithm algorithm, const char **eccName)
{
	S4Err err = kS4Err_FeatureNotAvailable;

	S4ECCinfo* eccInfo = sECCInfoForAlgorithm(algorithm);
	if(eccInfo)
	{
		if(eccName)
			*eccName = eccInfo->name;
		err = kS4Err_NoErr;
	}

	return err;
}



typedef struct ECC_Context    ECC_Context;

struct ECC_Context
{
#define kECC_ContextMagic		0x63344543
    uint32_t                    magic;
	ECC_Algorithm				algorithm;
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

EXPORT_FUNCTION S4Err ECC_Import_Info( const void *in, size_t inlen,
									  bool *isPrivate,
									  bool *isANSIx963,
									  size_t *keySizeOut  )
{
	S4Err           err = kS4Err_NoErr;
	int             status  =  CRYPT_OK;

	const uint8_t*  inByte = in;

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

S4Err ECC_Init(ECC_Algorithm algorithm, ECC_ContextRef * ctxOUT)
{
	S4Err           err = kS4Err_NoErr;
	ECC_Context*    eccCTX = kInvalidECC_ContextRef;

	if(!ECC_AlgorithmIsAvailable(algorithm))
		RETERR(kS4Err_FeatureNotAvailable);

	ValidateParam(ctxOUT);
	*ctxOUT = NULL;

	eccCTX = XMALLOC(sizeof (ECC_Context)); CKNULL(eccCTX);
	eccCTX->magic = kECC_ContextMagic;
	eccCTX->algorithm =  algorithm;

	switch(algorithm)
	{
		case kECC_Algorithm_Curve41417:
		{
			err = ecc_bl_make_key(NULL,
								  find_prng("sprng"),
								  52, /* Actually 51.75 bytes */
								  &eccCTX->key);CKERR;
			eccCTX->isInited = true;
			eccCTX->isBLCurve = true;

		}
			break;
		case kECC_Algorithm_ECC384:
		{
			err = ecc_make_key(NULL,
							   find_prng("sprng"),
							   48,
							   &eccCTX->key);CKERR;
			eccCTX->isBLCurve = false;
			eccCTX->isInited = true;

		}
			break;

		default:
			RETERR(kS4Err_BadParams) ;
	}

	*ctxOUT = eccCTX;

done:

	// if we failed destroy the context
	if(IsS4Err(err) && IsntNull(eccCTX))
	{
		ECC_Free(eccCTX);
	}

	return err;
}

EXPORT_FUNCTION S4Err ECC_Import_ANSI_X963(const void *in, size_t inlen,
										   ECC_ContextRef * ctxOUT )
{
	S4Err       	err = kS4Err_NoErr;
	ECC_Context*    eccCTX = kInvalidECC_ContextRef;

	bool 	isPrivate = false;
	size_t  importKeySize = 0;
	bool 	isANSIx963 = false;

	ValidateParam(ctxOUT);
	*ctxOUT = NULL;

	// determine what we have
	err = ECC_Import_Info( in, inlen, &isPrivate, &isANSIx963, &importKeySize );CKERR;
	ValidateParam(isANSIx963 && !isPrivate)

	eccCTX = XMALLOC(sizeof (ECC_Context)); CKNULL(eccCTX);
	eccCTX->magic = kECC_ContextMagic;

	if(importKeySize > 384)
	{
		err = ecc_bl_ansi_x963_import(in, inlen, &eccCTX->key); CKERR;
		eccCTX->algorithm =  kECC_Algorithm_Curve41417;
		eccCTX->isBLCurve = true;
		eccCTX->isInited = true;
	}
	else
	{
		err = ecc_ansi_x963_import(in, inlen, &eccCTX->key); CKERR;
		eccCTX->algorithm =  kECC_Algorithm_ECC384;
		eccCTX->isBLCurve = false;
		eccCTX->isInited = true;
	}


done:

	// if we failed destroy the context
	if(IsS4Err(err) && IsntNull(eccCTX))
	{
		ECC_Free(eccCTX);
	}

	*ctxOUT = eccCTX;

	return (err);
}

EXPORT_FUNCTION S4Err ECC_Import(const void *in, size_t inlen,   ECC_ContextRef * ctxOUT )
{

	S4Err       	err = kS4Err_NoErr;
	ECC_Context*    eccCTX = kInvalidECC_ContextRef;

	bool 	isPrivate = false;
	size_t  importKeySize = 0;
	bool 	isANSIx963 = false;

	ValidateParam(ctxOUT);
	*ctxOUT = NULL;

	// determine what we have
	err = ECC_Import_Info( in, inlen, &isPrivate, &isANSIx963, &importKeySize );CKERR;
	ValidateParam(!isANSIx963 )

	eccCTX = XMALLOC(sizeof (ECC_Context)); CKNULL(eccCTX);
	eccCTX->magic = kECC_ContextMagic;

	if(importKeySize > 384)
	{
		err = ecc_bl_import(in, inlen, &eccCTX->key); CKERR;
		eccCTX->algorithm =  kECC_Algorithm_Curve41417;
		eccCTX->isBLCurve = true;
		eccCTX->isInited = true;
	}
	else
	{
		err = ecc_import(in, inlen, &eccCTX->key); CKERR;
		eccCTX->algorithm =  kECC_Algorithm_ECC384;
		eccCTX->isBLCurve = false;
		eccCTX->isInited = true;
	}


done:

	// if we failed destroy the context
	if(IsS4Err(err) && IsntNull(eccCTX))
	{
		ECC_Free(eccCTX);
	}

	*ctxOUT = eccCTX;

	return (err);
}




bool ECC_isPrivate(ECC_ContextRef  ctx )
{
    bool isPrivate = false;
    
    if(sECC_ContextIsValid(ctx))
        isPrivate = ctx->key.type == PK_PRIVATE;
    
    return (isPrivate);
    
}

EXPORT_FUNCTION S4Err ECC_GetAlgorithm(ECC_ContextRef ctx, ECC_Algorithm *algorithm)
{
	S4Err             err = kS4Err_NoErr;

	validateECCContext(ctx);

	if(algorithm)
		*algorithm = ctx->algorithm;

	return err;

}

EXPORT_FUNCTION void ECC_Free(ECC_ContextRef  ctx)
{
    
    if(sECC_ContextIsValid(ctx))
    {

        if(ctx->isInited) ecc_free( &ctx->key);
        ZERO(ctx, sizeof(ECC_Context));
        XFREE(ctx);
    }
}

EXPORT_FUNCTION S4Err ECC_Export_ANSI_X963(ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *datSize)
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



EXPORT_FUNCTION S4Err ECC_Export(ECC_ContextRef  ctx, bool exportPrivate,
								 void *outData, size_t bufSize, size_t *datSize)
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




EXPORT_FUNCTION S4Err ECC_SharedSecret(ECC_ContextRef  privCtx, ECC_ContextRef  pubCtx,
									   void *outData, size_t bufSize, size_t *datSize)
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

EXPORT_FUNCTION S4Err ECC_KeySize( ECC_ContextRef  ctx, size_t * bits)
{
    S4Err  err = kS4Err_NoErr;
    
    validateECCContext(ctx);
    ValidateParam(ctx->isInited);
    
    *bits = ctx->key.dp->size *8;
    
    //done:
    
    return (err);
}

EXPORT_FUNCTION S4Err ECC_PubKeyHash( ECC_ContextRef  ctx, void *outData, size_t bufSize, size_t *outDataLen)
{
    S4Err  err = kS4Err_NoErr;
    HASH_ContextRef hash = kInvalidHASH_ContextRef;
    
    HASH_Algorithm  hashAlgor =  kHASH_Algorithm_Invalid;
    
     uint8_t         pubKey[256];
    size_t          pubKeyLen = 0;
    
    u08b_t          hashBuf[32];
    size_t          hashBytes = 0;
   
    validateECCContext(ctx);
    ValidateParam(sECC_ContextIsValid(ctx))
    ValidateParam(ctx->isInited);
    ValidateParam(outData);

    switch (ctx->algorithm) {
        case kECC_Algorithm_ECC384:
            hashAlgor = kHASH_Algorithm_SHA256;
            break;
            
        case kECC_Algorithm_Curve41417:
            hashAlgor = kHASH_Algorithm_SHA256; //kHASH_Algorithm_SKEIN256;
            break;
            
         default:
            RETERR (kS4Err_LazyProgrammer);
           break;
    }
    
    err  = HASH_Init(hashAlgor, &hash); CKERR;
    err =  ECC_Export_ANSI_X963( ctx, pubKey, sizeof(pubKey), &pubKeyLen);CKERR;
    
    err  = HASH_Update(hash, pubKey, pubKeyLen) ;CKERR;
	err = HASH_Final(hash,hashBuf); CKERR;
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




EXPORT_FUNCTION S4Err ECC_Encrypt(ECC_ContextRef  pubCtx, const void *inData, size_t inDataLen,
								  void *outData, size_t bufSize, size_t *outDataLen)
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


EXPORT_FUNCTION S4Err ECC_Decrypt(ECC_ContextRef  privCtx, const void *inData, size_t inDataLen,
								  void *outData, size_t bufSize, size_t *outDataLen)
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


EXPORT_FUNCTION S4Err ECC_Sign(ECC_ContextRef  privCtx, void *inData, size_t inDataLen,  void *outData, size_t bufSize, size_t *outDataLen)
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


EXPORT_FUNCTION S4Err ECC_Verify(ECC_ContextRef  pubCtx, void *sig, size_t sigLen,  void *hash, size_t hashLen)
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

