//
//  s4Cipher.c
//  S4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include "s4internal.h"


#ifdef __clang__
#pragma mark - EBC Symmetric Crypto
#endif

EXPORT_FUNCTION
S4Err ECB_Encrypt(Cipher_Algorithm algorithm,
                  const void *	key,
				  const void *	in,
				  size_t         inSize,
				  void *         out,
				  size_t         outSize)
{
    int             err = kS4Err_NoErr;
    int             status  =  CRYPT_OK;
    symmetric_ECB   ECB;
    
    int             keylen  = 0;
    int             cipher  = -1;

	ValidateParam(inSize == outSize);

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
            RETERR(kS4Err_BadCipherNumber);
    }
    
    status  = ecb_start(cipher, key, keylen, 0, &ECB ); CKSTAT;
    
    status  = ecb_encrypt(in, out, inSize, &ECB); CKSTAT;
    
    
done:
    
    ecb_done(&ECB);
    
    if(status != CRYPT_OK)
        err = sCrypt2S4Err(status);
    
    return err;
    
}

EXPORT_FUNCTION
S4Err ECB_Decrypt(Cipher_Algorithm algorithm,
				  const void *	key,
				  const void *	in,
				  size_t         inSize,
				  void *         out,
				  size_t         outSize)
{
    int             err = kS4Err_NoErr;
    int             status  =  CRYPT_OK;
    symmetric_ECB   ECB;
    
    int             keylen  = 0;
    int             cipher  = -1;

	ValidateParam(inSize == outSize);

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
            RETERR(kS4Err_BadCipherNumber);
    }
    
    status  = ecb_start(cipher, key, keylen, 0, &ECB ); CKSTAT;
    
    status  = ecb_decrypt(in, out, inSize, &ECB); CKSTAT;
    
    
done:
    
    ecb_done(&ECB);
    
    if(status != CRYPT_OK)
        err = sCrypt2S4Err(status);
    
    return err;
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


EXPORT_FUNCTION S4Err CBC_Init(Cipher_Algorithm algorithm,
               const void *key,
               const void *iv,
               CBC_ContextRef * ctxOut)
{
    int             err     = kS4Err_NoErr;
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
            RETERR(kS4Err_BadCipherNumber);
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
        err = sCrypt2S4Err(status);
    }
    
    return err;
}


EXPORT_FUNCTION S4Err CBC_GetAlgorithm(CBC_ContextRef ctx, Cipher_Algorithm *algorithm)
{
	S4Err             err = kS4Err_NoErr;

	validateCBCContext(ctx);

	if(algorithm)
		*algorithm = ctx->algor;

	return err;
}

EXPORT_FUNCTION S4Err CBC_Encrypt(CBC_ContextRef ctx,
								  const void *	in,
								  size_t         inSize,
								  void *         out,
								  size_t         outSize)
{
    S4Err           err = kS4Err_NoErr;
    int             status  =  CRYPT_OK;
    
    validateCBCContext(ctx);
	ValidateParam(inSize == outSize);

    status = cbc_encrypt(in, out, inSize, &ctx->state);
    
    err = sCrypt2S4Err(status);
    
    return (err);
    
}

EXPORT_FUNCTION S4Err CBC_Decrypt(CBC_ContextRef ctx,
								  const void *	in,
								  size_t         inSize,
								  void *         out,
								  size_t         outSize)
{
    S4Err           err = kS4Err_NoErr;
    int             status  =  CRYPT_OK;
    
    validateCBCContext(ctx);
	ValidateParam(inSize == outSize);

     status = cbc_decrypt(in, out, inSize, &ctx->state);
    
    err = sCrypt2S4Err(status);
    
    return (err);
    
}

EXPORT_FUNCTION void CBC_Free(CBC_ContextRef  ctx)
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

EXPORT_FUNCTION S4Err
CBC_EncryptPAD(Cipher_Algorithm algorithm,
               uint8_t*         key,
               const uint8_t*   iv,
               const uint8_t*   in,
			   size_t           in_len,
               uint8_t**        outAllocData,
			   size_t*          outSize)
{
    S4Err    err     = kS4Err_NoErr;
    CBC_ContextRef      cbc = kInvalidCBC_ContextRef;
    
    uint8_t     bytes2Pad;
    uint8_t     *buffer = NULL;
    size_t      buffLen = 0;
    
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
    
    err = CBC_Encrypt(cbc, buffer, buffLen, buffer, buffLen); CKERR;

	if(outSize)
		*outSize = buffLen;

	if(outAllocData)
    	*outAllocData = buffer;
	else if(buffer)
	{
		memset(buffer, buffLen, 0);
		XFREE(buffer);
		buffer = NULL;
	}

done:
    
    if(IsS4Err(err))
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



EXPORT_FUNCTION S4Err
CBC_DecryptPAD(Cipher_Algorithm algorithm,
               uint8_t*         key,
               const uint8_t*   iv,
               const uint8_t*   in,
               size_t           in_len,
               uint8_t**        outAllocData,
               size_t*          outSize)
{
    S4Err err = kS4Err_NoErr;
    CBC_ContextRef      cbc = kInvalidCBC_ContextRef;
    
    uint8_t *buffer = NULL;
    size_t buffLen = in_len;
    uint8_t  bytes2Pad = 0;
    

    buffer = XMALLOC(buffLen);
    
    err = CBC_Init(algorithm, key, iv,  &cbc);CKERR;
    
    err = CBC_Decrypt(cbc, in, buffLen, buffer, buffLen); CKERR;
    
    bytes2Pad = *(buffer+buffLen-1);
    
    if(bytes2Pad > buffLen)
        RETERR(kS4Err_CorruptData);
    

	if(outSize)
		*outSize = buffLen- bytes2Pad;;

	if(outAllocData)
		*outAllocData = buffer;
	else if(buffer)
	{
		memset(buffer, buffLen, 0);
		XFREE(buffer);
		buffer = NULL;
	}

done:
    if(IsS4Err(err))
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

