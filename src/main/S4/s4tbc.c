//
//  s4TBC.c
//  S4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include "s4internal.h"


#ifdef __clang__
#pragma mark - tweakable block cipher functions
#endif

typedef struct TBC_Context    TBC_Context;

struct TBC_Context
{
#define kTBC_ContextMagic		0x43347462
    uint32_t            magic;
    Cipher_Algorithm    algor;
    
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


EXPORT_FUNCTION S4Err TBC_Init(Cipher_Algorithm algorithm,
               const void *key,
				size_t keylen,
               TBC_ContextRef * ctxOut)
{
    int             err     = kS4Err_NoErr;
    TBC_Context*    tbcCTX  = NULL;
    int             keybits  = 0;
    u64b_t          tweek[3] = {0L,0L };
    
    ValidateParam(ctxOut);
    
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

	if(keylen != keybits >> 3)
		RETERR(kS4Err_BadParams);

    tbcCTX = XMALLOC(sizeof (TBC_Context)); CKNULL(tbcCTX);
    
    tbcCTX->magic = kTBC_ContextMagic;
    tbcCTX->algor = algorithm;
    tbcCTX->keybits = keybits;
    
    memcpy(tbcCTX->key, key, tbcCTX->keybits >> 3);
    
//    Skein_Get64_LSB_First(tbcCTX->key, key, tbcCTX->keybits >>5);   /* bytes to words */
    
    threefishSetKey(&tbcCTX->state, tbcCTX->keybits, tbcCTX->key, tweek);
    
    *ctxOut = tbcCTX;
    
done:
    
    if(IsS4Err(err))
    {
        if(tbcCTX)
        {
            memset(tbcCTX, sizeof (TBC_Context), 0);
            XFREE(tbcCTX);
        }
    }
    
    return err;
    
}

EXPORT_FUNCTION void TBC_Free(TBC_ContextRef  ctx)
{
    
    if(sTBC_ContextIsValid(ctx))
    {
        ZERO(ctx, sizeof(TBC_Context));
        XFREE(ctx);
    }
}


EXPORT_FUNCTION S4Err TBC_SetTweek(TBC_ContextRef ctx,
                   	const void *	tweekIn,
					size_t 			tweeklen) 	// tweek must be 16 bytes..
{
    S4Err       err = kS4Err_NoErr;
    u64b_t      tweek[2] = {0L,0L};
    
    validateTBCContext(ctx);
	ValidateParam(tweekIn);
	
	if(tweeklen != sizeof(tweek))
		RETERR(kS4Err_BadParams);

    memcpy(tweek, tweekIn, sizeof(tweek));
    
 //   Skein_Get64_LSB_First(tweek, tweekIn, 2);   /* bytes to words */
    
    threefishSetKey(&ctx->state, ctx->keybits, ctx->key, tweek);

done:
    return (err);
    
}

EXPORT_FUNCTION S4Err TBC_Encrypt(TBC_ContextRef ctx,
                  const void *	in,
                  void *         out )
{
    S4Err       err = kS4Err_NoErr;
    
    validateTBCContext(ctx);
    
    threefishEncryptBlockBytes(&ctx->state,(uint8_t*) in, out);
    
    return (err);
    
}

EXPORT_FUNCTION S4Err TBC_Decrypt(TBC_ContextRef ctx,
                  const void *	in,
                  void *         out )
{
    S4Err       err = kS4Err_NoErr;
    
    validateTBCContext(ctx);
    
    threefishDecryptBlockBytes(&ctx->state,(uint8_t*) in, out);
    
    return (err);
}

