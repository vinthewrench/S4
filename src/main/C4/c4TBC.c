//
//  c4TBC.c
//  C4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include "c4Internal.h"


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

