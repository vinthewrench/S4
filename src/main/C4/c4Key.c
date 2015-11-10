//
//  c4Key.c
//  C4
//
//  Created by vincent Moscaritolo on 11/9/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include "c4Internal.h"

#ifdef __clang__
#pragma mark - Key import Export.
#endif

enum C4KeyType_
{
    kC4KeyType_Symmetric           = 1,
    kC4KeyType_Tweekable           = 2,
    
    kC4KeyType_Invalid           =  kEnumMaxValue,
    
    ENUM_FORCE( C4KeyType_ )
};

ENUM_TYPEDEF( C4KeyType_, C4KeyType   );


typedef struct C4KeySymmetric_
{
    Cipher_Algorithm    symAlgor;
    int                 keylen;
    uint8_t        		symKey[64];
    
}C4KeySymmetric;



typedef struct C4KeyTBC_
{
    TBC_Algorithm       tbcAlgor;
    int                 keybits;
    u64b_t              key[16];
    
}C4KeyTBC;

typedef struct C4Key_Context    C4Key_Context;

struct C4Key_Context
{

#define kC4Key_ContextMagic		0x43346B79
    uint32_t            magic;
    C4KeyType           type;

    union {
        C4KeySymmetric  sym;
        C4KeyTBC        tbc;
      };

};

static bool sC4Key_ContextIsValid( const C4KeyContextRef  ref)
{
    bool       valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kC4Key_ContextMagic;
    
    return( valid );
}



#define validateC4KeyContext( s )		\
ValidateParam( sC4Key_ContextIsValid( s ) )


C4Err C4Key_NewSymmetric(Cipher_Algorithm       algorithm,
                             const void             *key,
                             
                             C4KeyContextRef    *ctxOut)
{
    C4Err               err = kC4Err_NoErr;
    C4Key_Context*    keyCTX  = NULL;
    
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
            RETERR(kC4Err_BadCipherNumber);
    }

    
    keyCTX = XMALLOC(sizeof (C4Key_Context)); CKNULL(keyCTX);
    keyCTX->magic = kC4Key_ContextMagic;
    keyCTX->type  = kC4KeyType_Symmetric;
    
    keyCTX->sym.symAlgor = algorithm;
    keyCTX->sym.keylen = keylen;
    COPY(key, keyCTX->sym.symKey, keylen);
    
    *ctxOut = keyCTX;
    
done:
    if(IsC4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (C4Key_Context), 0);
            XFREE(keyCTX);
        }
    }
     return err;
}


C4Err C4Key_NewTBC(     TBC_Algorithm       algorithm,
                             const void     *key,
                            C4KeyContextRef   *ctxOut)
{
    C4Err               err = kC4Err_NoErr;
    C4Key_Context*    keyCTX  = NULL;
    
    ValidateParam(ctxOut);
    
    int             keybits  = 0;
    
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
    
    
    
    keyCTX = XMALLOC(sizeof (C4Key_Context)); CKNULL(keyCTX);
    keyCTX->magic = kC4Key_ContextMagic;
    keyCTX->type  = kC4KeyType_Tweekable;
    
    keyCTX->tbc.tbcAlgor = algorithm;
    keyCTX->tbc.keybits = keybits;
  
    Skein_Get64_LSB_First(keyCTX->tbc.key, key, keybits >>5);   /* bytes to words */
    
    *ctxOut = keyCTX;
    
done:
    if(IsC4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (C4Key_Context), 0);
            XFREE(keyCTX);
        }
    }
    return err;
}



void C4Key_Free(C4KeyContextRef ctx)
{
    if(sC4Key_ContextIsValid(ctx))
    {
        ZERO(ctx, sizeof(C4Key_Context));
        XFREE(ctx);
    }

}


static C4Err sPASSPHRASE_HASH( const uint8_t  *key,
                                unsigned long  key_len,
                                uint8_t       *salt,
                                unsigned long  salt_len,
                                unsigned int   rounds,
                                uint8_t        *mac_buf,
                                unsigned long  mac_len)
{
    C4Err           err = kC4Err_NoErr;
  
    MAC_ContextRef  macRef     = kInvalidMAC_ContextRef;
    
    err = MAC_Init(kMAC_Algorithm_SKEIN,
                   kHASH_Algorithm_SKEIN256,
                   key, key_len, &macRef); CKERR
    
    err = MAC_Update( macRef, salt, salt_len); CKERR;
    err = MAC_Update( macRef, key, key_len); CKERR;
    size_t mac_len_SZ = (size_t)mac_len;
    err = MAC_Final( macRef, mac_buf, &mac_len_SZ); CKERR;
    
done:
    
    MAC_Free(macRef);
    
    return err;
}

#define SALT_BYTES                  8
#define PKDF_HASH_BYTES              16

C4Err C4Key_EncryptToPassPhrase(C4KeyContextRef  ctx,
                               const char       *passphrase,
                               size_t           passphraseLen,
                               uint8_t          **outData,
                               size_t           *outSize)

{
    C4Err           err = kC4Err_NoErr;
    
    uint32_t        rounds;
    uint8_t         keyHash[PKDF_HASH_BYTES] = {0};
    uint8_t         salt[SALT_BYTES] = {0};
   
    uint8_t         unlocking_key[128] = {0};
    int             keyBytes = 0;
    
    validateC4KeyContext(ctx);
    ValidateParam(passphrase);
    ValidateParam(outData);
    
    
    switch (ctx->type) {
        case kC4KeyType_Symmetric:
            keyBytes = ctx->sym.keylen ;
            break;
   
        case kC4KeyType_Tweekable:
            keyBytes = ctx->tbc.keybits >> 3 ;
            break;
            
        default:
            break;
    }
    
    
    err = RNG_GetBytes( salt, SALT_BYTES ); CKERR;
    
    err = PASS_TO_KEY_SETUP(passphraseLen, keyBytes,
                            salt, sizeof(salt),
                             &rounds); CKERR;

    err = PASS_TO_KEY(passphrase, passphraseLen,
                      salt, sizeof(salt), rounds,
                      unlocking_key, keyBytes); CKERR;
    
    err = sPASSPHRASE_HASH(unlocking_key, keyBytes,
                          salt, sizeof(salt),
                          rounds,
                          keyHash, PKDF_HASH_BYTES); CKERR;
   
    
    // write code to create JSON output here?
    
    
    /*
     
     {
     "version": 2,
     "keySuite": "aes256",
     "kdf": "pbkdf2",
     "salt": "t5H7FFFj+JY=",
     "rounds": 7345,
     "keyHash": "lqkA82LGdKc22tL2OqfRmg==",
     "encrypted": "P2mjPjs7FsssKG8/u26LAze4aMTOd1qV50kmordBdtk=",
     "locator": "85kU+OPcLtrDFnUMHzVLjjn6kqI=",
     "passPhraseSource": "keychain",
     "iv": "zIsF7Pd4ifSq6m+XenitKeziwC+MLjrM/woGBnxPbAM="
     }

     */
done:
    
    
    if(IsC4Err(err))
    {
     }
    return err;
   
}

