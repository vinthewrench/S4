//
//  c4Key.c
//  C4
//
//  Created by vincent Moscaritolo on 11/9/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include "c4Internal.h"


#include <yajl_parse.h>
#include <yajl_gen.h>

#ifdef __clang__
#pragma mark - YAJL memory management
#endif


#define CKYJAL  if((stat != yajl_gen_status_ok)) {\
printf("ERROR %d (%d)  %s:%d \n",  err, stat, __FILE__, __LINE__); \
err = kC4Err_CorruptData; \
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


#ifdef __clang__
#pragma mark - Key import Export.
#endif

#define kC4KeyProtocolVersion  0x01

#define K_KEYSUITE_AES128     "AES-128"
#define K_KEYSUITE_AES192     "AES-192"
#define K_KEYSUITE_AES256     "AES-256"

#define K_KEYSUITE_2FISH256   "Twofish-256"
#define K_KEYSUITE_3FISH256   "ThreeFish-256"
#define K_KEYSUITE_3FISH512   "ThreeFish-512"
#define K_KEYSUITE_3FISH1024  "ThreeFish-1024"


#define K_KEYSUITE_ECC384     "ecc384"
#define K_KEYSUITE_ECC414     "Curve3617"

static char *const kC4KeyProp_SCKeyVersion      = "version";

static char *const kC4KeyProp_KeySuite          = "keySuite";
static char *const kC4KeyProp_Encoding          = "encoding";

static char *const kC4KeyProp_Encoding_PBKDF2_AES256   = "pbkdf2-AES256";
static char *const kC4KeyProp_Encoding_PBKDF2_2FISH256   = "pbkdf2-Twofish-256";
static char *const kC4KeyProp_Encoding_PUBKEY_ECC384   =  "ECC-384";
static char *const kC4KeyProp_Encoding_PUBKEY_ECC414   =  "Curve3617";

static char *const kC4KeyProp_Salt              = "salt";
static char *const kC4KeyProp_Rounds            = "rounds";

static char *const kC4KeyProp_Hash              = "hash";
static char *const kC4KeyProp_EncryptedKey      = "encrypted";

static char *const kC4KeyProp_KeyID              = "keyID";


static char *cipher_algor_table(Cipher_Algorithm algor)
{
    switch (algor )
    {
        case kCipher_Algorithm_AES128: 		return (K_KEYSUITE_AES128);
        case kCipher_Algorithm_AES192: 		return (K_KEYSUITE_AES192);
        case kCipher_Algorithm_AES256: 		return (K_KEYSUITE_AES256);
        case kCipher_Algorithm_2FISH256: 		return (K_KEYSUITE_2FISH256);
        default:				return (("Invalid"));
    }
}

static char *tbc_algor_table(TBC_Algorithm algor)
{
    switch (algor )
    {
        case kTBC_Algorithm_3FISH256: 		return (K_KEYSUITE_3FISH256);
        case kTBC_Algorithm_3FISH512: 		return (K_KEYSUITE_3FISH512);
        case kTBC_Algorithm_3FISH1024: 		return (K_KEYSUITE_3FISH1024);
        default:				return (("Invalid"));
    }
}


static bool sC4KeyContextIsValid( const C4KeyContextRef  ref)
{
    bool       valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kC4KeyContextMagic;
    
    return( valid );
}



#define validateC4KeyContext( s )		\
ValidateParam( sC4KeyContextIsValid( s ) )

#ifdef __clang__
#pragma mark - create Key.
#endif

C4Err C4Key_NewSymmetric(Cipher_Algorithm       algorithm,
                             const void             *key,
                             
                             C4KeyContextRef    *ctxOut)
{
    C4Err               err = kC4Err_NoErr;
    C4KeyContext*    keyCTX  = NULL;
    
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

    
    keyCTX = XMALLOC(sizeof (C4KeyContext)); CKNULL(keyCTX);
    keyCTX->magic = kC4KeyContextMagic;
    keyCTX->type  = kC4KeyType_Symmetric;
    
    keyCTX->sym.symAlgor = algorithm;
    keyCTX->sym.keylen = keylen;
    
    // leave null bytes at end of key, for odd size keys (like 192)
    ZERO(keyCTX->sym.symKey, sizeof(keyCTX->sym.symKey) );
    COPY(key, keyCTX->sym.symKey, keylen);
    
    *ctxOut = keyCTX;
    
done:
    if(IsC4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (C4KeyContext), 0);
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
    C4KeyContext*    keyCTX  = NULL;
    
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
    
    
    
    keyCTX = XMALLOC(sizeof (C4KeyContext)); CKNULL(keyCTX);
    keyCTX->magic = kC4KeyContextMagic;
    keyCTX->type  = kC4KeyType_Tweekable;
    
    keyCTX->tbc.tbcAlgor = algorithm;
    keyCTX->tbc.keybits = keybits;
  
    Skein_Get64_LSB_First(keyCTX->tbc.key, key, keybits >>5);   /* bits to words */
    
    *ctxOut = keyCTX;
    
done:
    if(IsC4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (C4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    return err;
}



void C4Key_Free(C4KeyContextRef ctx)
{
    if(sC4KeyContextIsValid(ctx))
    {
        ZERO(ctx, sizeof(C4KeyContext));
        XFREE(ctx);
    }

}
#ifdef __clang__
#pragma mark - export key.
#endif


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

C4Err C4Key_SerializeToPassPhrase(C4KeyContextRef  ctx,
                               const char       *passphrase,
                               size_t           passphraseLen,
                               uint8_t          **outData,
                               size_t           *outSize)
{
    C4Err           err = kC4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    uint8_t             *yajlBuf = NULL;
    size_t              yajlLen = 0;
    yajl_gen            g = NULL;
 
    uint8_t             tempBuf[1024];
    size_t              tempLen;
    uint8_t             *outBuf = NULL;
    
    uint32_t        rounds;
    uint8_t         keyHash[kC4KeyPBKDF2_HashBytes] = {0};
    uint8_t         salt[kC4KeyPBKDF2_SaltBytes] = {0};
   
    uint8_t         unlocking_key[32] = {0};
    
    Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
    uint8_t             encrypted_key[128] = {0};
    int                 keyBytes = 0;
    void*               keyToEncrypt = NULL;
    
    char*           encodingPropString = NULL;
    char*           keySuiteString = "Invalid";
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };
    

    validateC4KeyContext(ctx);
    ValidateParam(passphrase);
    ValidateParam(outData);
    
    
    switch (ctx->type)
    {
        case kC4KeyType_Symmetric:
            keyBytes = ctx->sym.keylen ;
            keyToEncrypt = ctx->sym.symKey;
            
            switch (ctx->sym.symAlgor) {
                case kCipher_Algorithm_2FISH256:
                        encyptAlgor = kCipher_Algorithm_2FISH256;
                        encodingPropString =  kC4KeyProp_Encoding_PBKDF2_2FISH256;
                        break;
                    
                case kCipher_Algorithm_AES192:
                    encyptAlgor = kCipher_Algorithm_AES256;
                    encodingPropString =  kC4KeyProp_Encoding_PBKDF2_AES256;
    
                    //  pad the end  (treat it like it was 256 bits)
                    ZERO(&ctx->sym.symKey[24], 8);
                    keyBytes = 32;
                    break;
                    
                default:
                        encyptAlgor = kCipher_Algorithm_AES256;
                        encodingPropString =  kC4KeyProp_Encoding_PBKDF2_AES256;
                    break;
            }
            
            keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
            break;
   
        case kC4KeyType_Tweekable:
            keyBytes = ctx->tbc.keybits >> 3 ;
            encyptAlgor = kCipher_Algorithm_2FISH256;
            keySuiteString = tbc_algor_table(ctx->tbc.tbcAlgor);
            encodingPropString =  kC4KeyProp_Encoding_PBKDF2_2FISH256;
            keyToEncrypt = ctx->tbc.key;

          break;
            
        default:
            break;
    }
    
    
    err = RNG_GetBytes( salt, kC4KeyPBKDF2_SaltBytes ); CKERR;
    
    err = PASS_TO_KEY_SETUP(passphraseLen, keyBytes,
                            salt, sizeof(salt),
                             &rounds); CKERR;

    err = PASS_TO_KEY(passphrase, passphraseLen,
                      salt, sizeof(salt), rounds,
                      unlocking_key, sizeof(unlocking_key)); CKERR;
    
    err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
                           salt, sizeof(salt),
                           rounds,
                           keyHash, kC4KeyPBKDF2_HashBytes); CKERR;
 
    err =  ECB_Encrypt(encyptAlgor, unlocking_key, keyToEncrypt, keyBytes, encrypted_key); CKERR;
    
      g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
    
#if DEBUG
    yajl_gen_config(g, yajl_gen_beautify, 1);
#else
    yajl_gen_config(g, yajl_gen_beautify, 0);
    
#endif
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    stat = yajl_gen_map_open(g);
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_SCKeyVersion, strlen(kC4KeyProp_SCKeyVersion)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", kC4KeyProtocolVersion);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
   
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_Encoding, strlen(kC4KeyProp_Encoding)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)encodingPropString, strlen(encodingPropString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_KeySuite, strlen(kC4KeyProp_KeySuite)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_Salt, strlen(kC4KeyProp_Salt)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(salt, kC4KeyPBKDF2_SaltBytes, tempBuf, &tempLen);
    
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_Rounds, strlen(kC4KeyProp_Rounds)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", rounds);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_Hash, strlen(kC4KeyProp_Hash)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(keyHash, kC4KeyPBKDF2_HashBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_EncryptedKey, strlen(kC4KeyProp_EncryptedKey)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(encrypted_key, keyBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
  
    
    stat = yajl_gen_map_close(g); CKYJAL;
    stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;

    
    outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
    memcpy(outBuf, yajlBuf, yajlLen);
    outBuf[yajlLen] = 0;
    
    *outData = outBuf;
    *outSize = yajlLen;

 done:
    if(IsntNull(g))
        yajl_gen_free(g);
    
     return err;
   
}

C4Err C4Key_SerializeToPubKey(C4KeyContextRef   ctx,
                              ECC_ContextRef    eccPub,
                              uint8_t          **outData,
                              size_t           *outSize)
{
    C4Err           err = kC4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    uint8_t             *yajlBuf = NULL;
    size_t              yajlLen = 0;
    yajl_gen            g = NULL;
    
    uint8_t             tempBuf[1024];
    size_t              tempLen;
    uint8_t             *outBuf = NULL;
  
    char                curveName[32]  = {0};
  
    uint8_t             keyHash[kC4KeyPBKDF2_KeyIDBytes];
    size_t              keyHashLen = 0;

     uint8_t            encrypted[256] = {0};       // typical 199 bytes
    size_t              encryptedLen = 0;
    
    int                 keyBytes = 0;
    void*               keyToEncrypt = NULL;
    
     char*           keySuiteString = "Invalid";
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };
    
    
    validateC4KeyContext(ctx);
    validateECCContext(eccPub);
    ValidateParam(outData);
    
    switch (ctx->type)
    {
        case kC4KeyType_Symmetric:
            keyBytes = ctx->sym.keylen ;
            keyToEncrypt = ctx->sym.symKey;
            keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
             break;
            
        case kC4KeyType_Tweekable:
            keyBytes = ctx->tbc.keybits >> 3 ;
            keyToEncrypt = ctx->tbc.key;
            keySuiteString = tbc_algor_table(ctx->tbc.tbcAlgor);
            
            break;
            
        default:
            break;
    }
    
    /* limit ECC encryption to <= 512 bits of data */
    ValidateParam(keyBytes <= (512 >>3));
   
    err = ECC_CurveName(eccPub, curveName, sizeof(curveName), NULL); CKERR;
    err = ECC_PubKeyHash(eccPub, keyHash, kC4KeyPBKDF2_KeyIDBytes, &keyHashLen);CKERR;
    
    err = ECC_Encrypt(eccPub, keyToEncrypt, keyBytes,  encrypted, sizeof(encrypted), &encryptedLen);CKERR;
    
    g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
    
#if DEBUG
    yajl_gen_config(g, yajl_gen_beautify, 1);
#else
    yajl_gen_config(g, yajl_gen_beautify, 0);
    
#endif
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    stat = yajl_gen_map_open(g);
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_SCKeyVersion, strlen(kC4KeyProp_SCKeyVersion)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", kC4KeyProtocolVersion);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_Encoding, strlen(kC4KeyProp_Encoding)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)curveName, strlen(curveName)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_KeySuite, strlen(kC4KeyProp_KeySuite)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
  
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_KeyID, strlen(kC4KeyProp_KeyID)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(keyHash, keyHashLen, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kC4KeyProp_EncryptedKey, strlen(kC4KeyProp_EncryptedKey)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(encrypted, encryptedLen, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
     
    stat = yajl_gen_map_close(g); CKYJAL;
    stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
    
    
    outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
    memcpy(outBuf, yajlBuf, yajlLen);
    outBuf[yajlLen] = 0;
    
    *outData = outBuf;
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


enum C4Key_JSON_Type_
{
    C4Key_JSON_Type_Invalid ,
    C4Key_JSON_Type_BASE ,
    C4Key_JSON_Type_VERSION,
    C4Key_JSON_Type_KEYSUITE,
 
    C4Key_JSON_Type_ROUNDS,
    C4Key_JSON_Type_SALT,
    C4Key_JSON_Type_ENCODING,
    C4Key_JSON_Type_KEYHASH,
    C4Key_JSON_Type_ENCRYPTED_SYMKEY,
    C4Key_JSON_Type_KEYID,
    
    C4Key_JSON_Type_SYMKEY,
    
    ENUM_FORCE( C4Key_JSON_Type_ )
};
ENUM_TYPEDEF( C4Key_JSON_Type_, C4Key_JSON_Type   );

struct C4KeyJSONcontext
{
    uint8_t             version;    // message version
    C4KeyContext       key;        // used for decoding messages
    int                 level;
    
    C4Key_JSON_Type jType[8];
    void*           jItem;
    size_t*         jItemSize;
    uint8_t*        jTag;
    
 };

typedef struct C4KeyJSONcontext C4KeyJSONcontext;

static C4Err sParseKeySuiteString(const unsigned char * stringVal,  size_t stringLen,
                                  C4KeyType *keyTypeOut, int32_t *algorithmOut)
{
    
    C4Err               err = kC4Err_NoErr;
    C4KeyType   keyType = kC4KeyType_Invalid;
    int32_t     algorithm = kEnumMaxValue;
    
    
    if(CMP2(stringVal, stringLen, K_KEYSUITE_AES128, strlen(K_KEYSUITE_AES128)))
    {
        keyType  = kC4KeyType_Symmetric;
        algorithm = kCipher_Algorithm_AES128;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_AES192, strlen(K_KEYSUITE_AES192)))
    {
        keyType  = kC4KeyType_Symmetric;
        algorithm = kCipher_Algorithm_AES192;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_AES256, strlen(K_KEYSUITE_AES256)))
    {
        keyType  = kC4KeyType_Symmetric;
        algorithm = kCipher_Algorithm_AES256;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_2FISH256, strlen(K_KEYSUITE_2FISH256)))
    {
        keyType  = kC4KeyType_Symmetric;
        algorithm = kCipher_Algorithm_2FISH256;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH256, strlen(K_KEYSUITE_3FISH256)))
    {
        keyType  = kC4KeyType_Tweekable;
        algorithm = kTBC_Algorithm_3FISH256;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH512, strlen(K_KEYSUITE_3FISH512)))
    {
        keyType  = kC4KeyType_Tweekable;
        algorithm = kTBC_Algorithm_3FISH512;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH1024, strlen(K_KEYSUITE_3FISH1024)))
    {
        keyType  = kC4KeyType_Tweekable;
        algorithm = kTBC_Algorithm_3FISH1024;
    }
    
    if(keyType == kC4KeyType_Invalid)
        err = kC4Err_CorruptData;
    
    *keyTypeOut = keyType;
    *algorithmOut = algorithm;
    
    return err;
}


int sGetKeyLength(C4KeyType keyType, int32_t algorithm)
{
    int          keylen = 0;
    
    switch(keyType)
    {
        case kC4KeyType_Symmetric:
            
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
 
        case kC4KeyType_Tweekable:
            switch(algorithm)
        {
            case kTBC_Algorithm_3FISH256:
                keylen = 32;
                break;
                
            case kTBC_Algorithm_3FISH512:
                keylen = 64;
                break;
                
            case kTBC_Algorithm_3FISH1024:
                keylen = 128;
                break;
                
            default:;
        }
            break;
            
        default:;
      }
    
    
    return keylen;
    
}



static int sParse_start_map(void * ctx)
{
    C4KeyJSONcontext *jctx = (C4KeyJSONcontext*) ctx;
    int retval = 0;
    
//    printf("sParse_start_map\n");
    jctx->level++;
    
    if(IsntNull(jctx))
    {
        retval = 1;
        
    }
    
    return retval;
 }

static int sParse_end_map(void * ctx)
{
    C4KeyJSONcontext *jctx = (C4KeyJSONcontext*) ctx;
    int retval = 0;
    
//    printf("sParse_end_map\n");
    if(IsntNull(jctx)  )
    {
//        
//        if(jctx->level > 1)
//        {
//            C4KeyContext* key = &jctx->key;
//            
//            retval = 1;
//        }
//        else
              retval = 1;
        
        jctx->level--;
        
    }
       return retval;
}

static int sParse_start_array(void * ctx)
{
    C4KeyJSONcontext *jctx = (C4KeyJSONcontext*) ctx;
    int retval = 0;
    
    //    printf("sParse_start_map\n");
    jctx->level++;
    
    if(IsntNull(jctx))
    {
        retval = 1;
        
    }
    
    return retval;
}

static int sParse_end_array(void * ctx)
{
    C4KeyJSONcontext *jctx = (C4KeyJSONcontext*) ctx;
    int retval = 0;
    
    //    printf("sParse_start_map\n");
    jctx->level++;
    
    if(IsntNull(jctx))
    {
        retval = 1;
        
    }
    
    return retval;
}


static int sParse_number(void * ctx, const char * str, size_t len)
{
    C4KeyJSONcontext *jctx = (C4KeyJSONcontext*) ctx;
   char buf[32] = {0};
    int valid = 0;

//    printf("sParse_number\n");

    if(len < sizeof(buf))
    {
        COPY(str,buf,len);
        if(jctx->jType[jctx->level] == C4Key_JSON_Type_VERSION)
        {
            uint8_t val = atoi(buf);
            if(val == kC4KeyProtocolVersion)
            {
                jctx->version = val;
                valid = 1;

            }
         }
         else if(jctx->jType[jctx->level] == C4Key_JSON_Type_ROUNDS)
        {
            int val = atoi(buf);
            jctx->key.type = kC4KeyType_PBKDF2;
            jctx->key.pbkdf2.rounds = val;
            valid = 1;
        }
        
    }
    
    return valid;
}

static int sParse_string(void * ctx, const unsigned char * stringVal,
                         size_t stringLen)
{
    C4KeyJSONcontext *jctx = (C4KeyJSONcontext*) ctx;

    int valid = 1;
//    printf("sParse_string\n");
    
    if(0)
    {
        
    }
    else if(jctx->jType[jctx->level] == C4Key_JSON_Type_SALT)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal, stringLen, buf, &dataLen) == CRYPT_OK)
           && (dataLen == kC4KeyPBKDF2_SaltBytes))
        {
            jctx->key.type = kC4KeyType_PBKDF2;
            
            COPY(buf, jctx->key.pbkdf2.salt, dataLen);
            valid = 1;
        }
    }
    else if(jctx->jType[jctx->level] == C4Key_JSON_Type_KEYHASH)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
           && (dataLen == kC4KeyPBKDF2_HashBytes))
        {
            jctx->key.type = kC4KeyType_PBKDF2;
            
            COPY(buf, jctx->key.pbkdf2.keyHash, dataLen);
            valid = 1;
        }
    }
    else if(jctx->jType[jctx->level] == C4Key_JSON_Type_KEYID)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
           && (dataLen  == kC4KeyPBKDF2_KeyIDBytes))
        {
            jctx->key.type = kC4KeyType_PublicEncrypted;
            
            COPY(buf, jctx->key.publicKeyEncoded.keyID, dataLen);
            
            valid = 1;
        }
    }
    else if(jctx->jType[jctx->level] == C4Key_JSON_Type_ENCRYPTED_SYMKEY)
    {
        uint8_t     buf[256];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK))
        {
            size_t keyLength = 0;
            
            if(jctx->key.type == kC4KeyType_PBKDF2)
            {
                if(jctx->key.pbkdf2.keyAlgorithmType == kC4KeyType_Symmetric)
                {
                    keyLength = sGetKeyLength(kC4KeyType_Symmetric, jctx->key.pbkdf2.symAlgor);
                    
                    keyLength = keyLength == 24?32:keyLength;
                    
                }
                else  if(jctx->key.pbkdf2.keyAlgorithmType == kC4KeyType_Tweekable)
                {
                    keyLength = sGetKeyLength(kC4KeyType_Tweekable, jctx->key.pbkdf2.tbcAlgor);
                    
                }
                
                if(keyLength > 0 && keyLength == dataLen)
                {
                    COPY(buf, jctx->key.pbkdf2.encrypted, dataLen);
                    jctx->key.pbkdf2.encryptedLen = dataLen;
                    valid = 1;
                    
                }
              }
            else  if(jctx->key.type == kC4KeyType_PublicEncrypted)
            {
                
                if(dataLen <= kC4KeyPublic_Encrypted_BufferMAX)
                {
                    COPY(buf, jctx->key.publicKeyEncoded.encrypted, dataLen);
                    jctx->key.publicKeyEncoded.encryptedLen = dataLen;
                    valid = 1;
                 }
  
            }
        }
    }
    else if(jctx->jType[jctx->level] == C4Key_JSON_Type_ENCODING)
    {
        
        if(CMP2(stringVal, stringLen, kC4KeyProp_Encoding_PBKDF2_2FISH256, strlen(kC4KeyProp_Encoding_PBKDF2_2FISH256)))
        {
            jctx->key.type = kC4KeyType_PBKDF2;
            jctx->key.pbkdf2.encyptAlgor = kCipher_Algorithm_2FISH256;
            valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kC4KeyProp_Encoding_PBKDF2_AES256, strlen(kC4KeyProp_Encoding_PBKDF2_AES256)))
        {
                jctx->key.type = kC4KeyType_PBKDF2;
                jctx->key.pbkdf2.encyptAlgor = kCipher_Algorithm_AES256;
                valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kC4KeyProp_Encoding_PUBKEY_ECC384, strlen(kC4KeyProp_Encoding_PUBKEY_ECC384)))
        {
            jctx->key.type = kC4KeyType_PublicEncrypted;
            jctx->key.publicKeyEncoded.keysize = 384;
            valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kC4KeyProp_Encoding_PUBKEY_ECC414, strlen(kC4KeyProp_Encoding_PUBKEY_ECC414)))
        {
            jctx->key.type = kC4KeyType_PublicEncrypted;
            jctx->key.publicKeyEncoded.keysize = 414;
            valid = 1;
        }
     }
    else if(jctx->jType[jctx->level] == C4Key_JSON_Type_KEYSUITE)
    {
        C4KeyType   keyType = kC4KeyType_Invalid;
        int32_t     algorithm = kEnumMaxValue;
        
        if(IsntC4Err( sParseKeySuiteString(stringVal,  stringLen, &keyType, &algorithm)))
        {
            if( jctx->key.type == kC4KeyType_PBKDF2)
            {
                jctx->key.pbkdf2.keyAlgorithmType = keyType;

                if(keyType == kC4KeyType_Symmetric)
                {
                    jctx->key.pbkdf2.symAlgor = algorithm;
                    valid = 1;
                    
                }
                else  if(keyType == kC4KeyType_Tweekable)
                {
                    jctx->key.pbkdf2.tbcAlgor = algorithm;
                    valid = 1;
                }

            }
            else if( jctx->key.type == kC4KeyType_PublicEncrypted)
            {
                jctx->key.publicKeyEncoded.keyAlgorithmType = keyType;
                if(keyType == kC4KeyType_Symmetric)
                {
                    jctx->key.publicKeyEncoded.symAlgor = algorithm;
                    valid = 1;
                    
                }
                else  if(keyType == kC4KeyType_Tweekable)
                {
                    jctx->key.publicKeyEncoded.tbcAlgor = algorithm;
                    valid = 1;
                }
            }
            else
            {
                jctx->key.type = keyType;
                
                if(keyType == kC4KeyType_Symmetric)
                {
                    jctx->key.sym.symAlgor = algorithm;
                    valid = 1;
                    
                }
                else  if(keyType == kC4KeyType_Tweekable)
                {
                    jctx->key.tbc.tbcAlgor = algorithm;
                    valid = 1;
                }
            }
        }
     }

    return valid;

}

static int sParse_map_key(void * ctx, const unsigned char * stringVal, size_t stringLen )
{    int valid = 0;
 
    C4KeyJSONcontext *jctx = (C4KeyJSONcontext*) ctx;
   
//    printf("sParse_map_key\n");
    
    if(CMP2(stringVal, stringLen,kC4KeyProp_SCKeyVersion, strlen(kC4KeyProp_SCKeyVersion)))
    {
        jctx->jType[jctx->level] = C4Key_JSON_Type_VERSION;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kC4KeyProp_Rounds, strlen(kC4KeyProp_Rounds)))
    {
        jctx->jType[jctx->level] = C4Key_JSON_Type_ROUNDS;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kC4KeyProp_KeySuite, strlen(kC4KeyProp_KeySuite)))
    {
        jctx->jType[jctx->level] = C4Key_JSON_Type_KEYSUITE;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kC4KeyProp_Encoding, strlen(kC4KeyProp_Encoding)))
    {
        jctx->jType[jctx->level] = C4Key_JSON_Type_ENCODING;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kC4KeyProp_Salt, strlen(kC4KeyProp_Salt)))
    {
        jctx->jType[jctx->level] = C4Key_JSON_Type_SALT;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kC4KeyProp_Hash, strlen(kC4KeyProp_Hash)))
    {
        jctx->jType[jctx->level] = C4Key_JSON_Type_KEYHASH;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kC4KeyProp_EncryptedKey, strlen(kC4KeyProp_EncryptedKey)))
    {
        jctx->jType[jctx->level] = C4Key_JSON_Type_ENCRYPTED_SYMKEY;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kC4KeyProp_KeyID, strlen(kC4KeyProp_KeyID)))
    {
        jctx->jType[jctx->level] = C4Key_JSON_Type_KEYID;
        valid = 1;
    }
    
   return valid;

}



C4Err C4Key_Deserialize( uint8_t *inData, size_t inLen, C4KeyContextRef *ctx)
{
    C4Err           err = kC4Err_NoErr;
    yajl_status             stat = yajl_status_ok;
    yajl_handle             pHand = NULL;

    C4KeyJSONcontext       *jctx = NULL;

    static yajl_callbacks callbacks = {
        NULL,
        NULL,
        NULL,
        NULL,
        sParse_number,
        sParse_string,
        sParse_start_map,
        sParse_map_key,
        sParse_end_map,
        sParse_start_array,
        sParse_end_array
    };
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };

    ValidateParam(ctx);
    ValidateParam(inData);
    *ctx = NULL;

    jctx = XMALLOC(sizeof (C4KeyJSONcontext)); CKNULL(jctx);
    ZERO(jctx, sizeof(C4KeyJSONcontext));
    jctx->jType[jctx->level] = C4Key_JSON_Type_BASE;
    
    jctx->key.magic = kC4KeyContextMagic;
    jctx->key.type = kC4KeyType_Invalid;
    pHand = yajl_alloc(&callbacks, &allocFuncs, (void *) jctx);
    
    yajl_config(pHand, yajl_allow_comments, 1);
    stat = yajl_parse(pHand, inData,  inLen); CKYJAL;
    stat = yajl_complete_parse(pHand); CKYJAL;

    if(ctx)
    {
        *ctx =  XMALLOC(sizeof (C4KeyContext)); CKNULL(*ctx);
        COPY(&jctx->key, *ctx, sizeof (C4KeyContext));
    }
    
    
done:
    
    if(IsntNull(pHand))
        yajl_free(pHand);
    
    return err;
}

#ifdef __clang__
#pragma mark - verify passphrase.
#endif

C4Err C4Key_VerifyPassPhrase(   C4KeyContextRef  ctx,
                             const char       *passphrase,
                             size_t           passphraseLen)
{
    C4Err           err = kC4Err_NoErr;
    uint8_t         unlocking_key[32] = {0};
    size_t           keyBytes = 0;
    uint8_t         keyHash[kC4KeyPBKDF2_HashBytes] = {0};

    validateC4KeyContext(ctx);
    ValidateParam(passphrase);
    
    ValidateParam(ctx->type == kC4KeyType_PBKDF2);
    
    if(ctx->pbkdf2.keyAlgorithmType == kC4KeyType_Symmetric)
    {
        keyBytes = sGetKeyLength(kC4KeyType_Symmetric, ctx->pbkdf2.symAlgor);
        
    }
    else  if(ctx->pbkdf2.keyAlgorithmType == kC4KeyType_Tweekable)
    {
        keyBytes = sGetKeyLength(kC4KeyType_Tweekable, ctx->pbkdf2.tbcAlgor);
    }
    
    err = PASS_TO_KEY(passphrase, passphraseLen,
                      ctx->pbkdf2.salt, sizeof(ctx->pbkdf2.salt), ctx->pbkdf2.rounds,
                      unlocking_key, sizeof(unlocking_key)); CKERR;
    
    
    err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
                          ctx->pbkdf2.salt, sizeof(ctx->pbkdf2.salt), ctx->pbkdf2.rounds,
                           keyHash, kC4KeyPBKDF2_HashBytes); CKERR;
    
   ASSERTERR(!CMP(keyHash, ctx->pbkdf2.keyHash, kC4KeyPBKDF2_HashBytes), kC4Err_BadIntegrity)
    

done:
    
    ZERO(unlocking_key, sizeof(unlocking_key));
    
    return err;

}

C4Err C4Key_DecryptFromPassPhrase( C4KeyContextRef  passCtx,
                                  const char       *passphrase,
                                  size_t           passphraseLen,
                                  C4KeyContextRef       *symCtx)
{
    C4Err           err = kC4Err_NoErr;
    C4KeyContext*   keyCTX = NULL;

    Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
    uint8_t             unlocking_key[32] = {0};
     int                 keyBytes = 0;
    uint8_t             decrypted_key[128] = {0};
    uint8_t             keyHash[kC4KeyPBKDF2_HashBytes] = {0};
    
    validateC4KeyContext(passCtx);
    ValidateParam(passphrase);
    
    ValidateParam(passCtx->type == kC4KeyType_PBKDF2);
    
    if(passCtx->pbkdf2.keyAlgorithmType == kC4KeyType_Symmetric)
    {
        keyBytes = sGetKeyLength(kC4KeyType_Symmetric, passCtx->pbkdf2.symAlgor);
    
        switch (passCtx->pbkdf2.symAlgor)
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
    else  if(passCtx->pbkdf2.keyAlgorithmType == kC4KeyType_Tweekable)
    {
        encyptAlgor = kCipher_Algorithm_2FISH256;

        keyBytes = sGetKeyLength(kC4KeyType_Tweekable, passCtx->pbkdf2.tbcAlgor);
    }
    
    err = PASS_TO_KEY(passphrase, passphraseLen,
                      passCtx->pbkdf2.salt, sizeof(passCtx->pbkdf2.salt), passCtx->pbkdf2.rounds,
                      unlocking_key, sizeof(unlocking_key)); CKERR;
    
    
    err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
                           passCtx->pbkdf2.salt, sizeof(passCtx->pbkdf2.salt), passCtx->pbkdf2.rounds,
                           keyHash, kC4KeyPBKDF2_HashBytes); CKERR;
    
    ASSERTERR(!CMP(keyHash, passCtx->pbkdf2.keyHash, kC4KeyPBKDF2_HashBytes), kC4Err_BadIntegrity)
    
    keyCTX = XMALLOC(sizeof (C4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(C4KeyContext));
    
    keyCTX->magic = kC4KeyContextMagic;
    
    if(passCtx->pbkdf2.keyAlgorithmType == kC4KeyType_Symmetric)
    {
        int bytesToDecrypt = keyBytes == 24?32:keyBytes;
        keyCTX->type  = kC4KeyType_Symmetric;
        keyCTX->sym.symAlgor = passCtx->pbkdf2.symAlgor;
        keyCTX->sym.keylen = keyBytes;
        
        err =  ECB_Decrypt(encyptAlgor, unlocking_key, passCtx->pbkdf2.encrypted,
                           bytesToDecrypt, decrypted_key); CKERR;

        COPY(decrypted_key, keyCTX->sym.symKey, bytesToDecrypt);
      
    }
    else  if(passCtx->pbkdf2.keyAlgorithmType == kC4KeyType_Tweekable)
    {
        keyCTX->type  = kC4KeyType_Tweekable;
        keyCTX->tbc.tbcAlgor = passCtx->pbkdf2.tbcAlgor;
        keyCTX->tbc.keybits = keyBytes << 3;
        
        err =  ECB_Decrypt(encyptAlgor, unlocking_key, passCtx->pbkdf2.encrypted,
                           keyBytes,  decrypted_key); CKERR;

        Skein_Get64_LSB_First(keyCTX->tbc.key, decrypted_key, keyBytes >>2);   /* bytes to words */
      }
    
    

    *symCtx = keyCTX;
    
done:
    if(IsC4Err(err))
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



