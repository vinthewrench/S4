//
//  s4Key.c
//  S4
//
//  Created by vincent Moscaritolo on 11/9/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//


#include <ctype.h>

#ifndef __USE_BSD
#define __USE_BSD
#include <time.h>
#undef __USE_BSD
#endif


#if defined(ANDROID)
#include "timegm.c"
#endif



#include "s4internal.h"

#include <yajl_parse.h>
#include <yajl_gen.h>

#ifdef __clang__
#pragma mark - YAJL memory management
#endif


#define CKYJAL  if((stat != yajl_gen_status_ok)) {\
printf("ERROR %d (%d)  %s:%d \n",  err, stat, __FILE__, __LINE__); \
err = kS4Err_CorruptData; \
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


#define CMP2(b1, l1, b2, l2)							\
(((l1) == (l2)) && (memcmp((void *)(b1), (void *)(b2), (l1)) == 0))

#define STRCMP2(s1, s2) \
(CMP2((s1), strlen(s1), (s2), strlen(s2)))


#define kS4KeyProtocolVersion  0x01

#define K_KEYTYPE           "keyType"
#define K_KEYSUITE          "keySuite"
#define K_KEYDATA           "keyData"
#define K_HASHALGORITHM     "hashAlgorithm"

#define K_INDEX             "index"
#define K_THRESHLOLD        "threshold"
#define K_SHAREHASH         "sharehash"
#define K_SHAREIDS          "shareIDs"
#define K_PUBKEY            "pubKey"
#define K_PRIVKEY           "privKey"

#define K_KEYSUITE_AES128     "AES-128"
#define K_KEYSUITE_AES192     "AES-192"
#define K_KEYSUITE_AES256     "AES-256"
#define K_KEYSUITE_2FISH256   "Twofish-256"
#define K_KEYSUITE_3FISH256   "ThreeFish-256"
#define K_KEYSUITE_3FISH512   "ThreeFish-512"
#define K_KEYSUITE_3FISH1024  "ThreeFish-1024"
#define K_KEYSUITE_SPLIT      "Shamir"

#define K_HASHALGORITHM_SHA256    "SHA-256"
#define K_HASHALGORITHM_SHA512    "SHA-512"
#define K_HASHALGORITHM_SKEIN256  "SKEIN-256"
#define K_HASHALGORITHM_SKEIN512  "SKEIN-512"

#define K_KEYSUITE_ECC384     "ecc384"
#define K_KEYSUITE_ECC414     "Curve41417"

#define K_PROP_VERSION          "version"
#define K_PROP_ENCODING         "encoding"
#define K_PROP_SALT             "salt"
#define K_PROP_ROUNDS           "rounds"
#define K_PROP_MAC              "mac"
#define K_PROP_ENCRYPTED        "encrypted"
#define K_PROP_KEYID            "keyID"
#define K_PROP_KEYIDSTR         "keyID-String"

#define K_PROP_STARTDATE        "start-date"
#define K_PROP_EXPIREDATE       "expire-date"
#define K_SIGNATURE             "signature"
#define K_SIGNATURES            "signatures"
#define K_SIGN_BYID             "issuer"
#define K_SIGPROPS              "signed-properties"
#define K_PROP_SIGNED_DATE      "issue-date"
#define K_PROP_SIGEXPIRE        "sig-expire"
#define K_SIGNABLE_PROPS        "signable-properties"
#define K_SIGID                 "sigID"


char *const kS4KeyProp_KeyType          = K_KEYTYPE;
char *const kS4KeyProp_KeySuite         = K_KEYSUITE;
char *const kS4KeyProp_HashAlgorithm    = K_HASHALGORITHM;

char *const kS4KeyProp_KeyData          = K_KEYDATA;
char *const kS4KeyProp_KeyID            = K_PROP_KEYID;
char *const kS4KeyProp_KeyIDString      = K_PROP_KEYIDSTR;
char *const kS4KeyProp_Mac               = K_PROP_MAC;
char *const kS4KeyProp_StartDate        = K_PROP_STARTDATE;
char *const kS4KeyProp_ExpireDate       = K_PROP_EXPIREDATE;
char *const kS4KeyProp_EncryptedKey     = K_PROP_ENCRYPTED;
char *const kS4KeyProp_Encoding         = K_PROP_ENCODING;
char *const kS4KeyProp_SigID            = K_SIGID;

char *const kS4KeyProp_Signature        = K_SIGNATURE;
char *const kS4KeyProp_SignedBy         = K_SIGN_BYID;
char *const kS4KeyProp_SignedProperties = K_SIGPROPS;
char *const kS4KeyProp_SignedDate        = K_PROP_SIGNED_DATE;
char *const kS4KeyProp_SigExpire         = K_PROP_SIGEXPIRE;

char *const kS4KeyProp_SignableProperties  = K_SIGNABLE_PROPS;


static char *const kS4KeyProp_Version      = K_PROP_VERSION;

static char *const kS4KeyProp_Encoding_SYM_AES128    = K_KEYSUITE_AES128;
static char *const kS4KeyProp_Encoding_SYM_AES256    = K_KEYSUITE_AES256;
static char *const kS4KeyProp_Encoding_SYM_2FISH256    = K_KEYSUITE_2FISH256;

static char *const kS4KeyProp_Encoding_PBKDF2_AES256    = "pbkdf2-AES256";
static char *const kS4KeyProp_Encoding_PBKDF2_2FISH256  = "pbkdf2-Twofish-256";

static char *const kS4KeyProp_Encoding_SPLIT_AES256    = "Shamir-AES256";
static char *const kS4KeyProp_Encoding_SPLIT_2FISH256  = "Shamir-Twofish-256";

static char *const kS4KeyProp_Encoding_PUBKEY_ECC384   =  "ECC-384";
static char *const kS4KeyProp_Encoding_PUBKEY_ECC414   =  "Curve41417";

static char *const kS4KeyProp_Encoding_Signature       = "Signature";

static char *const kS4KeyProp_Salt              = K_PROP_SALT;
static char *const kS4KeyProp_Rounds            = K_PROP_ROUNDS;

static char *const kS4KeyProp_ShareIndex      = K_INDEX;
static char *const kS4KeyProp_ShareThreshold  = K_THRESHLOLD;
static char *const kS4KeyProp_ShareHash        = K_SHAREHASH;
static char *const kS4KeyProp_ShareIDs        = K_SHAREIDS;

static char *const kS4KeyProp_PubKey            = K_PUBKEY;
static char *const kS4KeyProp_PrivKey           = K_PRIVKEY;

static char *const kS4KeyProp_Signatures    = K_SIGNATURES;

static const char *kRfc339Format = "%Y-%m-%dT%H:%M:%SZ";


typedef struct S4KeyPropertyInfo  S4KeyPropertyInfo;

struct S4KeyPropertyInfo
{
    char      *const name;
    S4KeyPropertyType type;
    bool              readOnly;
    bool              signable;
} ;


static S4KeyPropertyInfo sPropertyTable[] = {
    
    { K_PROP_VERSION,           S4KeyPropertyType_Numeric,  true,  false},
    { K_KEYTYPE,                S4KeyPropertyType_Numeric,  true,  false},
    { K_KEYSUITE,               S4KeyPropertyType_Numeric,  true,  true},
    { K_KEYDATA,                S4KeyPropertyType_Binary,  true,  true},
    { K_HASHALGORITHM,          S4KeyPropertyType_Numeric,  true,  false},
    
    { K_PROP_ENCODING,          S4KeyPropertyType_UTF8String,  true,  true},
    { K_PROP_SALT,              S4KeyPropertyType_Binary,  true,  true},
    { K_PROP_ROUNDS,            S4KeyPropertyType_Numeric,  true,  true},
    { K_PROP_MAC,               S4KeyPropertyType_Binary,  true,  true},
    { K_PROP_ENCRYPTED,         S4KeyPropertyType_Binary,  true,  true},
    { K_PROP_KEYID,             S4KeyPropertyType_Binary,  true,  true},
    { K_PROP_KEYIDSTR,          S4KeyPropertyType_UTF8String,  true,  true},
    
    { K_SHAREHASH,              S4KeyPropertyType_Binary,  true,  true},
    { K_INDEX,                  S4KeyPropertyType_Numeric,  true,  true},
    { K_THRESHLOLD,              S4KeyPropertyType_Numeric,  true,  true},
    
    { K_SIGN_BYID,              S4KeyPropertyType_Binary,   true,  false},
    { K_PROP_EXPIREDATE,        S4KeyPropertyType_Time,     false,  true},
    { K_PROP_STARTDATE,         S4KeyPropertyType_Time,     false,  true},
    { K_PROP_SIGNED_DATE,       S4KeyPropertyType_Time,     true,  false},
    { K_PROP_SIGEXPIRE,         S4KeyPropertyType_Time,     true,  false},
    { K_SIGID,                  S4KeyPropertyType_Binary,  false,  false},
    
    { NULL,                     S4KeyPropertyType_Invalid,  true,  true},
};


#ifdef __clang__
#pragma mark - fwd declare
#endif

static void sCloneSignatures(S4KeyContext *src, S4KeyContext *dest );
static char** sDeepStrDup( char** list);
static S4Err sGetSignablePropertyNames(S4KeyContext *ctx,  char ***namesOut, size_t* countOut );
static S4Err sCalulateKeyDigest( S4KeyContextRef  keyCtx,
                                char**            optionalPropNamesList,
                                HASH_Algorithm    hashAlgorithm,
                                time_t            signDate,
                                long              sigExpireTime,
                                uint8_t* hashBuf, size_t *hashBytes );

#ifdef __clang__
#pragma mark - Key utilities.
#endif

static char *cipher_algor_table(Cipher_Algorithm algor)
{
    switch (algor )
    {
        case kCipher_Algorithm_AES128: 		return (K_KEYSUITE_AES128);
        case kCipher_Algorithm_AES192: 		return (K_KEYSUITE_AES192);
        case kCipher_Algorithm_AES256: 		return (K_KEYSUITE_AES256);
        case kCipher_Algorithm_2FISH256:    return (K_KEYSUITE_2FISH256);
            
        case kCipher_Algorithm_3FISH256:    return (K_KEYSUITE_3FISH256);
        case kCipher_Algorithm_3FISH512:    return (K_KEYSUITE_3FISH512);
        case kCipher_Algorithm_3FISH1024:   return (K_KEYSUITE_3FISH1024);
            
        case kCipher_Algorithm_ECC384:      return (K_KEYSUITE_ECC384);
        case kCipher_Algorithm_ECC414:      return (K_KEYSUITE_ECC414);
            
        case kCipher_Algorithm_SharedKey: 		return (K_KEYSUITE_SPLIT);
            
            
        default:				return (("Invalid"));
    }
}


char *hash_algor_table(HASH_Algorithm algor)
{
    switch (algor )
    {
        case kHASH_Algorithm_SHA256:		return (K_HASHALGORITHM_SHA256);
        case kHASH_Algorithm_SHA512:		return (K_HASHALGORITHM_SHA512);
        case kHASH_Algorithm_SKEIN256:		return (K_HASHALGORITHM_SKEIN256);
        case kHASH_Algorithm_SKEIN512:		return (K_HASHALGORITHM_SKEIN512);
        default:				return (("Invalid"));
    }
}


static bool sS4KeyContextIsValid( const S4KeyContextRef  ref)
{
    bool       valid	= false;
    
    valid	= IsntNull( ref ) && ref->magic	 == kS4KeyContextMagic;
    
    return( valid );
}

#define validateS4KeyContext( s )		\
ValidateParam( sS4KeyContextIsValid( s ) )

static S4Err sPASSPHRASE_HASH( const uint8_t  *key,
                              unsigned long  key_len,
                              uint8_t       *salt,
                              unsigned long  salt_len,
                              uint32_t        roundsIn,
                              uint8_t        *mac_buf,
                              unsigned long  mac_len)
{
    S4Err           err = kS4Err_NoErr;
    
    MAC_ContextRef  macRef     = kInvalidMAC_ContextRef;
    
    uint32_t        rounds = roundsIn;
    uint8_t         L[4];
    char*           label = "passphrase-hash";
    
    L[0] = (salt_len >> 24) & 0xff;
    L[1] = (salt_len >> 16) & 0xff;
    L[2] = (salt_len >> 8) & 0xff;
    L[3] = salt_len & 0xff;
    
    err = MAC_Init(kMAC_Algorithm_SKEIN,
                   kHASH_Algorithm_SKEIN256,
                   key, key_len, &macRef); CKERR
    
    MAC_Update(macRef,  "\x00\x00\x00\x01",  4);
    MAC_Update(macRef,  label,  strlen(label));
    
    err = MAC_Update( macRef, salt, salt_len); CKERR;
    MAC_Update(macRef,  L,  4);
    
    err = MAC_Update( macRef, &rounds, sizeof(rounds)); CKERR;
    MAC_Update(macRef,  "\x00\x00\x00\x04",  4);
    
    size_t mac_len_SZ = (size_t)mac_len;
    err = MAC_Final( macRef, mac_buf, &mac_len_SZ); CKERR;
    
done:
    
    MAC_Free(macRef);
    
    return err;
}

static S4Err sKEY_HASH( const uint8_t  *key,
                       unsigned long  key_len,
                       S4KeyType     keyTypeIn,
                       int           keyAlgorithmIn,
                       uint8_t        *mac_buf,
                       unsigned long  mac_len)
{
    S4Err           err = kS4Err_NoErr;
    
    MAC_ContextRef  macRef     = kInvalidMAC_ContextRef;
    
    uint32_t        keyType = keyTypeIn;
    uint32_t        algorithm = keyAlgorithmIn;
    
    char*           label = "key-hash";
    
    err = MAC_Init(kMAC_Algorithm_SKEIN,
                   kHASH_Algorithm_SKEIN256,
                   key, key_len, &macRef); CKERR
    
    MAC_Update(macRef,  "\x00\x00\x00\x01",  4);
    MAC_Update(macRef,  label,  strlen(label));
    
    err = MAC_Update( macRef, &keyType, sizeof(keyType)); CKERR;
    MAC_Update(macRef,  "\x00\x00\x00\x04",  4);
    
    err = MAC_Update( macRef, &algorithm, sizeof(algorithm)); CKERR;
    MAC_Update(macRef,  "\x00\x00\x00\x04",  4);
    
    size_t mac_len_SZ = (size_t)mac_len;
    err = MAC_Final( macRef, mac_buf, &mac_len_SZ); CKERR;
    
done:
    
    MAC_Free(macRef);
    
    return err;
}


int sGetKeyLength(S4KeyType keyType, int32_t algorithm)
{
    int          keylen = 0;
    
    switch(keyType)
    {
        case kS4KeyType_Symmetric:
            
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
            
        case kS4KeyType_Tweekable:
            switch(algorithm)
        {
            case kCipher_Algorithm_3FISH256:
                keylen = 32;
                break;
                
            case kCipher_Algorithm_3FISH512:
                keylen = 64;
                break;
                
            case kCipher_Algorithm_3FISH1024:
                keylen = 128;
                break;
                
            default:;
        }
            break;
            
        default:;
    }
    
    
    return keylen;
    
}

static yajl_gen_status sGenPropStrings(S4KeyContextRef ctx, yajl_gen g)

{
    S4Err           err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    S4KeyProperty *prop = ctx->propList;
    while(prop)
    {
        stat = yajl_gen_string(g, prop->prop, strlen((char *)(prop->prop))) ; CKYJAL;
        switch(prop->type)
        {
            case S4KeyPropertyType_UTF8String:
                stat = yajl_gen_string(g, prop->value, prop->valueLen) ; CKYJAL;
                
                break;
                
            case S4KeyPropertyType_Binary:
            {
                size_t propLen =  prop->valueLen*4;
                uint8_t     *propBuf =  XMALLOC(propLen);
                
                base64_encode(prop->value, prop->valueLen, propBuf, &propLen);
                stat = yajl_gen_string(g, propBuf, (size_t)propLen) ; CKYJAL;
                XFREE(propBuf);
            }
                break;
                
            case S4KeyPropertyType_Time:
            {
                uint8_t     tempBuf[32];
                size_t      tempLen;
                time_t      gTime;
                struct      tm *nowtm;
                
                COPY(prop->value, &gTime, sizeof(gTime));
                nowtm = gmtime(&gTime);
                tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
                stat = yajl_gen_string(g, tempBuf, tempLen) ; CKYJAL;
            }
                break;
                
            default:
                yajl_gen_string(g, (uint8_t *)"NULL", 4) ;
                break;
        }
        
        prop = prop->next;
    }
    
done:
    return err;
}
static yajl_gen_status sGenSignatureStrings(S4KeyContextRef ctx, yajl_gen g)

{
    S4Err               err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    uint8_t             tempBuf[1024];
    size_t              tempLen;

    char*               hashAlgorString = "Invalid";
    
    S4KeySigItem *sigItem = ctx->sigList;
    if(sigItem)
    {
        stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Signatures, strlen(kS4KeyProp_Signatures)) ; CKYJAL;
         stat = yajl_gen_array_open(g);
        while(sigItem)
        {

            stat = yajl_gen_map_open(g); CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SigID, strlen(kS4KeyProp_SigID)) ; CKYJAL;
            tempLen = sizeof(tempBuf);
            base64_encode(sigItem->sig.sigID, kS4Key_KeyIDBytes, tempBuf, &tempLen);
            stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_HashAlgorithm, strlen(kS4KeyProp_HashAlgorithm)) ; CKYJAL
            hashAlgorString = hash_algor_table(sigItem->sig.hashAlgorithm);
            stat = yajl_gen_string(g, (uint8_t *)hashAlgorString, strlen(hashAlgorString)) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Signature, strlen(kS4KeyProp_Signature)) ; CKYJAL;
            
            tempLen = sizeof(tempBuf);
            base64_encode(sigItem->sig.signature, sigItem->sig.signatureLen, tempBuf, &tempLen);
            stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedBy, strlen(kS4KeyProp_SignedBy)) ; CKYJAL;
            tempLen = sizeof(tempBuf);
            base64_encode(sigItem->sig.issuerID, kS4Key_KeyIDBytes, tempBuf, &tempLen);
            stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedDate, strlen(kS4KeyProp_SignedDate)) ; CKYJAL;
            struct tm *nowtm;
            nowtm = gmtime(&sigItem->sig.signDate);
            tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
            stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;

            if(sigItem->sig.expirationTime != LONG_MAX)
            {
                stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SigExpire, strlen(kS4KeyProp_SigExpire)) ; CKYJAL;
                stat = yajl_gen_integer(g, sigItem->sig.expirationTime) ; CKYJAL;
             }
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedProperties, strlen(kS4KeyProp_SignedProperties)) ; CKYJAL;
             stat = yajl_gen_array_open(g);
            for(char** itemName = sigItem->sig.propNameList ;*itemName; itemName++)
            {
                stat = yajl_gen_string(g, (uint8_t *)*itemName, strlen(*itemName)) ; CKYJAL;
                
            }
            stat = yajl_gen_array_close(g);
            stat = yajl_gen_map_close(g); CKYJAL;

            sigItem = sigItem->next;
        }
        stat = yajl_gen_array_close(g);
   
    }

done:
    return err;

}

static yajl_gen_status sGenSignablePropString(S4KeyContextRef ctx, yajl_gen g)

{
    S4Err               err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    size_t      propListEntries = 0;
    char**       propList = NULL;
    
    err = sGetSignablePropertyNames(ctx, &propList, &propListEntries); CKERR;
   
    if(propListEntries > 0)
    {
        stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignableProperties, strlen(kS4KeyProp_SignableProperties)) ; CKYJAL;
        stat = yajl_gen_array_open(g);
        for(size_t i = 0  ; i < propListEntries; i++)
        {
            stat = yajl_gen_string(g, (uint8_t *)propList[i], strlen(propList[i])) ; CKYJAL;
            
        }
        stat = yajl_gen_array_close(g);
  
    }
    
done:
    
    for(int i = 0; propList[i]; i++)
        XFREE(propList[i]);
    
    XFREE(propList);

    return err;
    
    
}


#ifdef __clang__
#pragma mark - Key property management.
#endif

static S4KeyProperty* sFindProperty(S4KeyContext *ctx, const char *propName )
{
    S4KeyProperty* prop = ctx->propList;
    
    while(prop)
    {
        if(CMP2(prop->prop, strlen((char *)(prop->prop)), propName, strlen(propName)))
        {
            break;
        }else
            prop = prop->next;
    }
    
    return prop;
}

static void sInsertProperty(S4KeyContext *ctx, const char *propName,
                            S4KeyPropertyType propType,
                            S4KeyPropertyExtendedType  extendedPropType,
                            void *data,  size_t  datSize)
{
    S4KeyProperty* prop = sFindProperty(ctx,propName);
    if(!prop)
    {
        prop = XMALLOC(sizeof(S4KeyProperty));
        ZERO(prop,sizeof(S4KeyProperty));
        prop->prop = (uint8_t *)strndup(propName, strlen(propName));
        prop->next = ctx->propList;
        ctx->propList = prop;
    }
    
    if(prop->value) XFREE(prop->value);
    prop->value = XMALLOC(datSize);
    prop->type = propType;
    prop->extended = extendedPropType;
    COPY(data, prop->value, datSize );
    prop->valueLen = datSize;
};


static void sCloneProperties(S4KeyContext *src, S4KeyContext *dest )
{
    S4KeyProperty* sprop = NULL;
    S4KeyProperty** lastProp = &dest->propList;
    
    for(sprop = src->propList; sprop; sprop = sprop->next)
    {
        S4KeyProperty* newProp =  XMALLOC(sizeof(S4KeyProperty));
        ZERO(newProp,sizeof(S4KeyProperty));
        newProp->prop = (uint8_t *)strndup((char *)(sprop->prop), strlen((char *)(sprop->prop)));
        newProp->type = sprop->type;
        newProp->extended = sprop->extended;
        newProp->value = XMALLOC(sprop->valueLen);
        COPY(sprop->value, newProp->value, sprop->valueLen );
        newProp->valueLen = sprop->valueLen;
        *lastProp = newProp;
        lastProp = &newProp->next;
    }
    *lastProp = NULL;
    
}


static int cmpPropNames(const void *p1, const void *p2){
    return strcasecmp(* (char * const *) p1, * (char * const *) p2);
}

static S4Err sGetSignablePropertyNames(S4KeyContext *ctx,  char ***namesOut, size_t* countOut )
{
    S4Err               err = kS4Err_NoErr;
 
    const size_t alloc_quantum = 8;

    S4KeyProperty* prop = ctx->propList;
    size_t count = 0;
    size_t allocCount = alloc_quantum;
    char** names =  NULL;
    
    validateS4KeyContext(ctx);

    names = XMALLOC(allocCount * sizeof(char*) );

    if(prop)
    {
        switch (ctx->type)
        {
                
            case kS4KeyType_PublicKey:
                names[count++] = strdup(kS4KeyProp_KeySuite);
                names[count++] = strdup(kS4KeyProp_KeyID);
                names[count++] = strdup(kS4KeyProp_PubKey);
                break;
                
            case kS4KeyType_Signature:
                names[count++] = strdup(kS4KeyProp_SigID);
                names[count++] = strdup(kS4KeyProp_SignedBy);
                names[count++] = strdup(kS4KeyProp_Signature);
                names[count++] = strdup(kS4KeyProp_SignedDate);
                names[count++] = strdup(kS4KeyProp_SigExpire);
                break;
                
                // add in more names here for other types of keys.
            default:
                names[count++] = strdup(kS4KeyProp_KeySuite);
                names[count++] = strdup(kS4KeyProp_KeyID);
                
                break;
        }
    }
    

//        
//        // add in built in properites
//        names[count++] = strdup(kS4KeyProp_KeySuite);
//        names[count++] = strdup(kS4KeyProp_KeyID);
//     }
    
//    switch (ctx->type)
//    {
//        case kS4KeyType_PublicKey:
//            names[count++] = strdup(kS4KeyProp_PubKey);
//            break;
//            
//        default:
//    // add in more names here for other types of keys.
//            break;
//    }

    while(prop)
    {
        if(count > allocCount)
        {
            allocCount += alloc_quantum;
            names =  XREALLOC(names, allocCount * sizeof(char*) );
        }
        
        names[count] = strdup((char*) prop->prop );
        count++;
        prop = prop->next;
    }
    
    // put a null termination on list
    if(count > allocCount)
    {
        allocCount += alloc_quantum;
        names =  XREALLOC(names, allocCount * sizeof(char*) );
    }
    names[count] = NULL;
    
    if(names)
    {
        qsort(names, count, sizeof(char *), cmpPropNames);
    }
    
    if(namesOut)
    {
        *namesOut = names;
    }
    else
    {
        for(int i = 0; i < count; i++)
            XFREE(names[i]);
        
        XFREE(names);
     }
    
    if(countOut) *countOut = count;
    
done:
    return err;

}


S4Err S4Key_SetProperty( S4KeyContextRef ctx,
                        const char *propName, S4KeyPropertyType propType,
                        void *data,  size_t  datSize)
{
    return S4Key_SetPropertyExtended(ctx, propName,propType, S4KeyPropertyExtendedType_None, data,datSize);
}

S4Err S4Key_SetPropertyExtended ( S4KeyContextRef ctx,
                                 const char *propName, S4KeyPropertyType propType,
                                 S4KeyPropertyExtendedType  extendedPropType,
                                 void *data,  size_t  datSize)
{
    
    S4Err               err = kS4Err_NoErr;
    S4KeyPropertyInfo  *propInfo = NULL;
    bool found = false;
    
    validateS4KeyContext(ctx);
    
    for(propInfo = sPropertyTable; propInfo->name; propInfo++)
    {
        if(CMP2(propName, strlen(propName), propInfo->name, strlen(propInfo->name)))
        {
            if(propInfo->readOnly)
                RETERR(kS4Err_BadParams);
            
            if(propType != propInfo->type)
                RETERR(kS4Err_BadParams);
            
            if(propInfo->signable)
                extendedPropType |= S4KeyPropertyExtended_Signable;
            
            found = true;
            break;
        }
    }
    
    // if you get this far, you can insert a property
    sInsertProperty(ctx, propName, propType,extendedPropType, data, datSize);CKERR;
    
done:
    return err;
    
}



static S4Err s4Key_GetPropertyInternal( S4KeyContextRef ctx,
                                       const char *propName,
                                       S4KeyPropertyType *outPropType,
                                       S4KeyPropertyExtendedType *outExtendedProp,
                                       void *outData, size_t bufSize, size_t *datSize, bool doAlloc,
                                       uint8_t** allocBuffer)
{
    S4Err               err = kS4Err_NoErr;
    S4KeyPropertyInfo   *propInfo   = NULL;
    S4KeyProperty*      otherProp   = NULL;
    S4KeyPropertyType   propType    = S4KeyPropertyType_Invalid;
    S4KeyPropertyExtendedType extendedProp =  S4KeyPropertyExtendedType_None;
    bool                found       = false;
    
    size_t          actualLength = 0;
    uint8_t*        buffer = NULL;
    
    if(datSize)
        *datSize = 0;
    
    // write code here to process internal properties
    for(propInfo = sPropertyTable;propInfo->name; propInfo++)
    {
        if(CMP2(propName, strlen(propName), propInfo->name, strlen(propInfo->name)))
        {
            propType = propInfo->type;
            
            if(propInfo->signable)
                extendedProp |= S4KeyPropertyExtended_Signable;
            
            found = true;
            
            if(STRCMP2(propName, kS4KeyProp_KeyType))
            {
                actualLength =  sizeof(S4KeyType);
            }
            else if(STRCMP2(propName, kS4KeyProp_KeySuite))
            {
                actualLength =  sizeof(uint32_t);
            }
            else if(STRCMP2(propName, kS4KeyProp_HashAlgorithm))
            {
                actualLength =  sizeof(uint32_t);
            }
            else if(STRCMP2(propName, kS4KeyProp_Encoding))
            {
                actualLength =  sizeof(uint32_t);
            }
            else if(STRCMP2(propName, kS4KeyProp_KeyData))
            {
                switch (ctx->type) {
                    case kS4KeyType_Symmetric:
                        actualLength = ctx->sym.keylen;
                        break;
                        
                    case kS4KeyType_Tweekable:
                        actualLength = ctx->tbc.keybits >> 3 ;
                        break;
                        
                    case kS4KeyType_PublicEncrypted:
                        actualLength = ctx->publicKeyEncoded.encryptedLen;
                        break;
                        
                    case kS4KeyType_PBKDF2:
                    default:
                        RETERR(kS4Err_BadParams);
                }
            }
            
            else if(STRCMP2(propName, kS4KeyProp_SigID))
            {
                switch (ctx->type) {
                    case kS4KeyType_Signature:
                        actualLength = sizeof(ctx->sig.sigID);
                        break;
                        
                    default:
                        RETERR(kS4Err_BadParams);
                }
            }
            else if(STRCMP2(propName, kS4KeyProp_SignedBy))
            {
                switch (ctx->type) {
                    case kS4KeyType_Signature:
                        actualLength = sizeof(ctx->sig.issuerID);
                        break;
                        
                    default:
                        RETERR(kS4Err_BadParams);
                }
            }
   
            else if(STRCMP2(propName, kS4KeyProp_SignedDate))
            {
                switch (ctx->type) {
                    case kS4KeyType_Signature:
                        actualLength = sizeof(ctx->sig.signDate);
                        break;
                        
                    default:
                        RETERR(kS4Err_BadParams);
                }
            }
            else if(STRCMP2(propName, kS4KeyProp_SigExpire))
            {
                switch (ctx->type) {
                    case kS4KeyType_Signature:
                        actualLength = sizeof(ctx->sig.expirationTime);
                        break;
                        
                    default:
                        RETERR(kS4Err_BadParams);
                }
            }
            else if(STRCMP2(propName, kS4KeyProp_KeyID))
            {
                switch (ctx->type) {
                    case kS4KeyType_PublicEncrypted:
                        actualLength = sizeof(ctx->publicKeyEncoded.keyID);
                        break;
                        
                    case kS4KeyType_SymmetricEncrypted:
                        actualLength = sizeof(ctx->symKeyEncoded.keyID);
                        break;
                        
                    case kS4KeyType_PublicKey:
                        actualLength = sizeof(ctx->pub.keyID);
                        break;
                        
                     case kS4KeyType_Symmetric:
                        actualLength = kS4Key_KeyIDBytes;
                        break;
                        
                    case kS4KeyType_Tweekable:
                        actualLength = kS4Key_KeyIDBytes;
                        break;
                        
                    default:
                        RETERR(kS4Err_BadParams);
                }
            }
            
            else if(STRCMP2(propName, kS4KeyProp_Mac))
            {
                switch (ctx->type) {
                    case kS4KeyType_Symmetric:
                    case kS4KeyType_Tweekable:
                    case kS4KeyType_Share:
                    case kS4KeyType_PublicEncrypted:
                        actualLength = kS4KeyPublic_Encrypted_HashBytes;
                        break;
                        
                        //                     case kS4KeyType_PublicEncrypted:
                        //                        actualLength = sizeof(ctx->publicKeyEncoded.keyID);
                        //                        break;
                        
                    default:
                        RETERR(kS4Err_BadParams);
                }
            }
            else if(STRCMP2(propName, kS4KeyProp_KeyIDString))
            {
                switch (ctx->type) {
                        
                    case kS4KeyType_SymmetricEncrypted:
                        actualLength = (((sizeof(ctx->symKeyEncoded.keyID) + 2) / 3) * 4) + 1;
                        break;
                        
                    case kS4KeyType_PublicEncrypted:
                        actualLength = (((sizeof(ctx->publicKeyEncoded.keyID) + 2) / 3) * 4) + 1;
                        break;
                        
                    case kS4KeyType_PublicKey:
                        actualLength = (((sizeof(ctx->pub.keyID) + 2) / 3) * 4) + 1;
                        break;
                        
                        
                    case kS4KeyType_Symmetric:
                        actualLength =  (((kS4Key_KeyIDBytes + 2) / 3) * 4) + 1; ;
                        break;
                        
                    case kS4KeyType_Tweekable:
                        actualLength =  (((kS4Key_KeyIDBytes + 2) / 3) * 4) + 1; ;
                        break;
                        
                    default:
                        RETERR(kS4Err_BadParams);
                }
            }
            else
                found = false;
            
            break;
            
        }
    }
    
    if(!found)
    {
        otherProp = sFindProperty(ctx,propName);
        if(otherProp)
        {
            actualLength = (unsigned long)(otherProp->valueLen);
            propType = otherProp->type;
            extendedProp = otherProp->extended;
            found = true;
        }
    }
    
    if(!found)
        RETERR(kS4Err_PropertyNotFound);
    
    
    if(!actualLength)
        goto done;
    
    if(doAlloc)
    {
        buffer = XMALLOC(actualLength + sizeof('\0')); CKNULL(buffer);
        *allocBuffer = buffer;
    }
    else
    {
        actualLength = (actualLength < (unsigned long)bufSize) ? actualLength : (unsigned long)bufSize;
        buffer = outData;
    }
    
    if(STRCMP2(propName, kS4KeyProp_KeyType))
    {
        COPY(&ctx->type, buffer, actualLength);
    }
    else if(STRCMP2(propName, kS4KeyProp_HashAlgorithm))
    {
        switch (ctx->type) {
            case kS4KeyType_Signature:
                COPY(&ctx->sig.hashAlgorithm , buffer, actualLength);
                break;
                
               default:
                RETERR(kS4Err_BadParams);
                
        }
    }
    else if(STRCMP2(propName, kS4KeyProp_KeySuite))
    {
        switch (ctx->type) {
            case kS4KeyType_Symmetric:
                COPY(&ctx->sym.symAlgor , buffer, actualLength);
                break;
                
            case kS4KeyType_Tweekable:
                COPY(&ctx->tbc.tbcAlgor , buffer, actualLength);
                break;
                
            case kS4KeyType_PublicKey:
                COPY(&ctx->pub.cipherAlgor , buffer, actualLength);
                break;
                
            case kS4KeyType_PublicEncrypted:
                COPY(&ctx->publicKeyEncoded.cipherAlgor , buffer, actualLength);
                break;
                
            case kS4KeyType_PBKDF2:
            default:
                RETERR(kS4Err_BadParams);
                
        }
    }
    else if(STRCMP2(propName, kS4KeyProp_Encoding))
    {
        switch (ctx->type) {
            case kS4KeyType_PublicEncrypted:
            {
                Cipher_Algorithm  algor = kCipher_Algorithm_Invalid;
                
                switch(ctx->publicKeyEncoded.keysize)
                {
                    case 384: algor = kCipher_Algorithm_ECC384; break;
                    case 414: algor = kCipher_Algorithm_ECC414 ; break;
                    default: algor = kCipher_Algorithm_Invalid;
                }
                COPY(&algor , buffer, actualLength);
                
            }
                break;
                
            default:
                RETERR(kS4Err_BadParams);
        }
    }
    else if(STRCMP2(propName, kS4KeyProp_KeyData))
    {
        switch (ctx->type) {
            case kS4KeyType_Symmetric:
                COPY(&ctx->sym.symKey , buffer, actualLength);
                break;
                
            case kS4KeyType_Tweekable:
                COPY(&ctx->tbc.key , buffer, actualLength);
                break;
                
            case kS4KeyType_PublicEncrypted:
                COPY(&ctx->publicKeyEncoded.encrypted , buffer, actualLength);
                break;
                
            case kS4KeyType_PBKDF2:
            default:
                RETERR(kS4Err_BadParams);
        }
    }
    
    
    else if(STRCMP2(propName, kS4KeyProp_SigID))
    {
        switch (ctx->type) {
                
            case kS4KeyType_Signature:
                COPY(&ctx->sig.sigID , buffer, actualLength);
                break;
                
            default:
                RETERR(kS4Err_BadParams);
                
        }
    }
    else if(STRCMP2(propName, kS4KeyProp_SignedBy))
    {
        switch (ctx->type) {
                
            case kS4KeyType_Signature:
                COPY(&ctx->sig.issuerID , buffer, actualLength);
                break;

            default:
                RETERR(kS4Err_BadParams);

        }
    }
    else if(STRCMP2(propName, kS4KeyProp_SignedDate))
    {
        switch (ctx->type) {
            case kS4KeyType_Signature:
                
                COPY(&ctx->sig.signDate, buffer, actualLength);
                break;
                
            default:
                RETERR(kS4Err_BadParams);
        }
    }

    else if(STRCMP2(propName, kS4KeyProp_SigExpire))
   {
        switch (ctx->type) {
            case  kS4KeyType_Signature:
                
                COPY(&ctx->sig.expirationTime, buffer, actualLength);
                break;
                
            default:
                RETERR(kS4Err_BadParams);
        }
    }
    else if(STRCMP2(propName, kS4KeyProp_KeyID))
    {
        switch (ctx->type) {
                
            case kS4KeyType_SymmetricEncrypted:
                COPY(&ctx->symKeyEncoded.keyID , buffer, actualLength);
                break;
                
            case kS4KeyType_PublicEncrypted:
                COPY(&ctx->publicKeyEncoded.keyID , buffer, actualLength);
                break;
                
            case kS4KeyType_PublicKey:
                COPY(&ctx->pub.keyID , buffer, actualLength);
                break;
                
            case kS4KeyType_Symmetric:
                // calculate a keyID for the sym key
                err =  sKEY_HASH(ctx->sym.symKey,  ctx->sym.keylen, ctx->type,
                                 ctx->sym.symAlgor,  buffer, actualLength );
                
                break;
                
            case kS4KeyType_Tweekable:
                // calculate a keyID for the TBC key
                err =  sKEY_HASH((uint8_t*)ctx->tbc.key,  ctx->tbc.keybits >> 3, ctx->type,
                                 ctx->tbc.tbcAlgor,  buffer, actualLength );
                break;
                
            default:
                RETERR(kS4Err_BadParams);
        }
    }
    else if(STRCMP2(propName, kS4KeyProp_Mac))
    {
        uint8_t     keyHash[kS4KeyPBKDF2_HashBytes] = {0};
        
        switch (ctx->type) {
            case kS4KeyType_Symmetric:
                err =  sKEY_HASH(ctx->sym.symKey, ctx->tbc.keybits >> 3, ctx->type,
                                 ctx->sym.symAlgor, keyHash, kS4KeyPublic_Encrypted_HashBytes );
                
                COPY(keyHash , buffer, kS4KeyPublic_Encrypted_HashBytes);
                break;
                
            case kS4KeyType_Tweekable:
                err =  sKEY_HASH((uint8_t*)ctx->tbc.key, ctx->sym.keylen >> 3, ctx->type,
                                 ctx->tbc.tbcAlgor, keyHash, kS4KeyPublic_Encrypted_HashBytes );
                
                COPY(keyHash , buffer, kS4KeyPublic_Encrypted_HashBytes);
                break;
                
            case kS4KeyType_Share:
                actualLength = kS4KeyPublic_Encrypted_HashBytes;
                
                err =  sKEY_HASH(ctx->share.shareSecret, (int)ctx->share.shareSecretLen, ctx->type,
                                 kCipher_Algorithm_SharedKey, keyHash, kS4KeyPublic_Encrypted_HashBytes );
                
                COPY(keyHash , buffer, kS4KeyPublic_Encrypted_HashBytes);
                break;
                
            case kS4KeyType_PublicEncrypted:
                COPY(ctx->publicKeyEncoded.keyHash , buffer, kS4KeyPublic_Encrypted_HashBytes);
                break;
                
            default:
                RETERR(kS4Err_BadParams);
        }
    }
    
    else if(STRCMP2(propName, kS4KeyProp_KeyIDString))
    {
        switch (ctx->type) {
                
            case kS4KeyType_SymmetricEncrypted:
                err = base64_encode(ctx->symKeyEncoded.keyID, sizeof(ctx->symKeyEncoded.keyID), buffer, &actualLength); CKERR;
                actualLength++;
                buffer[actualLength]= '\0';
                break;
                
                
            case kS4KeyType_PublicEncrypted:
                err = base64_encode(ctx->publicKeyEncoded.keyID, sizeof(ctx->publicKeyEncoded.keyID), buffer, &actualLength); CKERR;
                actualLength++;
                buffer[actualLength]= '\0';
                break;
                
            case kS4KeyType_PublicKey:
                err = base64_encode(ctx->pub.keyID, sizeof(ctx->pub.keyID), buffer, &actualLength); CKERR;
                actualLength++;
                buffer[actualLength]= '\0';
                break;
                
                
                
            case kS4KeyType_Symmetric:
            {
                uint8_t keyID[kS4Key_KeyIDBytes];
                
                err =  sKEY_HASH(ctx->sym.symKey,  ctx->sym.keylen, ctx->type,
                                 ctx->sym.symAlgor,  keyID, kS4Key_KeyIDBytes );
                
                err = base64_encode(keyID, kS4Key_KeyIDBytes , buffer, &actualLength); CKERR;
                actualLength++;
                buffer[actualLength]= '\0';
            }
                break;
                
            case kS4KeyType_Tweekable:
            {
                uint8_t keyID[kS4Key_KeyIDBytes];
                
                err =  sKEY_HASH((uint8_t*)ctx->tbc.key,  ctx->tbc.keybits >> 3, ctx->type,
                                 ctx->tbc.tbcAlgor,  keyID, kS4Key_KeyIDBytes );
                
                err = base64_encode(keyID, kS4Key_KeyIDBytes , buffer, &actualLength); CKERR;
                actualLength++;
                buffer[actualLength]= '\0';
            }
                break;
                
                
            default:
                RETERR(kS4Err_BadParams);
        }
    }
    else if(otherProp)
    {
        COPY(otherProp->value,  buffer, actualLength);
        propType = otherProp->type;
    }
    
    if(outExtendedProp)
        *outExtendedProp = extendedProp;
    
    if(outPropType)
        *outPropType = propType;
    
    if(datSize)
        *datSize = actualLength;
    
    
done:
    return err;
    
    
}

S4Err S4Key_GetExtendedProperty( S4KeyContextRef ctx,
                        const char *propName,
                        S4KeyPropertyExtendedType *outPropType)
{
    S4Err               err = kS4Err_NoErr;
    
    validateS4KeyContext(ctx);
    ValidateParam(outPropType);

    err =  s4Key_GetPropertyInternal(ctx, propName, NULL, outPropType, NULL, 0, 0, false, NULL);
    
    return err;

}



S4Err S4Key_GetProperty( S4KeyContextRef ctx,
                        const char *propName,
                        S4KeyPropertyType *outPropType, void *outData, size_t bufSize, size_t *datSize)
{
    S4Err               err = kS4Err_NoErr;
    
    validateS4KeyContext(ctx);
    ValidateParam(outData);
    
    if ( IsntNull( outData ) )
    {
        ZERO( outData, bufSize );
    }
    
    err =  s4Key_GetPropertyInternal(ctx, propName, outPropType, NULL, outData, bufSize, datSize, false, NULL);
    
    return err;
}



S4Err S4Key_GetAllocatedProperty( S4KeyContextRef ctx,
                                const char *propName,
                                S4KeyPropertyType *outPropType, void **outData, size_t *datSize)
{
    S4Err               err = kS4Err_NoErr;
    
    validateS4KeyContext(ctx);
    ValidateParam(outData);
    
    err =  s4Key_GetPropertyInternal(ctx, propName, outPropType, NULL, NULL, 0, datSize, true, (uint8_t**) outData);
    
    return err;
}



#ifdef __clang__
#pragma mark - Public Key wrapper.
#endif

S4Err S4Key_Clone_ECC_Context(S4KeyContextRef pubKeyCtx,  ECC_ContextRef *eccOut)
{
    S4Err           err = kS4Err_NoErr;
    ECC_ContextRef  ecc = kInvalidECC_ContextRef;
    uint8_t         keyData[256];
    size_t          keyDataLen = 0;
    
    validateS4KeyContext(pubKeyCtx);
    ValidateParam(pubKeyCtx->type == kS4KeyType_PublicKey);
    ValidateParam(pubKeyCtx->pub.cipherAlgor == kCipher_Algorithm_ECC384
                  ||pubKeyCtx->pub.cipherAlgor == kCipher_Algorithm_ECC414 )
    ValidateParam(eccOut);
    
    err = ECC_Init(&ecc);
    
    if(ECC_isPrivate(pubKeyCtx->pub.ecc))
    {
        err =  ECC_Export(pubKeyCtx->pub.ecc, true, keyData, sizeof(keyData), &keyDataLen);CKERR;
        err = ECC_Import(ecc, keyData, keyDataLen);CKERR;
    }
    else
    {
        err = ECC_Export_ANSI_X963(pubKeyCtx->pub.ecc, keyData, sizeof(keyData), &keyDataLen);CKERR;
        err = ECC_Import_ANSI_X963(ecc, keyData, keyDataLen);CKERR;
    }
    
    if(eccOut) *eccOut = ecc;
    
done:
    
    if(IsS4Err(err))
    {
        if(ECC_ContextRefIsValid(ecc))
        {
            ECC_Free(ecc);
        }
    }
    
    ZERO(keyData, sizeof(keyData));
    
    return err;
    
};



static S4Err sDecryptFromPubKey( S4KeyContextRef      encodedCtx,
                                ECC_ContextRef    eccPriv,
                                S4KeyContextRef       *symCtx)
{
    S4Err           err = kS4Err_NoErr;
    S4KeyContext*   keyCTX = NULL;
    
    int                 encyptAlgor = kCipher_Algorithm_Invalid;
    size_t              keyBytes = 0;
    
    uint8_t             decrypted_key[128] = {0};
    size_t              decryptedLen = 0;
    
    uint8_t             keyHash[kS4KeyPublic_Encrypted_HashBytes] = {0};
    
    validateS4KeyContext(encodedCtx);
    validateECCContext(eccPriv);
    ValidateParam(symCtx);
    
    ValidateParam(encodedCtx->type == kS4KeyType_PublicEncrypted);
    
    ValidateParam (ECC_isPrivate(eccPriv));
    
    if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Symmetric)
    {
        keyBytes = sGetKeyLength(kS4KeyType_Symmetric, encodedCtx->publicKeyEncoded.cipherAlgor);
        encyptAlgor = encodedCtx->publicKeyEncoded.cipherAlgor;
        
    }
    else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Tweekable)
    {
        keyBytes = sGetKeyLength(kS4KeyType_Tweekable, encodedCtx->publicKeyEncoded.cipherAlgor);
        encyptAlgor = encodedCtx->publicKeyEncoded.cipherAlgor;
    }
    else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Share)
    {
        encyptAlgor = kCipher_Algorithm_SharedKey;
    }
    
    
    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(S4KeyContext));
    
    keyCTX->magic = kS4KeyContextMagic;
    
    if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Symmetric)
    {
        keyCTX->type  = kS4KeyType_Symmetric;
        keyCTX->sym.symAlgor = encodedCtx->publicKeyEncoded.cipherAlgor;
        keyCTX->sym.keylen = keyBytes;
        
        err = ECC_Decrypt(eccPriv,
                          encodedCtx->publicKeyEncoded.encrypted, encodedCtx->publicKeyEncoded.encryptedLen,
                          decrypted_key, sizeof(decrypted_key), &decryptedLen  );CKERR;
        
        ASSERTERR(decryptedLen == keyBytes, kS4Err_CorruptData );
        
        COPY(decrypted_key, keyCTX->sym.symKey, decryptedLen);
        
    }
    else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Tweekable)
    {
        keyCTX->type  = kS4KeyType_Tweekable;
        keyCTX->tbc.tbcAlgor = encodedCtx->publicKeyEncoded.cipherAlgor;
        keyCTX->tbc.keybits = keyBytes << 3;
        
        err = ECC_Decrypt(eccPriv,
                          encodedCtx->publicKeyEncoded.encrypted, encodedCtx->publicKeyEncoded.encryptedLen,
                          decrypted_key, sizeof(decrypted_key), &decryptedLen  );CKERR;
        
        ASSERTERR(decryptedLen == keyBytes , kS4Err_CorruptData );
        
        memcpy(keyCTX->tbc.key, decrypted_key, keyBytes);
        
        //       Skein_Get64_LSB_First(keyCTX->tbc.key, decrypted_key, keyBytes >>2);   /* bytes to words */
    }
    else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Share)
    {
        keyCTX->type  = kS4KeyType_Share;
        keyCTX->share.threshold = encodedCtx->publicKeyEncoded.threshold;
        keyCTX->share.xCoordinate = encodedCtx->publicKeyEncoded.xCoordinate;
        COPY(encodedCtx->publicKeyEncoded.shareHash, keyCTX->share.shareHash,  kS4ShareInfo_HashBytes);
        
        err = ECC_Decrypt(eccPriv,
                          encodedCtx->publicKeyEncoded.encrypted, encodedCtx->publicKeyEncoded.encryptedLen,
                          decrypted_key, sizeof(decrypted_key), &decryptedLen  );CKERR;
        
        // is the Share to big?
        ASSERTERR(decryptedLen <= 64 , kS4Err_CorruptData );
        
        // we dont have a way to determine the expected length of a split key.
        keyBytes =  decryptedLen;
        keyCTX->share.shareSecretLen = decryptedLen;
        COPY(decrypted_key, keyCTX->share.shareSecret, decryptedLen);
    }
    
    // check integrity of decypted value against the MAC
    err = sKEY_HASH(decrypted_key, keyBytes, keyCTX->type,  encyptAlgor,
                    keyHash, kS4KeyPublic_Encrypted_HashBytes ); CKERR;
    
    ASSERTERR( CMP(keyHash, encodedCtx->publicKeyEncoded.keyHash, kS4KeyPublic_Encrypted_HashBytes),
              kS4Err_BadIntegrity)
    
    
    
    *symCtx = keyCTX;
    
    
    
done:
    
    if(IsS4Err(err))
    {
        if(IsntNull(keyCTX))
        {
            XFREE(keyCTX);
        }
    }
    
    ZERO(decrypted_key, sizeof(decrypted_key));
    
    return err;
    
}


static S4Err sSerializeToPubKey(S4KeyContextRef   ctx,
                                ECC_ContextRef    eccPub,
                                uint8_t          **outData,
                                size_t           *outSize)
{
    S4Err           err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    uint8_t             *yajlBuf = NULL;
    size_t              yajlLen = 0;
    yajl_gen            g = NULL;
    
    uint8_t             tempBuf[1024];
    size_t              tempLen;
    uint8_t             *outBuf = NULL;
    
    char                curveName[32]  = {0};
    
    uint8_t             keyID[kS4Key_KeyIDBytes];
    size_t              keyIDLen = 0;
    
    uint8_t             keyHash[kS4KeyPublic_Encrypted_HashBytes];
    int                 keyAlgorithm = 0;
    
    uint8_t            encrypted[256] = {0};       // typical 199 bytes
    size_t              encryptedLen = 0;
    
    size_t              keyBytes = 0;
    void*               keyToEncrypt = NULL;
    
    char*              keySuiteString = "Invalid";
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };
    
    
    validateS4KeyContext(ctx);
    validateECCContext(eccPub);
    ValidateParam(outData);
    
    switch (ctx->type)
    {
        case kS4KeyType_Symmetric:
            keyBytes = ctx->sym.keylen ;
            keyToEncrypt = ctx->sym.symKey;
            keyAlgorithm = ctx->sym.symAlgor;
            keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
            break;
            
        case kS4KeyType_Tweekable:
            keyBytes = ctx->tbc.keybits >> 3 ;
            keyToEncrypt = ctx->tbc.key;
            keyAlgorithm = ctx->tbc.tbcAlgor;
            keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
            break;
            
        case kS4KeyType_Share:
            keyBytes = (int)ctx->share.shareSecretLen ;
            keyToEncrypt = ctx->share.shareSecret;
            keyAlgorithm = kCipher_Algorithm_SharedKey;
            keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
            break;
            
        default:
            break;
    }
    
    /* limit ECC encryption to <= 512 bits of data */
    //    ValidateParam(keyBytes <= (512 >>3));
    
    err = sKEY_HASH(keyToEncrypt, keyBytes, ctx->type,
                    keyAlgorithm, keyHash, kS4KeyPublic_Encrypted_HashBytes ); CKERR;
    
    err = ECC_CurveName(eccPub, curveName, sizeof(curveName), NULL); CKERR;
    err = ECC_PubKeyHash(eccPub, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
    
    err = ECC_Encrypt(eccPub, keyToEncrypt, keyBytes,  encrypted, sizeof(encrypted), &encryptedLen);CKERR;
    
    g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
    
#if DEBUG
    yajl_gen_config(g, yajl_gen_beautify, 1);
#else
    yajl_gen_config(g, yajl_gen_beautify, 0);
    
#endif
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    stat = yajl_gen_map_open(g);
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)curveName, strlen(curveName)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeyID, strlen(kS4KeyProp_KeyID)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(keyID, keyIDLen, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(keyHash, kS4KeyPublic_Encrypted_HashBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    
    switch (ctx->type)
    {
        case kS4KeyType_Symmetric:
        case kS4KeyType_Tweekable:
            break;
            
        case kS4KeyType_Share:
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIndex, strlen(kS4KeyProp_ShareIndex)) ; CKYJAL;
            sprintf((char *)tempBuf, "%d", ctx->share.xCoordinate);
            stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
            sprintf((char *)tempBuf, "%d", ctx->share.threshold);
            stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareHash, strlen(kS4KeyProp_ShareHash)) ; CKYJAL;
            tempLen = sizeof(tempBuf);
            base64_encode(ctx->share.shareHash, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
            stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
            break;
            
        default:
            break;
    }
    
    
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(encrypted, encryptedLen, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    err = sGenPropStrings(ctx, g); CKERR;
    err = sGenSignablePropString(ctx, g); CKERR;
    err = sGenSignatureStrings(ctx, g); CKERR;
    
    stat = yajl_gen_map_close(g); CKYJAL;
    stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
    
    outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
    memcpy(outBuf, yajlBuf, yajlLen);
    outBuf[yajlLen] = 0;
    
    *outData = outBuf;
    if(outSize)
        *outSize = yajlLen;
    
done:
    if(IsntNull(g))
        yajl_gen_free(g);
    
    return err;
    
}

#ifdef __clang__
#pragma mark - create Key.
#endif

S4Err S4Key_NewKey(Cipher_Algorithm       algorithm,
                   S4KeyContextRef    *ctxOut)
{
    S4Err   err = kS4Err_NoErr;
    S4KeyContext*    keyCTX  = NULL;
    
    int     keyBytes  = 0;
    uint8_t *keyData = NULL;
    
    ValidateParam(ctxOut);
    
    switch(algorithm)
    {
        case kCipher_Algorithm_AES128:
            keyBytes = 128 >> 3;
            break;
            
        case kCipher_Algorithm_AES192:
            keyBytes = 192 >> 3;
            break;
            
        case kCipher_Algorithm_AES256:
            keyBytes = 256 >> 3;
            break;
            
        case kCipher_Algorithm_2FISH256:
            keyBytes = 256 >> 3;
            break;
            
        case kCipher_Algorithm_3FISH256:
            keyBytes =  256 >> 3;
            break;
            
        case kCipher_Algorithm_3FISH512:
            keyBytes = 512 >> 3;
            break;
            
        case kCipher_Algorithm_3FISH1024:
            keyBytes = 1024 >> 3;
            break;
            
        default: ;
    }
    
    if(keyBytes)
    {
        keyData = (uint8_t*)XMALLOC(keyBytes);
        err = RNG_GetBytes(keyData, keyBytes);
    }
    
    switch(algorithm)
    {
        case kCipher_Algorithm_AES128:
        case kCipher_Algorithm_AES192:
        case kCipher_Algorithm_AES256:
        case kCipher_Algorithm_2FISH256:
            
            err = S4Key_NewSymmetric(algorithm, keyData, &keyCTX);
            break;
            
        case kCipher_Algorithm_3FISH256:
        case kCipher_Algorithm_3FISH512:
        case kCipher_Algorithm_3FISH1024:
            
            err = S4Key_NewTBC(algorithm, keyData, &keyCTX);
            break;
            
        case kCipher_Algorithm_ECC384:
        case kCipher_Algorithm_ECC414:
            err= S4Key_NewPublicKey(algorithm, &keyCTX);
            break;
            
        default:
            RETERR(kS4Err_BadCipherNumber);
    }
    
    
    *ctxOut = keyCTX;
    
done:
    
    if(keyData && keyBytes)
    {
        ZERO(keyData, keyBytes);
        XFREE(keyData);
    }
    
    if(IsS4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (S4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    
    return err;
}

S4Err S4Key_NewSymmetric(Cipher_Algorithm       algorithm,
                         const void             *key,
                         S4KeyContextRef    *ctxOut)
{
    S4Err               err = kS4Err_NoErr;
    S4KeyContext*    keyCTX  = NULL;
    
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
            RETERR(kS4Err_BadCipherNumber);
    }
    
    
    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(S4KeyContext));

    keyCTX->magic = kS4KeyContextMagic;
    keyCTX->type  = kS4KeyType_Symmetric;
    keyCTX->propList = NULL;
    keyCTX->sigList = NULL;
    
    keyCTX->sym.symAlgor = algorithm;
    keyCTX->sym.keylen = keylen;
    
    // leave null bytes at end of key, for odd size keys (like 192)
    ZERO(keyCTX->sym.symKey, sizeof(keyCTX->sym.symKey) );
    COPY(key, keyCTX->sym.symKey, keylen);
    
    *ctxOut = keyCTX;
    
done:
    if(IsS4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (S4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    return err;
}


S4Err S4Key_NewTBC(     Cipher_Algorithm       algorithm,
                   const void     *key,
                   S4KeyContextRef   *ctxOut)
{
    S4Err               err = kS4Err_NoErr;
    S4KeyContext*    keyCTX  = NULL;
    
    ValidateParam(ctxOut);
    
    int             keybits  = 0;
    
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
    
    
    
    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(S4KeyContext));

    keyCTX->magic = kS4KeyContextMagic;
    keyCTX->type  = kS4KeyType_Tweekable;
    keyCTX->propList = NULL;
    keyCTX->sigList = NULL;
    
    keyCTX->tbc.tbcAlgor = algorithm;
    keyCTX->tbc.keybits = keybits;
    
    memcpy(keyCTX->tbc.key, key, keybits >> 3);
    
    //   Skein_Get64_LSB_First(keyCTX->tbc.key, key, keybits >>5);   /* bits to words */
    
    *ctxOut = keyCTX;
    
done:
    if(IsS4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (S4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    return err;
}


S4Err S4Key_NewShare(SHARES_ShareInfo   *share,
                     S4KeyContextRef    *ctxOut)
{
    S4Err               err = kS4Err_NoErr;
    S4KeyContext*    keyCTX  = NULL;
    
    ValidateParam(ctxOut);
    ValidateParam(share->shareSecretLen <= 64);
    
    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(S4KeyContext));

    keyCTX->magic = kS4KeyContextMagic;
    keyCTX->type  = kS4KeyType_Share;
    keyCTX->propList = NULL;
    keyCTX->sigList = NULL;

    keyCTX->share.xCoordinate = share->xCoordinate;
    keyCTX->share.threshold   = share->threshold;
    COPY(share->shareHash, keyCTX->share.shareHash, kS4ShareInfo_HashBytes);
    keyCTX->share.shareSecretLen    = share->shareSecretLen;
    COPY(share->shareSecret, keyCTX->share.shareSecret, share->shareSecretLen);
    
    *ctxOut = keyCTX;
    
done:
    if(IsS4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (S4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    return err;
    
}


static S4Err sCalculateECCData(S4KeyContextRef  ctx)
{
    S4Err               err = kS4Err_NoErr;
    size_t          len = 0;
    size_t          pubKeyLen = 0;
    
    if(ECC_isPrivate(ctx->pub.ecc))
    {
        ctx->pub.privKey = XMALLOC(kS4KeyPublic_MAX_PrivKeyLen);
        err =  ECC_Export( ctx->pub.ecc, true, ctx->pub.privKey, kS4KeyPublic_MAX_PrivKeyLen, &len);CKERR;
        ctx->pub.privKeyLen  = (uint8_t)(len & 0xff);
        ctx->pub.isPrivate = 1;
    }
    else
    {
        ctx->pub.isPrivate = 0;
        ctx->pub.privKeyLen = 0;
        ctx->pub.privKey = NULL;
    }
    
    err =  ECC_Export_ANSI_X963( ctx->pub.ecc, ctx->pub.pubKey, sizeof(ctx->pub.pubKey), &pubKeyLen);CKERR;
    ctx->pub.pubKeyLen = pubKeyLen;
    
    err = ECC_PubKeyHash(ctx->pub.ecc, ctx->pub.keyID, kS4Key_KeyIDBytes, NULL);CKERR;
    
done:
    return err;
    
}


S4Err S4Key_Import_ECC_Context(ECC_ContextRef ecc, S4KeyContextRef*ctxOut)
{
    S4Err err = kS4Err_NoErr;
    
    ValidateParam(ECC_ContextRefIsValid(ecc));
    ValidateParam(ctxOut);
    
    S4KeyContext*       keyCTX  = NULL;
    Cipher_Algorithm    algorithm = kCipher_Algorithm_Invalid;
    
    err = ECC_CipherAlgorithm(ecc, &algorithm); CKERR;
    
    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(S4KeyContext));

    keyCTX->magic = kS4KeyContextMagic;
    keyCTX->type  = kS4KeyType_PublicKey;
    keyCTX->propList = NULL;
    keyCTX->sigList = NULL;

    keyCTX->pub.ecc = ecc;
    keyCTX->pub.cipherAlgor = algorithm;
    err = sCalculateECCData(keyCTX); CKERR;
    
    *ctxOut = keyCTX;
    
done:
    if(IsS4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (S4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    return err;
    
}

S4Err S4Key_NewPublicKey(Cipher_Algorithm       algorithm,
                         S4KeyContextRef    *ctxOut)
{
    S4Err               err = kS4Err_NoErr;
    S4KeyContext*       keyCTX  = NULL;
    ECC_ContextRef      ecc = kInvalidECC_ContextRef;
    
    ValidateParam(ctxOut);
    int             keybits  = 0;
    
    switch(algorithm)
    {
        case kCipher_Algorithm_ECC384:
            keybits = 384;
            break;
            
        case kCipher_Algorithm_ECC414:
            keybits = 414;
            break;
            
        default:
            RETERR(kS4Err_BadCipherNumber);
    }
    
    err = ECC_Init(&ecc);
    err = ECC_Generate(ecc, keybits); CKERR;
    err = S4Key_Import_ECC_Context(ecc, &keyCTX); CKERR;
    
    *ctxOut = keyCTX;
    
done:
    if(IsS4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (S4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    return err;
    
}



void S4Key_Free(S4KeyContextRef ctx)
{
    if(sS4KeyContextIsValid(ctx))
    {
        
        S4KeyProperty *prop = ctx->propList;
        
        while(prop)
        {
            S4KeyProperty *nextProp = prop->next;
            XFREE(prop->prop);
            XFREE(prop->value);
            XFREE(prop);
            prop = nextProp;
        }
   
        S4KeySigItem *sig = ctx->sigList;
        
        while(sig)
        {
            S4KeySigItem *nextSig = sig->next;
            
            if(sig->sig.propNameList)
            {
                char**   itemName = sig->sig.propNameList;
                for(;*itemName; itemName++)  XFREE(*itemName);
                XFREE(sig->sig.propNameList);
            }
            
            if (sig->sig.signature)
                XFREE(sig->sig.signature);
            XFREE(sig);
            sig = nextSig;
        }

        
        switch (ctx->type) {
            case kS4KeyType_PublicKey:
                
                if(ECC_ContextRefIsValid(ctx->pub.ecc))
                    ECC_Free(ctx->pub.ecc);
                
                if(ctx->pub.privKey && ctx->pub.privKeyLen)
                {
                    ZERO(ctx->pub.privKey ,ctx->pub.privKeyLen);
                    XFREE(ctx->pub.privKey);
                    ctx->pub.privKey = NULL;
                }
                
                break;
           
            case kS4KeyType_Signature:
            {
                if(ctx->sig.signature)
                    XFREE(ctx->sig.signature);
                
                if(ctx->sig.propNameList)
                {
                    char**   itemName = ctx->sig.propNameList;
                    for(;*itemName; itemName++)  XFREE(*itemName);
                    XFREE(ctx->sig.propNameList);
                }
                
            }
                break;
                
            default:
                break;
        }
        
        
        
        ZERO(ctx, sizeof(S4KeyContext));
        XFREE(ctx);
    }
}


static S4Err sClonePubKey(S4KeyContext *src, S4KeyContext *dest )
{
    S4Err               err = kS4Err_NoErr;
    
    uint8_t         keyData[256];
    size_t          keyDataLen = 0;
    
    dest->magic = kS4KeyContextMagic;
    dest->type = kS4KeyType_PublicKey;
    dest->pub.cipherAlgor = src->pub.cipherAlgor;
    
    err = ECC_Init(&dest->pub.ecc);
    
    if(ECC_isPrivate(src->pub.ecc))
    {
        err =  ECC_Export(src->pub.ecc, true, keyData, sizeof(keyData), &keyDataLen);CKERR;
        err = ECC_Import(dest->pub.ecc, keyData, keyDataLen);CKERR;
    }
    else
    {
        err = ECC_Export_ANSI_X963(src->pub.ecc, keyData, sizeof(keyData), &keyDataLen);CKERR;
        err = ECC_Import_ANSI_X963(dest->pub.ecc, keyData, keyDataLen);CKERR;
    }
    
    err = sCalculateECCData(dest); CKERR;
    
done:
    
    ZERO(keyData, sizeof(keyData));
    return err;
}

static S4Err sCloneDetachedSig(S4KeyContext *src, S4KeyContext *dest )
{
    S4Err               err = kS4Err_NoErr;

    COPY(src->sig.issuerID, dest->sig.issuerID, kS4Key_KeyIDBytes );
    COPY(src->sig.sigID, dest->sig.sigID, kS4Key_KeyIDBytes );
    
    dest->sig.signDate = src->sig.signDate;
    dest->sig.expirationTime = src->sig.expirationTime;
    dest->sig.hashAlgorithm = src->sig.hashAlgorithm;
    
    dest->sig.signature = XMALLOC(src->sig.signatureLen);  CKNULL(dest->sig.signature);
    COPY(src->sig.signature, dest->sig.signature, src->sig.signatureLen );
    dest->sig.signatureLen = src->sig.signatureLen;
   
done:
    
     return err;

}

S4Err S4Key_Copy(S4KeyContextRef ctx, S4KeyContextRef *ctxOut)
{
    S4Err               err = kS4Err_NoErr;
    S4KeyContext*    keyCTX  = NULL;
    
    validateS4KeyContext(ctx);
    ValidateParam(ctxOut);
    
    
    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX,sizeof (S4KeyContext));
    
    keyCTX->magic = kS4KeyContextMagic;
    keyCTX->type = ctx->type;
    
    switch (ctx->type)
    {
        case kS4KeyType_Symmetric:
            keyCTX->sym = ctx->sym;
            break;
            
        case kS4KeyType_Tweekable:
            keyCTX->tbc = ctx->tbc;
            break;
            
            
        case kS4KeyType_PBKDF2:
            keyCTX->pbkdf2 = ctx->pbkdf2;
            break;
            
        case kS4KeyType_PublicEncrypted:
            keyCTX->publicKeyEncoded = ctx->publicKeyEncoded;
            break;
            
        case kS4KeyType_SymmetricEncrypted:
            keyCTX->symKeyEncoded = ctx->symKeyEncoded;
            break;
            
        case kS4KeyType_Share:
            keyCTX->share = ctx->share;
            break;
            
        case kS4KeyType_PublicKey:
            err = sClonePubKey(ctx, keyCTX); CKERR;
            break;
            
        case kS4KeyType_Signature:
            err = sCloneDetachedSig(ctx, keyCTX); CKERR;
            break;
            
        default:
            break;
    }
    
    sCloneProperties(ctx, keyCTX);
    sCloneSignatures(ctx, keyCTX);
    *ctxOut = keyCTX;
    
done:
    if(IsS4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (S4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    return err;
    
}


#ifdef __clang__
#pragma mark - export key.
#endif



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

S4Err S4Key_SerializeToPassPhrase(S4KeyContextRef  ctx,
                                  const uint8_t       *passphrase,
                                  size_t           passphraseLen,
                                  uint8_t          **outData,
                                  size_t           *outSize)
{
    S4Err           err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    uint8_t             *yajlBuf = NULL;
    size_t              yajlLen = 0;
    yajl_gen            g = NULL;
    
    uint8_t             tempBuf[1024];
    size_t              tempLen;
    uint8_t             *outBuf = NULL;
    
    uint32_t        rounds;
    uint8_t         keyHash[kS4KeyPBKDF2_HashBytes] = {0};
    uint8_t         salt[kS4KeyPBKDF2_SaltBytes] = {0};
    
    uint8_t         unlocking_key[32] = {0};
    
    Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
    uint8_t             encrypted_key[128] = {0};
    size_t              keyBytes = 0;
    void*               keyToEncrypt = NULL;
    
    char*           encodingPropString = NULL;
    char*           keySuiteString = "Invalid";
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };
    
    
    validateS4KeyContext(ctx);
    ValidateParam(passphrase);
    ValidateParam(outData);
    
    switch (ctx->type)
    {
        case kS4KeyType_Symmetric:
            keyBytes = ctx->sym.keylen ;
            keyToEncrypt = ctx->sym.symKey;
            
            switch (ctx->sym.symAlgor) {
                case kCipher_Algorithm_2FISH256:
                    encyptAlgor = kCipher_Algorithm_2FISH256;
                    encodingPropString =  kS4KeyProp_Encoding_PBKDF2_2FISH256;
                    break;
                    
                case kCipher_Algorithm_AES192:
                    encyptAlgor = kCipher_Algorithm_AES256;
                    encodingPropString =  kS4KeyProp_Encoding_PBKDF2_AES256;
                    
                    //  pad the end  (treat it like it was 256 bits)
                    ZERO(&ctx->sym.symKey[24], 8);
                    keyBytes = 32;
                    break;
                    
                default:
                    encyptAlgor = kCipher_Algorithm_AES256;
                    encodingPropString =  kS4KeyProp_Encoding_PBKDF2_AES256;
                    break;
            }
            
            keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
            break;
            
        case kS4KeyType_Tweekable:
            keyBytes = ctx->tbc.keybits >> 3 ;
            encyptAlgor = kCipher_Algorithm_2FISH256;
            keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
            encodingPropString =  kS4KeyProp_Encoding_PBKDF2_2FISH256;
            keyToEncrypt = ctx->tbc.key;
            
            break;
            
        case kS4KeyType_Share:
            keyBytes = (int)ctx->share.shareSecretLen ;
            encyptAlgor = kCipher_Algorithm_2FISH256;
            keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
            keyToEncrypt = ctx->share.shareSecret;
            encodingPropString =  kS4KeyProp_Encoding_PBKDF2_2FISH256;
            
            // we only encode block sizes of 16, 32, 48 and 64
            ASSERTERR((keyBytes % 16) == 0, kS4Err_FeatureNotAvailable);
            ASSERTERR(keyBytes <= 64, kS4Err_FeatureNotAvailable);
            
            break;
            
        default:
            break;
    }
    
    
    err = RNG_GetBytes( salt, kS4KeyPBKDF2_SaltBytes ); CKERR;
    
    err = PASS_TO_KEY_SETUP(passphraseLen, keyBytes,
                            salt, sizeof(salt),
                            &rounds); CKERR;
    
    err = PASS_TO_KEY(passphrase, passphraseLen,
                      salt, sizeof(salt), rounds,
                      unlocking_key, sizeof(unlocking_key)); CKERR;
    
    err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
                           salt, sizeof(salt),
                           rounds,
                           keyHash, kS4KeyPBKDF2_HashBytes); CKERR;
    
    err =  ECB_Encrypt(encyptAlgor, unlocking_key, keyToEncrypt, keyBytes, encrypted_key); CKERR;
    
    g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
    
#if DEBUG
    yajl_gen_config(g, yajl_gen_beautify, 1);
#else
    yajl_gen_config(g, yajl_gen_beautify, 0);
    
#endif
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    stat = yajl_gen_map_open(g);
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)encodingPropString, strlen(encodingPropString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Salt, strlen(kS4KeyProp_Salt)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(salt, kS4KeyPBKDF2_SaltBytes, tempBuf, &tempLen);
    
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Rounds, strlen(kS4KeyProp_Rounds)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", rounds);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(keyHash, kS4KeyPBKDF2_HashBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    switch (ctx->type)
    {
        case kS4KeyType_Symmetric:
        case kS4KeyType_Tweekable:
            break;
            
        case kS4KeyType_Share:
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIndex, strlen(kS4KeyProp_ShareIndex)) ; CKYJAL;
            sprintf((char *)tempBuf, "%d", ctx->share.xCoordinate);
            stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
            sprintf((char *)tempBuf, "%d", ctx->share.threshold);
            stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareHash, strlen(kS4KeyProp_ShareHash)) ; CKYJAL;
            tempLen = sizeof(tempBuf);
            base64_encode(ctx->share.shareHash, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
            stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
            break;
            
        default:
            break;
    }
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(encrypted_key, keyBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    err = sGenPropStrings(ctx, g); CKERR;
    err = sGenSignablePropString(ctx, g); CKERR;
    err = sGenSignatureStrings(ctx, g); CKERR;
    
    stat = yajl_gen_map_close(g); CKYJAL;
    stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
    
    
    outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
    memcpy(outBuf, yajlBuf, yajlLen);
    outBuf[yajlLen] = 0;
    
    *outData = outBuf;
    
    if(outSize)
        *outSize = yajlLen;
    
done:
    if(IsntNull(g))
        yajl_gen_free(g);
    
    return err;
    
}




S4Err S4Key_SerializeToS4Key(S4KeyContextRef  ctx,
                             S4KeyContextRef  passKeyCtx,
                             uint8_t          **outData,
                             size_t           *outSize)
{
    S4Err           err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    uint8_t             *yajlBuf = NULL;
    size_t              yajlLen = 0;
    yajl_gen            g = NULL;
    
    uint8_t             tempBuf[1024];
    size_t              tempLen;
    uint8_t             *outBuf = NULL;
    
    
    uint8_t             keyHash[kS4KeyPBKDF2_HashBytes] = {0};
    uint8_t             keyID[kS4Key_KeyIDBytes] = {0};
    
    size_t              keyBytes = 0;
    void*               keyToEncrypt = NULL;
    
    Cipher_Algorithm    keyAlgorithm = kCipher_Algorithm_Invalid;
    
    Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
    void*               unlockingKey    = NULL;
    
    char*           keySuiteString = "Invalid";
    char*           encodingPropString = NULL;
    
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };
    
    
    validateS4KeyContext(ctx);
    validateS4KeyContext(passKeyCtx);
    ValidateParam(outData);
    
    switch (passKeyCtx->type)
    {
        case kS4KeyType_Symmetric:
            unlockingKey = passKeyCtx->sym.symKey;
            encyptAlgor =  passKeyCtx->sym.symAlgor;
            ASSERTERR(passKeyCtx->sym.symAlgor != kCipher_Algorithm_AES192, kS4Err_FeatureNotAvailable);
            
            switch (passKeyCtx->sym.symAlgor) {
                    
                case kCipher_Algorithm_AES128:
                    encodingPropString =  kS4KeyProp_Encoding_SYM_AES128;
                    break;
                    
                case kCipher_Algorithm_AES256:
                    encodingPropString =  kS4KeyProp_Encoding_SYM_AES256;
                    break;
                    
                case kCipher_Algorithm_2FISH256:
                    encodingPropString =  kS4KeyProp_Encoding_SYM_2FISH256;
                    break;
                    
                default:
                    RETERR(kS4Err_FeatureNotAvailable);
                    
                    break;
            }
            
            break;
            
        case kS4KeyType_PublicKey:
            
            return sSerializeToPubKey(ctx, passKeyCtx->pub.ecc, outData, outSize);
            break;
            
        default:
            RETERR(kS4Err_FeatureNotAvailable);
            break;
    }
    
    switch (ctx->type)
    {
        case kS4KeyType_Symmetric:
            keyBytes = ctx->sym.keylen ;
            keyToEncrypt = ctx->sym.symKey;
            keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
            keyAlgorithm = ctx->sym.symAlgor;
            
            if (ctx->sym.symAlgor == kCipher_Algorithm_AES192)
            {
                //  pad the end  (treat it like it was 256 bits)
                ZERO(&ctx->sym.symKey[24], 8);
                keyBytes = 32;
                
            }
            break;
            
        case kS4KeyType_Tweekable:
            keyBytes = ctx->tbc.keybits >> 3 ;
            keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
            keyToEncrypt = ctx->tbc.key;
            keyAlgorithm = ctx->tbc.tbcAlgor;
            break;
            
        case kS4KeyType_Share:
            keyBytes = (int)ctx->share.shareSecretLen ;
            keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
            keyToEncrypt = ctx->share.shareSecret;
            keyAlgorithm = kCipher_Algorithm_SharedKey;
            
            // we only encode block sizes of 16, 32, 48 and 64
            ASSERTERR((keyBytes % 16) == 0, kS4Err_FeatureNotAvailable);
            ASSERTERR(keyBytes <= 64, kS4Err_FeatureNotAvailable);
            
            break;
            
        case kS4KeyType_PublicKey:
            ASSERTERR(ctx->pub.isPrivate, kS4Err_FeatureNotAvailable);
            keyBytes = (int)ctx->pub.privKeyLen ;
            keyToEncrypt = ctx->pub.privKey;
            keySuiteString = cipher_algor_table(ctx->pub.cipherAlgor);
            keyAlgorithm = ctx->pub.cipherAlgor;
            break;
            
        default:
            break;
    }
    
    err = sKEY_HASH(keyToEncrypt, keyBytes, ctx->type,
                    keyAlgorithm, keyHash, kS4KeyPublic_Encrypted_HashBytes ); CKERR;
    
    g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
    
#if DEBUG
    yajl_gen_config(g, yajl_gen_beautify, 1);
#else
    yajl_gen_config(g, yajl_gen_beautify, 0);
    
#endif
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    stat = yajl_gen_map_open(g);
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)encodingPropString, strlen(encodingPropString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(keyHash, kS4KeyPBKDF2_HashBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    // calculate the hash
    switch (ctx->type)
    {
        case kS4KeyType_Symmetric:
        case kS4KeyType_Tweekable:
            break;
            
        case kS4KeyType_Share:
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIndex, strlen(kS4KeyProp_ShareIndex)) ; CKYJAL;
            sprintf((char *)tempBuf, "%d", ctx->share.xCoordinate);
            stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
            sprintf((char *)tempBuf, "%d", ctx->share.threshold);
            stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareHash, strlen(kS4KeyProp_ShareHash)) ; CKYJAL;
            tempLen = sizeof(tempBuf);
            base64_encode(ctx->share.shareHash, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
            stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
            break;
            
        case kS4KeyType_PublicKey:
        {
            size_t              keyIDLen = 0;
            
            err = ECC_PubKeyHash(ctx->pub.ecc, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
            
            stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeyID, strlen(kS4KeyProp_KeyID)) ; CKYJAL;
            tempLen = sizeof(tempBuf);
            base64_encode(keyID, keyIDLen, tempBuf, &tempLen);
            stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
        }
            break;
            
        default:
            break;
    }
    
    
    // create the encyptd payload.
    if(ctx->type == kS4KeyType_PublicKey)
    {
        uint8_t *CT = NULL;
        size_t CTLen = 0;
        
        stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_PrivKey, strlen(kS4KeyProp_PrivKey)) ; CKYJAL;
        tempLen = sizeof(tempBuf);
        
        // the private key is CBC encrypted to the unlocking key, we pad and use the keyID as the IV.
        err =  CBC_EncryptPAD (encyptAlgor,unlockingKey, keyID, keyToEncrypt, keyBytes, &CT, &CTLen); CKERR;
        base64_encode(CT, CTLen, tempBuf, &tempLen);
        XFREE(CT);
    }
    else
    {
        stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
        tempLen = sizeof(tempBuf);
        
        uint8_t encrypted_key[128] = {0};
        err =  ECB_Encrypt(encyptAlgor, unlockingKey, keyToEncrypt, keyBytes, encrypted_key); CKERR;
        base64_encode(encrypted_key, keyBytes, tempBuf, &tempLen);
    }
    
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    err = sGenPropStrings(ctx, g); CKERR;
    err = sGenSignablePropString(ctx, g); CKERR;
    err = sGenSignatureStrings(ctx, g); CKERR;
    
    stat = yajl_gen_map_close(g); CKYJAL;
    stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
    
    
    outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
    memcpy(outBuf, yajlBuf, yajlLen);
    outBuf[yajlLen] = 0;
    
    *outData = outBuf;
    
    if(outSize)
        *outSize = yajlLen;
    
done:
    if(IsntNull(g))
        yajl_gen_free(g);
    
    return err;
    
}


S4Err S4Key_SerializePubKey(S4KeyContextRef  ctx,
                            uint8_t          **outData,
                            size_t           *outSize)
{
    S4Err           err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    uint8_t             *yajlBuf = NULL;
    size_t              yajlLen = 0;
    yajl_gen            g = NULL;
    
    uint8_t             tempBuf[1024];
    size_t              tempLen;
    uint8_t             *outBuf = NULL;
    
    uint8_t             keyID[kS4Key_KeyIDBytes];
    size_t              keyIDLen = 0;
    
    char*               keySuiteString = "Invalid";
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };
    
    
    validateS4KeyContext(ctx);
    ValidateParam(outData);
    
    
    switch (ctx->type)
    {
        case kS4KeyType_PublicKey:
            
            err = ECC_PubKeyHash(ctx->pub.ecc, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
            
            switch (ctx->pub.cipherAlgor)
        {
            case kCipher_Algorithm_ECC384:
                keySuiteString =  K_KEYSUITE_ECC384;
                break;
                
            case kCipher_Algorithm_ECC414:
                keySuiteString =  K_KEYSUITE_ECC414;
                
                break;
                
            default:
                RETERR(kS4Err_BadParams);
                
                break;
        }
            break;
            
        default:
            RETERR(kS4Err_BadParams);
            break;
            
    }
    
    g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
    
#if DEBUG
    yajl_gen_config(g, yajl_gen_beautify, 1);
#else
    yajl_gen_config(g, yajl_gen_beautify, 0);
    
#endif
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    stat = yajl_gen_map_open(g);
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeyID, strlen(kS4KeyProp_KeyID)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(keyID, keyIDLen, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_PubKey, strlen(kS4KeyProp_PubKey)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(ctx->pub.pubKey, ctx->pub.pubKeyLen, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    err = sGenPropStrings(ctx, g); CKERR;
    err = sGenSignablePropString(ctx, g); CKERR;
    err = sGenSignatureStrings(ctx, g); CKERR;
    
    stat = yajl_gen_map_close(g); CKYJAL;
    stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
    
    
    outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
    memcpy(outBuf, yajlBuf, yajlLen);
    outBuf[yajlLen] = 0;
    
    *outData = outBuf;
    
    if(outSize)
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


enum S4Key_JSON_Type_
{
    S4Key_JSON_Type_Invalid ,
    S4Key_JSON_Type_BASE ,
    S4Key_JSON_Type_VERSION,
    S4Key_JSON_Type_KEYALGORITHM,
    S4Key_JSON_Type_HASHALGORITHM,

    S4Key_JSON_Type_ROUNDS,
    S4Key_JSON_Type_SALT,
    S4Key_JSON_Type_ENCODING,
    S4Key_JSON_Type_MAC,
    S4Key_JSON_Type_ENCRYPTED_SYMKEY,
    S4Key_JSON_Type_KEYID,
    S4Key_JSON_Type_SYMKEY,
    
    S4Key_JSON_Type_SHAREHASH,
    S4Key_JSON_Type_THRESHOLD,
    S4Key_JSON_Type_SHAREINDEX,
    
    S4Key_JSON_Type_PUBKEY,
    S4Key_JSON_Type_PRIVKEY,
    
    S4Key_JSON_Type_PROPERTY,
    
    S4Key_JSON_Type_SIGNATURES,
    S4Key_JSON_Type_SIGNATURE,
    S4Key_JSON_Type_SIGNEDBY,
    S4Key_JSON_Type_SIGNDATE,
    S4Key_JSON_Type_SIGEXPIRETIME,
    S4Key_JSON_Type_SIGNED_PROPS,
    S4Key_JSON_Type_SIGNABLE_PROPS,
    S4Key_JSON_Type_SIGID,
    
    ENUM_FORCE( S4Key_JSON_Type_ )
};
ENUM_TYPEDEF( S4Key_JSON_Type_, S4Key_JSON_Type   );

struct S4KeyJSONcontext
{
    uint8_t             version;    // message version
    //    S4KeyContext       key;        // used for decoding messages
    
    S4KeyContext        *keys;     // pointer to array of S4KeyContext
    int                 index;      // current key
    
    int                 level;
    
    S4Key_JSON_Type jType[8];
    void*           jItem;
    size_t*         jItemSize;
    uint8_t*        jTag;
    
    S4KeySig        currentSigItem;             // temp space used for parsing signatures
    
    char**          currentSignablePropList; // used for importing current key

};

typedef struct S4KeyJSONcontext S4KeyJSONcontext;

static time_t parseRfc3339(const unsigned char *s, size_t stringLen)
{
    struct tm tm;
    time_t t;
    const unsigned char *p = s;
    
    if(stringLen < strlen("YYYY-MM-DDTHH:MM:SSZ"))
        return 0;
    
    memset(&tm, 0, sizeof tm);
    
    /* YYYY- */
    if (!isdigit(s[0]) || !isdigit(s[1]) ||  !isdigit(s[2]) || !isdigit(s[3]) || s[4] != '-')
        return 0;
    tm.tm_year = (((s[0] - '0') * 10 + s[1] - '0') * 10 +  s[2] - '0') * 10 + s[3] - '0' - 1900;
    s += 5;
    
    /* mm- */
    if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != '-')
        return 0;
    tm.tm_mon = (s[0] - '0') * 10 + s[1] - '0';
    if (tm.tm_mon < 1 || tm.tm_mon > 12)
        return 0;
    --tm.tm_mon;	/* 0-11 not 1-12 */
    s += 3;
    
    /* ddT */
    if (!isdigit(s[0]) || !isdigit(s[1]) || toupper(s[2]) != 'T')
        return 0;
    tm.tm_mday = (s[0] - '0') * 10 + s[1] - '0';
    s += 3;
    
    /* HH: */
    if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != ':')
        return 0;
    tm.tm_hour = (s[0] - '0') * 10 + s[1] - '0';
    s += 3;
    
    /* MM: */
    if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != ':')
        return 0;
    tm.tm_min = (s[0] - '0') * 10 + s[1] - '0';
    s += 3;
    
    /* SS */
    if (!isdigit(s[0]) || !isdigit(s[1]))
        return 0;
    tm.tm_sec = (s[0] - '0') * 10 + s[1] - '0';
    s += 2;
    
    if (*s == '.') {
        do
            ++s;
        while (isdigit(*s));
    }
    
   	if (toupper(s[0]) == 'Z' &&  ((s-p == stringLen -1) ||  s[1] == '\0'))
        tm.tm_gmtoff = 0;
    else if (s[0] == '+' || s[0] == '-')
    {
        char tzsign = *s++;
        
        /* HH: */
        if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != ':')
            return 0;
        tm.tm_gmtoff = ((s[0] - '0') * 10 + s[1] - '0') * 3600;
        s += 3;
        
        /* MM */
        if (!isdigit(s[0]) || !isdigit(s[1]) || s[2] != '\0')
            return 0;
        tm.tm_gmtoff += ((s[0] - '0') * 10 + s[1] - '0') * 60;
        
        if (tzsign == '-')
            tm.tm_gmtoff = -tm.tm_gmtoff;
    } else
        return 0;
    
    t = timegm(&tm);
    if (t < 0)
        return 0;
    return t;
    
    //  	return t - tm.tm_gmtoff;
    
}

 static S4Err sParseHashAlgorthmString(const unsigned char * stringVal,  size_t stringLen, HASH_Algorithm *algorithmOut)
{
    
    S4Err            err = kS4Err_NoErr;
    HASH_Algorithm    hashAlgor = kHASH_Algorithm_Invalid;
    
    if(CMP2(stringVal, stringLen, K_HASHALGORITHM_SHA256, strlen(K_HASHALGORITHM_SHA256)))
    {
         hashAlgor = kHASH_Algorithm_SHA256;
    }
    else if(CMP2(stringVal, stringLen, K_HASHALGORITHM_SHA512, strlen(K_HASHALGORITHM_SHA512)))
    {
        hashAlgor = kHASH_Algorithm_SHA512;
    }
    else if(CMP2(stringVal, stringLen, K_HASHALGORITHM_SKEIN256, strlen(K_HASHALGORITHM_SKEIN256)))
    {
        hashAlgor = kHASH_Algorithm_SKEIN256;
    }
    else if(CMP2(stringVal, stringLen, K_HASHALGORITHM_SKEIN512, strlen(K_HASHALGORITHM_SKEIN512)))
    {
        hashAlgor = kHASH_Algorithm_SKEIN512;
    }
   
    *algorithmOut = hashAlgor;
    
    return err;

}

static S4Err sParseKeySuiteString(const unsigned char * stringVal,  size_t stringLen,
                                  S4KeyType *keyTypeOut, int32_t *algorithmOut)
{
    
    S4Err               err = kS4Err_NoErr;
    S4KeyType   keyType = kS4KeyType_Invalid;
    int32_t     algorithm = kEnumMaxValue;
    
    
    if(CMP2(stringVal, stringLen, K_KEYSUITE_AES128, strlen(K_KEYSUITE_AES128)))
    {
        keyType  = kS4KeyType_Symmetric;
        algorithm = kCipher_Algorithm_AES128;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_AES192, strlen(K_KEYSUITE_AES192)))
    {
        keyType  = kS4KeyType_Symmetric;
        algorithm = kCipher_Algorithm_AES192;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_AES256, strlen(K_KEYSUITE_AES256)))
    {
        keyType  = kS4KeyType_Symmetric;
        algorithm = kCipher_Algorithm_AES256;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_2FISH256, strlen(K_KEYSUITE_2FISH256)))
    {
        keyType  = kS4KeyType_Symmetric;
        algorithm = kCipher_Algorithm_2FISH256;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH256, strlen(K_KEYSUITE_3FISH256)))
    {
        keyType  = kS4KeyType_Tweekable;
        algorithm = kCipher_Algorithm_3FISH256;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH512, strlen(K_KEYSUITE_3FISH512)))
    {
        keyType  = kS4KeyType_Tweekable;
        algorithm = kCipher_Algorithm_3FISH512;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_3FISH1024, strlen(K_KEYSUITE_3FISH1024)))
    {
        keyType  = kS4KeyType_Tweekable;
        algorithm = kCipher_Algorithm_3FISH1024;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_SPLIT, strlen(K_KEYSUITE_SPLIT)))
    {
        keyType  = kS4KeyType_Share;
        algorithm = kCipher_Algorithm_SharedKey;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_ECC384, strlen(K_KEYSUITE_ECC384)))
    {
        keyType  = kS4KeyType_PublicKey;
        algorithm = kCipher_Algorithm_ECC384;
    }
    else if(CMP2(stringVal, stringLen, K_KEYSUITE_ECC414, strlen(K_KEYSUITE_ECC414)))
    {
        keyType  = kS4KeyType_PublicKey;
        algorithm = kCipher_Algorithm_ECC414;
    }
    
    
    if(keyType == kS4KeyType_Invalid)
        err = kS4Err_CorruptData;
    
    *keyTypeOut = keyType;
    *algorithmOut = algorithm;
    
    return err;
}


static void sAppendSigProp(S4KeySig* sig,const char * str, size_t len)
{
    
    int offset = 0;
    
    if(!sig->propNameList)
    {
        sig->propNameList = XMALLOC(sizeof(char*) * 2);  // do we ever check for memory anymore?
    }
    else
    {
        for(offset = 0; sig->propNameList[offset] != NULL; offset++);
        sig->propNameList = XREALLOC(sig->propNameList, sizeof(char*) * (offset + 2));
    }
    
    char* name = XMALLOC(len +1);
    COPY(str, name, len);
    name[len] = 0;
    sig->propNameList[offset++] = name;
    sig->propNameList[offset] = NULL;
}


static int sParse_start_map(void * ctx)
{
    S4KeyJSONcontext *jctx = (S4KeyJSONcontext*) ctx;
    int retval = 0;
    
    jctx->level++;
    
    if(jctx->level ==  1)
    {
        jctx->currentSignablePropList = NULL;
        
    }

//     printf("sParse_start_map(%d) \n",jctx->level);
    
     if(!jctx->keys)
    {
        jctx->index = 0;
        
        jctx->keys = XMALLOC(sizeof (S4KeyContext));
        ZERO(jctx->keys, sizeof(sizeof (S4KeyContext)));
    }
    else
    {
        if(jctx->level > 1)
        {
            // SIGNATURES WILL HAVE A SUB MAP OF JSON, DONT CREATE ANOTHER ENTRY
            if(jctx->jType[jctx->level-1] == S4Key_JSON_Type_SIGNATURES)
            {
                return(1);
             }
        }

        jctx->index++;
        jctx->keys =  XREALLOC(jctx->keys, sizeof(S4KeyContext) * (jctx->index + 1));
    }
    
    S4KeyContext* keyP = &jctx->keys[jctx->index];
    ZERO(keyP, sizeof(S4KeyContext));
    keyP->magic = kS4KeyContextMagic;
    keyP->type = kS4KeyType_Invalid;
    
    if(IsntNull(jctx))
    {
        retval = 1;
        
    }
    
    return retval;
}

static int sParse_end_map(void * ctx)
{
    S4KeyJSONcontext *jctx = (S4KeyJSONcontext*) ctx;
    int retval = 0;
    
     if(IsntNull(jctx)  )
    {
//        printf("sParse_end_map(%d) \n",jctx->level);
     
        if(jctx->level == 1)
        {
            if(jctx->currentSignablePropList)
            {
                S4KeyContext* keyP = &jctx->keys[jctx->index];

                for(int i = 0; jctx->currentSignablePropList[i]; i++)
                {
                    char* propName = jctx->currentSignablePropList[i];
                    S4KeyProperty* prop = sFindProperty(keyP,propName);
                    if(prop)
                    {
                        prop->extended |=  S4KeyPropertyExtended_Signable;
                    }
                    XFREE(propName);
                }
                XFREE(jctx->currentSignablePropList);
                
                jctx->currentSignablePropList = NULL;
            }
         }
        else if(jctx->level > 1)
        {
             S4KeyContext* keyP = &jctx->keys[jctx->index];
            
            if(jctx->jType[jctx->level-1] == S4Key_JSON_Type_SIGNATURES)
            {
                S4KeySig* item = &jctx->currentSigItem;
                S4KeySigItem* sigItem = XMALLOC(sizeof(S4KeySigItem));
                 if(sigItem)
                {
                    COPY(item, &sigItem->sig, sizeof(S4KeySig));
                    
                    sigItem->next = keyP->sigList;
                    keyP->sigList = sigItem;
                    ZERO(item, sizeof(S4KeySig));
                 }
            }
        }
 
        retval = 1;
        
        jctx->level--;
        
    }
    return retval;
}

static int sParse_start_array(void * ctx)
{
    S4KeyJSONcontext *jctx = (S4KeyJSONcontext*) ctx;
    int retval = 0;
    
//        printf("sParse_start_array\n");
    
    if(IsntNull(jctx))
    {
        retval = 1;
        
    }
    
    return retval;
}

static int sParse_end_array(void * ctx)
{
    S4KeyJSONcontext *jctx = (S4KeyJSONcontext*) ctx;
    int retval = 0;
    
//         printf("sParse_end_array\n");
   
    
    if(IsntNull(jctx))
    {
        retval = 1;
    }
    
    return retval;
}


static int sParse_number(void * ctx, const char * str, size_t len)
{
    S4KeyJSONcontext *jctx = (S4KeyJSONcontext*) ctx;
    char buf[32] = {0};
    int valid = 0;
    
    //     printf("sParse_number\n");
    
    S4KeyContext* keyP = &jctx->keys[jctx->index];
    
    bool insideSignatures = (jctx->level > 1) && (jctx->jType[jctx->level-1] == S4Key_JSON_Type_SIGNATURES);

    if(len < sizeof(buf))
    {
        COPY(str,buf,len);
        if(jctx->jType[jctx->level] == S4Key_JSON_Type_VERSION)
        {
            uint8_t val = atoi(buf);
            if(val == kS4KeyProtocolVersion)
            {
                jctx->version = val;
                valid = 1;
                
            }
        }
        else if(jctx->jType[jctx->level] == S4Key_JSON_Type_ROUNDS)
        {
            int val = atoi(buf);
            keyP->type = kS4KeyType_PBKDF2;
            keyP->pbkdf2.rounds = val;
            valid = 1;
        }
        else if(jctx->jType[jctx->level] == S4Key_JSON_Type_THRESHOLD)
        {
            int val = atoi(buf);
            
            if(keyP->type == kS4KeyType_PublicEncrypted)
            {
                keyP->publicKeyEncoded.threshold = val;
                valid = 1;
            }
            else if(keyP->type == kS4KeyType_PBKDF2)
            {
                keyP->pbkdf2.threshold = val;
                valid = 1;
            }
            else  if(keyP->type == kS4KeyType_Share)
            {
                keyP->share.threshold = val;
                valid = 1;
            }
        }
        else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SHAREINDEX)
        {
            int val = atoi(buf);
            
            if(keyP->type == kS4KeyType_PublicEncrypted)
            {
                keyP->publicKeyEncoded.xCoordinate = val;
                valid = 1;
            }
            else if(keyP->type == kS4KeyType_PBKDF2)
            {
                keyP->pbkdf2.xCoordinate = val;
                valid = 1;
            }
            else  if(keyP->type == kS4KeyType_Share)
            {
                keyP->share.xCoordinate = val;
                valid = 1;
            }
        }
        else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SIGEXPIRETIME)
        {
            time_t val = atol(buf);
            
            if(insideSignatures)
            {
                S4KeySig* sig = &jctx->currentSigItem;
                sig->expirationTime = val;
                valid = 1;
            }
            else  if(keyP->type == kS4KeyType_Signature)
            {
                keyP->sig.expirationTime = val;
                valid = 1;
            }
        }
    }
    
    return valid;
}

static int sParse_string(void * ctx, const unsigned char * stringVal,
                         size_t stringLen)
{
    S4KeyJSONcontext *jctx = (S4KeyJSONcontext*) ctx;
    
    S4KeyContext* keyP = &jctx->keys[jctx->index];
    
    int valid = 0;
    //     printf("sParse_string\n");
    
    bool insideSignatures = (jctx->level > 1) && (jctx->jType[jctx->level-1] == S4Key_JSON_Type_SIGNATURES);
    
    if(jctx->jType[jctx->level] == S4Key_JSON_Type_PROPERTY)
    {
        S4KeyPropertyInfo  *propInfo = NULL;
        
        for(propInfo = sPropertyTable;  propInfo->name  && !valid; propInfo++)
        {
            if(CMP2(jctx->jTag, strlen((char *)(jctx->jTag)), propInfo->name, strlen(propInfo->name)))
            {
                switch (propInfo->type)
                {
                    case S4KeyPropertyType_UTF8String:
                        sInsertProperty(keyP, propInfo->name, S4KeyPropertyType_UTF8String,
                                        propInfo->signable?S4KeyPropertyExtended_Signable: S4KeyPropertyExtendedType_None,
                                        (void*)stringVal, stringLen);
                        valid = 1;
                        break;
                        
                    case S4KeyPropertyType_Time:
                    {
                        time_t t = parseRfc3339(stringVal, stringLen);
                        sInsertProperty(keyP, propInfo->name, S4KeyPropertyType_Time,
                                        propInfo->signable?S4KeyPropertyExtended_Signable: S4KeyPropertyExtendedType_None,
                                        &t, sizeof(time_t));
                        valid = 1;
                        break;
                    }
                        
                    case S4KeyPropertyType_Binary:
                    {
                        size_t dataLen = stringLen;
                        uint8_t     *buf = XMALLOC(dataLen);
                        
                        if(base64_decode(stringVal, stringLen, buf, &dataLen) == CRYPT_OK)
                        {
                            sInsertProperty(keyP, propInfo->name, S4KeyPropertyType_Binary,
                                            propInfo->signable?S4KeyPropertyExtended_Signable: S4KeyPropertyExtendedType_None,
                                            (void*)buf, dataLen);
                            valid = 1;
                        }
                        XFREE(buf);
                        break;
                    }
                        
                    default:
                        break;
                }
            }
        }
        
        // else just copy it
        if(!valid)
        {
            sInsertProperty(keyP, (char *)(jctx->jTag), S4KeyPropertyType_UTF8String,S4KeyPropertyExtendedType_None,
                            (void*)stringVal, stringLen);
            valid = 1;
        }
        
        if(jctx->jTag)
        {
            free(jctx->jTag);
            jctx->jTag = NULL;
        }
        
    }
    if(jctx->jType[jctx->level] == S4Key_JSON_Type_SIGNED_PROPS)
    {
        S4KeySig* sig = &jctx->currentSigItem;
        
        sAppendSigProp(sig,(char *)stringVal,  stringLen);
        valid = 1;
    }
    if(jctx->jType[jctx->level] == S4Key_JSON_Type_SIGNABLE_PROPS)
    {
        int offset = 0;
        
        if(!jctx->currentSignablePropList)
        {
            jctx->currentSignablePropList = XMALLOC(sizeof(char*) * 2);  // do we ever check for memory anymore?
        }
        else
        {
            for(offset = 0; jctx->currentSignablePropList[offset] != NULL; offset++);
            jctx->currentSignablePropList = XREALLOC(jctx->currentSignablePropList, sizeof(char*) * (offset + 2));
        }

        char* name = XMALLOC(stringLen +1);
        COPY(stringVal, name, stringLen);
        name[stringLen] = 0;
        
        jctx->currentSignablePropList[offset++] = name;
        jctx->currentSignablePropList[offset] = NULL;
 
        valid = 1;
    }
    
    
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SALT)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal, stringLen, buf, &dataLen) == CRYPT_OK)
           && (dataLen == kS4KeyPBKDF2_SaltBytes))
        {
            keyP->type = kS4KeyType_PBKDF2;
            
            COPY(buf, keyP->pbkdf2.salt, dataLen);
            valid = 1;
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_MAC)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if( base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
        {
            
            if(keyP->type == kS4KeyType_SymmetricEncrypted && (dataLen == kS4KeyPublic_Encrypted_HashBytes))
            {
                COPY(buf, keyP->symKeyEncoded.keyHash, dataLen);
                valid = 1;
            }
            else  if(keyP->type == kS4KeyType_PublicEncrypted && (dataLen == kS4KeyPublic_Encrypted_HashBytes))
            {
                COPY(buf, keyP->publicKeyEncoded.keyHash, dataLen);
                valid = 1;
            }
            else if(keyP->type == kS4KeyType_PublicKey && (dataLen == kS4KeyPublic_Encrypted_HashBytes))
            {
                COPY(buf, keyP->pub.keyHash, dataLen);
                valid = 1;
            }
            else if(keyP->type == kS4KeyType_PBKDF2 && (dataLen == kS4KeyPBKDF2_HashBytes))
            {
                COPY(buf, keyP->pbkdf2.keyHash, dataLen);
                valid = 1;
            }
            
            
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SHAREHASH)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if( (base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
           && (dataLen == kS4ShareInfo_HashBytes))
        {
            if(keyP->type == kS4KeyType_PublicEncrypted)
            {
                COPY(buf, keyP->publicKeyEncoded.shareHash, dataLen);
                valid = 1;
            }
            else if(keyP->type == kS4KeyType_PBKDF2)
            {
                COPY(buf, keyP->pbkdf2.shareHash, dataLen);
                valid = 1;
            }
            else  if(keyP->type == kS4KeyType_Share)
            {
                COPY(buf, keyP->share.shareHash, dataLen);
                valid = 1;
            }
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_PUBKEY)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if( (base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
           && (dataLen <= sizeof(buf)) )
        {
            COPY(buf, keyP->pub.pubKey, dataLen);
            keyP->pub.pubKeyLen = dataLen;
            keyP->pub.isPrivate = 0;
            valid = 1;
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_PRIVKEY)
    {
        uint8_t     buf[256];
        size_t dataLen = sizeof(buf);
        
        if( (base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
           && (dataLen <= sizeof(buf)) )
        {
            if(keyP->type == kS4KeyType_SymmetricEncrypted)
            {
                COPY(buf, keyP->symKeyEncoded.encrypted, dataLen);
                keyP->symKeyEncoded.encryptedLen = dataLen;
                valid = 1;
            }
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_KEYID)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
           && (dataLen  == kS4Key_KeyIDBytes))
        {
            if(keyP->type == kS4KeyType_PublicKey)
            {
                COPY(buf, keyP->pub.keyID, dataLen);
            }
            else if(keyP->type == kS4KeyType_SymmetricEncrypted)
            {
                COPY(buf, keyP->symKeyEncoded.keyID, dataLen);
            }
            else
            {
                keyP->type = kS4KeyType_PublicEncrypted;
                COPY(buf, keyP->publicKeyEncoded.keyID, dataLen);
            }
            valid = 1;
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SIGID)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
           && (dataLen  == kS4Key_KeyIDBytes))
        {
            if(insideSignatures)
            {
                S4KeySig* sig = &jctx->currentSigItem;
                COPY(buf, sig->sigID, dataLen);
                valid = 1;
            }
            else if(keyP->type == kS4KeyType_Signature)
            {
                COPY(buf, keyP->sig.sigID, dataLen);
                valid = 1;
            }
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_ENCRYPTED_SYMKEY)
    {
        uint8_t     buf[256];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK))
        {
            size_t keyLength = 0;
            
            if(keyP->type == kS4KeyType_PBKDF2)
            {
                if(keyP->pbkdf2.keyAlgorithmType == kS4KeyType_Symmetric)
                {
                    keyLength = sGetKeyLength(kS4KeyType_Symmetric, keyP->pbkdf2.cipherAlgor);
                    
                    keyLength = keyLength == 24?32:keyLength;
                    
                }
                else  if(keyP->pbkdf2.keyAlgorithmType == kS4KeyType_Tweekable)
                {
                    keyLength = sGetKeyLength(kS4KeyType_Tweekable, keyP->pbkdf2.cipherAlgor);
                    
                }
                else  if(keyP->pbkdf2.keyAlgorithmType == kS4KeyType_Share)
                {
                    keyLength = dataLen;
                }
                
                if(keyLength > 0 && keyLength == dataLen)
                {
                    COPY(buf, keyP->pbkdf2.encrypted, dataLen);
                    keyP->pbkdf2.encryptedLen = dataLen;
                    valid = 1;
                    
                }
            }
            else  if(keyP->type == kS4KeyType_PublicEncrypted)
            {
                
                if(dataLen <= kS4KeyPublic_Encrypted_BufferMAX)
                {
                    COPY(buf, keyP->publicKeyEncoded.encrypted, dataLen);
                    keyP->publicKeyEncoded.encryptedLen = dataLen;
                    valid = 1;
                }
                
            }
            else  if(keyP->type == kS4KeyType_SymmetricEncrypted)
            {
                
                if(dataLen <= kS4KeySymmetric_Encrypted_BufferMAX)
                {
                    COPY(buf, keyP->symKeyEncoded.encrypted, dataLen);
                    keyP->symKeyEncoded.encryptedLen = dataLen;
                    valid = 1;
                }
                
            }
            
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_ENCODING)
    {
        
        if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_PBKDF2_2FISH256, strlen(kS4KeyProp_Encoding_PBKDF2_2FISH256)))
        {
            keyP->type = kS4KeyType_PBKDF2;
            keyP->pbkdf2.encyptAlgor = kCipher_Algorithm_2FISH256;
            valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_PBKDF2_AES256, strlen(kS4KeyProp_Encoding_PBKDF2_AES256)))
        {
            keyP->type = kS4KeyType_PBKDF2;
            keyP->pbkdf2.encyptAlgor = kCipher_Algorithm_AES256;
            valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_PUBKEY_ECC384, strlen(kS4KeyProp_Encoding_PUBKEY_ECC384)))
        {
            keyP->type = kS4KeyType_PublicEncrypted;
            keyP->publicKeyEncoded.keysize = 384;
            valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_PUBKEY_ECC414, strlen(kS4KeyProp_Encoding_PUBKEY_ECC414)))
        {
            keyP->type = kS4KeyType_PublicEncrypted;
            keyP->publicKeyEncoded.keysize = 414;
            valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_SYM_2FISH256, strlen(kS4KeyProp_Encoding_SYM_2FISH256)))
        {
            keyP->type = kS4KeyType_SymmetricEncrypted;
            keyP->symKeyEncoded.encryptingAlgor = kCipher_Algorithm_2FISH256;
            valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_SYM_AES128, strlen(kS4KeyProp_Encoding_SYM_AES128)))
        {
            keyP->type = kS4KeyType_SymmetricEncrypted;
            keyP->symKeyEncoded.encryptingAlgor = kCipher_Algorithm_AES128;
            valid = 1;
        }
        else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_SYM_AES256, strlen(kS4KeyProp_Encoding_SYM_AES256)))
        {
            keyP->type = kS4KeyType_SymmetricEncrypted;
            keyP->symKeyEncoded.encryptingAlgor = kCipher_Algorithm_AES256;
            valid = 1;
        }
        
        else if(CMP2(stringVal, stringLen, kS4KeyProp_Encoding_Signature, strlen(kS4KeyProp_Encoding_Signature)))
        {
            keyP->type = kS4KeyType_Signature;
            valid = 1;
        }

    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_HASHALGORITHM)
    {
        HASH_Algorithm    hashAlgor = kHASH_Algorithm_Invalid;
        
        if(IsntS4Err( sParseHashAlgorthmString(stringVal,  stringLen, &hashAlgor)))
        {
            if(insideSignatures)
            {
                S4KeySig* sig = &jctx->currentSigItem;
                sig->hashAlgorithm = hashAlgor;
                valid = 1;
            }
            else  if(keyP->type == kS4KeyType_Signature)
            {
                keyP->sig.hashAlgorithm = hashAlgor;
                valid = 1;
            }
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_KEYALGORITHM)
    {
        S4KeyType   keyType = kS4KeyType_Invalid;
        int32_t     algorithm = kEnumMaxValue;
        
        if(IsntS4Err( sParseKeySuiteString(stringVal,  stringLen, &keyType, &algorithm)))
        {
            if( keyP->type == kS4KeyType_PBKDF2)
            {
                keyP->pbkdf2.keyAlgorithmType = keyType;
                
                if(keyType == kS4KeyType_Symmetric)
                {
                    keyP->pbkdf2.cipherAlgor = algorithm;
                    valid = 1;
                    
                }
                else  if(keyType == kS4KeyType_Tweekable)
                {
                    keyP->pbkdf2.cipherAlgor = algorithm;
                    valid = 1;
                }
                else if (keyType == kS4KeyType_Share)
                {
                    keyP->pbkdf2.cipherAlgor = algorithm;
                    valid = 1;
                }
                
            }
            else if( keyP->type == kS4KeyType_PublicEncrypted)
            {
                keyP->publicKeyEncoded.keyAlgorithmType = keyType;
                if(keyType == kS4KeyType_Symmetric)
                {
                    keyP->publicKeyEncoded.cipherAlgor = algorithm;
                    valid = 1;
                    
                }
                else  if(keyType == kS4KeyType_Tweekable)
                {
                    keyP->publicKeyEncoded.cipherAlgor = algorithm;
                    valid = 1;
                }
                else if (keyType == kS4KeyType_Share)
                {
                    keyP->publicKeyEncoded.cipherAlgor = algorithm;
                    valid = 1;
                }
            }
            else if( keyP->type == kS4KeyType_SymmetricEncrypted)
            {
                keyP->symKeyEncoded.keyAlgorithmType = keyType;
                if(keyType == kS4KeyType_Symmetric)
                {
                    keyP->symKeyEncoded.cipherAlgor = algorithm;
                    valid = 1;
                    
                }
                else  if(keyType == kS4KeyType_Tweekable)
                {
                    keyP->symKeyEncoded.cipherAlgor = algorithm;
                    valid = 1;
                }
                else  if(keyType == kS4KeyType_PublicKey)
                {
                    keyP->symKeyEncoded.cipherAlgor = algorithm;
                    valid = 1;
                }
            }
            else
            {
                keyP->type = keyType;
                
                if(keyType == kS4KeyType_Symmetric)
                {
                    keyP->sym.symAlgor = algorithm;
                    valid = 1;
                    
                }
                else  if(keyType == kS4KeyType_Tweekable)
                {
                    keyP->tbc.tbcAlgor = algorithm;
                    valid = 1;
                }
                else  if(keyType == kS4KeyType_PublicKey)
                {
                    keyP->pub.cipherAlgor = algorithm;
                    valid = 1;
                }
            }
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SIGNATURES)
    {
        // we never see S4Key_JSON_Type_SIGNATURES as a string
        valid = 0;
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SIGNATURE)
    {
        size_t dataLen = stringLen;
 
        uint8_t     *buf = XMALLOC(dataLen);
        
        if(base64_decode(stringVal, stringLen, buf, &dataLen) == CRYPT_OK)
        {
            if(insideSignatures)
            {
                S4KeySig* sig = &jctx->currentSigItem;
                
                sig->signatureLen = (size_t)dataLen;
                sig->signature = buf;
                valid = 1;
                
            }
            else if(keyP->type == kS4KeyType_Signature)
            {
                keyP->sig.signature = buf;
                keyP->sig.signatureLen = (size_t)dataLen;
                valid = 1;

            }
        }
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SIGNEDBY)
    {
        uint8_t     buf[128];
        size_t dataLen = sizeof(buf);
        
        if(( base64_decode(stringVal,  stringLen, buf, &dataLen)  == CRYPT_OK)
           && (dataLen  == kS4Key_KeyIDBytes))
        {
            if(insideSignatures)
            {
                S4KeySig* sig = &jctx->currentSigItem;
                COPY(buf, sig->issuerID, dataLen);
                valid = 1;
                
            }
            else if(keyP->type == kS4KeyType_Signature)
            {
                COPY(buf, keyP->sig.issuerID, dataLen);
                valid = 1;

            }
        }
        
    }
    else if(jctx->jType[jctx->level] == S4Key_JSON_Type_SIGNDATE)
    {
        time_t t = parseRfc3339(stringVal, stringLen);

       if(insideSignatures)
       {
            S4KeySig* sig = &jctx->currentSigItem;
            sig->signDate = t;
           valid = 1;
        }
        else  if(keyP->type == kS4KeyType_Signature)
        {
            keyP->sig.signDate = t;
            valid = 1;
        }
    }
   
    return valid;
    
}

static int sParse_map_key(void * ctx, const unsigned char * stringVal, size_t stringLen )
{    int valid = 0;
    
    S4KeyJSONcontext *jctx = (S4KeyJSONcontext*) ctx;
    
    //  printf("sParse_map_key[%d] \"%.*s\"\n",(int)jctx->level, (int)stringLen, stringVal);
    
    if(CMP2(stringVal, stringLen,kS4KeyProp_Version, strlen(kS4KeyProp_Version)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_VERSION;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_Rounds, strlen(kS4KeyProp_Rounds)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_ROUNDS;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_KEYALGORITHM;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_HashAlgorithm, strlen(kS4KeyProp_HashAlgorithm)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_HASHALGORITHM;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_ENCODING;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_Salt, strlen(kS4KeyProp_Salt)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SALT;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_MAC;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_ENCRYPTED_SYMKEY;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_KeyID, strlen(kS4KeyProp_KeyID)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_KEYID;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_SigID, strlen(kS4KeyProp_SigID)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SIGID;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_ShareHash, strlen(kS4KeyProp_ShareHash)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SHAREHASH;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_ShareIndex, strlen(kS4KeyProp_ShareIndex)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SHAREINDEX;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_THRESHOLD;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_PubKey, strlen(kS4KeyProp_PubKey)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_PUBKEY;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_PrivKey, strlen(kS4KeyProp_PrivKey)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_PRIVKEY;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_Signatures, strlen(kS4KeyProp_Signatures)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SIGNATURES;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_SignableProperties, strlen(kS4KeyProp_SignableProperties)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SIGNABLE_PROPS;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_SignedDate, strlen(kS4KeyProp_SignedDate)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SIGNDATE;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_SigExpire, strlen(kS4KeyProp_SigExpire)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SIGEXPIRETIME;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_SignedBy, strlen(kS4KeyProp_SignedBy)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SIGNEDBY;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_Signature, strlen(kS4KeyProp_Signature)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SIGNATURE;
        valid = 1;
    }
    else  if(CMP2(stringVal, stringLen,kS4KeyProp_SignedProperties, strlen(kS4KeyProp_SignedProperties)))
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_SIGNED_PROPS;
        valid = 1;
    }
    else
    {
        jctx->jType[jctx->level] = S4Key_JSON_Type_PROPERTY;
        if(jctx->jTag) free(jctx->jTag);
        jctx->jTag = (uint8_t *)strndup((char *)stringVal, stringLen);
        valid = 1;
        
    }
    
    
    return valid;
    
}


S4Err S4Key_DeserializeKeys( uint8_t *inData, size_t inLen,
                            size_t           *outCount,
                            S4KeyContextRef  *ctxArray[])
{
    S4Err               err = kS4Err_NoErr;
    yajl_status             stat = yajl_status_ok;
    yajl_handle             pHand = NULL;
    
    S4KeyJSONcontext       *jctx = NULL;
    size_t                  keyCount = 0;
    
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
    
    //    ValidateParam(ctxArray);
    ValidateParam(inData);
    
    jctx = XMALLOC(sizeof (S4KeyJSONcontext)); CKNULL(jctx);
    ZERO(jctx, sizeof(S4KeyJSONcontext));
    jctx->level = 0;
    jctx->index = -1;
    jctx->jType[jctx->level] = S4Key_JSON_Type_BASE;
    
    pHand = yajl_alloc(&callbacks, &allocFuncs, (void *) jctx);
    
    yajl_config(pHand, yajl_allow_comments, 1);
    stat = yajl_parse(pHand, inData,  inLen); CKYJAL;
    stat = yajl_complete_parse(pHand); CKYJAL;
    keyCount = jctx->index + 1;
    
    if(outCount)
    {
        *outCount = keyCount;
    }
    
    if(ctxArray)
    {
        if(!keyCount)
        {
            *ctxArray = NULL;
        }
        else
        {
            int index = 0;
            S4KeyContextRef  *keys = XMALLOC(sizeof(S4KeyContextRef) *  keyCount);
            ZERO(keys , sizeof(S4KeyContextRef) *  keyCount);
            
            for(index = 0; index < keyCount; index++)
            {
                S4KeyContext* keyP = &jctx->keys[index];
                
                keys[index] =  XMALLOC(sizeof (S4KeyContext)); CKNULL(keys[index]);
                COPY(keyP, keys[index], sizeof (S4KeyContext));
                
                S4KeyContext* copiedKey =  keys[index];
                
                if(copiedKey->type == kS4KeyType_PublicKey)
                {
                    uint8_t             keyID[kS4Key_KeyIDBytes];
                    size_t              keyIDLen = 0;
                    
                    err = ECC_Init(&copiedKey->pub.ecc); CKERR;
                    err = ECC_Import_ANSI_X963(copiedKey->pub.ecc, copiedKey->pub.pubKey, copiedKey->pub.pubKeyLen);CKERR;
                    
                    // verify keyID
                    err = ECC_PubKeyHash(copiedKey->pub.ecc, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
                    ASSERTERR(CMP(keyID, copiedKey->pub.keyID, kS4Key_KeyIDBytes), kS4Err_BadIntegrity)
                    
                    // verify signature here..
                    
                }
                
            }
            *ctxArray = keys;
        }
    }
    
    
done:
    if(jctx)
    {
        if(jctx->keys)
        {
            ZERO(jctx->keys, sizeof(S4KeyContext) *  jctx->index);
            XFREE(jctx->keys);
        }
        
        XFREE(jctx);
    }
    
    
    if(IsntNull(pHand))
        yajl_free(pHand);
    
    return err;
}

#ifdef __clang__
#pragma mark - verify passphrase.
#endif

S4Err S4Key_VerifyPassPhrase(   S4KeyContextRef  ctx,
                             const uint8_t    *passphrase,
                             size_t           passphraseLen)
{
    S4Err           err = kS4Err_NoErr;
    uint8_t         unlocking_key[32] = {0};
    size_t           keyBytes = 0;
    uint8_t         keyHash[kS4KeyPBKDF2_HashBytes] = {0};
    
    validateS4KeyContext(ctx);
    ValidateParam(passphrase);
    
    ValidateParam(ctx->type == kS4KeyType_PBKDF2);
    
    if(ctx->pbkdf2.keyAlgorithmType == kS4KeyType_Symmetric)
    {
        keyBytes = sGetKeyLength(kS4KeyType_Symmetric, ctx->pbkdf2.cipherAlgor);
        
    }
    else  if(ctx->pbkdf2.keyAlgorithmType == kS4KeyType_Tweekable)
    {
        keyBytes = sGetKeyLength(kS4KeyType_Tweekable, ctx->pbkdf2.cipherAlgor);
    }
    
    err = PASS_TO_KEY(passphrase, passphraseLen,
                      ctx->pbkdf2.salt, sizeof(ctx->pbkdf2.salt), ctx->pbkdf2.rounds,
                      unlocking_key, sizeof(unlocking_key)); CKERR;
    
    
    err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
                           ctx->pbkdf2.salt, sizeof(ctx->pbkdf2.salt), ctx->pbkdf2.rounds,
                           keyHash, kS4KeyPBKDF2_HashBytes); CKERR;
    
    ASSERTERR(CMP(keyHash, ctx->pbkdf2.keyHash, kS4KeyPBKDF2_HashBytes), kS4Err_BadIntegrity)
    
    
done:
    
    ZERO(unlocking_key, sizeof(unlocking_key));
    
    return err;
    
}

S4Err S4Key_DecryptFromPassPhrase( S4KeyContextRef  passCtx,
                                  const uint8_t    *passphrase,
                                  size_t           passphraseLen,
                                  S4KeyContextRef       *symCtx)
{
    S4Err           err = kS4Err_NoErr;
    S4KeyContext*   keyCTX = NULL;
    
    Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
    uint8_t             unlocking_key[32] = {0};
    size_t             keyBytes = 0;
    uint8_t             decrypted_key[128] = {0};
    uint8_t             keyHash[kS4KeyPBKDF2_HashBytes] = {0};
    
    validateS4KeyContext(passCtx);
    ValidateParam(passphrase);
    
    ValidateParam(passCtx->type == kS4KeyType_PBKDF2);
    
    if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Symmetric)
    {
        keyBytes = sGetKeyLength(kS4KeyType_Symmetric, passCtx->pbkdf2.cipherAlgor);
        
        switch (passCtx->pbkdf2.cipherAlgor)
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
    else  if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Tweekable)
    {
        encyptAlgor = kCipher_Algorithm_2FISH256;
        
        keyBytes = sGetKeyLength(kS4KeyType_Tweekable, passCtx->pbkdf2.cipherAlgor);
    }
    else  if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Share)
    {
        encyptAlgor = kCipher_Algorithm_2FISH256;
        keyBytes = passCtx->pbkdf2.encryptedLen;
    }
    
    
    err = PASS_TO_KEY(passphrase, passphraseLen,
                      passCtx->pbkdf2.salt, sizeof(passCtx->pbkdf2.salt), passCtx->pbkdf2.rounds,
                      unlocking_key, sizeof(unlocking_key)); CKERR;
    
    err = sPASSPHRASE_HASH(unlocking_key, sizeof(unlocking_key),
                           passCtx->pbkdf2.salt, sizeof(passCtx->pbkdf2.salt), passCtx->pbkdf2.rounds,
                           keyHash, kS4KeyPBKDF2_HashBytes); CKERR;
    
    if(!CMP(keyHash, passCtx->pbkdf2.keyHash, kS4KeyPBKDF2_HashBytes))
        RETERR (kS4Err_BadIntegrity);
    
    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(S4KeyContext));
    
    keyCTX->magic = kS4KeyContextMagic;
    
    if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Symmetric)
    {
        size_t bytesToDecrypt = keyBytes == 24?32:keyBytes;
        keyCTX->type  = kS4KeyType_Symmetric;
        keyCTX->sym.symAlgor = passCtx->pbkdf2.cipherAlgor;
        keyCTX->sym.keylen = keyBytes;
        
        err =  ECB_Decrypt(encyptAlgor, unlocking_key, passCtx->pbkdf2.encrypted,
                           bytesToDecrypt, decrypted_key); CKERR;
        
        COPY(decrypted_key, keyCTX->sym.symKey, bytesToDecrypt);
        
    }
    else  if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Tweekable)
    {
        keyCTX->type  = kS4KeyType_Tweekable;
        keyCTX->tbc.tbcAlgor = passCtx->pbkdf2.cipherAlgor;
        keyCTX->tbc.keybits = keyBytes << 3;
        
        err =  ECB_Decrypt(encyptAlgor, unlocking_key, passCtx->pbkdf2.encrypted,
                           keyBytes,  decrypted_key); CKERR;
        
        memcpy(keyCTX->tbc.key, decrypted_key, keyBytes);
        
        //      Skein_Get64_LSB_First(keyCTX->tbc.key, decrypted_key, keyBytes >>2);   /* bytes to words */
    }
    else  if(passCtx->pbkdf2.keyAlgorithmType == kS4KeyType_Share)
    {
        // we dont have a way to determine the expected length of a split key.
        
        // is the Share to big?
        ASSERTERR(keyBytes <= 64 , kS4Err_CorruptData );
        
        keyCTX->type  = kS4KeyType_Share;
        keyCTX->share.threshold = passCtx->pbkdf2.threshold;
        keyCTX->share.xCoordinate = passCtx->pbkdf2.xCoordinate;
        COPY(passCtx->pbkdf2.shareHash, keyCTX->share.shareHash,  kS4ShareInfo_HashBytes);
        
        err =  ECB_Decrypt(encyptAlgor, unlocking_key, passCtx->pbkdf2.encrypted,
                           keyBytes, decrypted_key); CKERR;
        
        keyCTX->share.shareSecretLen = keyBytes;
        COPY(decrypted_key, keyCTX->share.shareSecret, keyBytes);
    }
    
    sCloneProperties(passCtx, keyCTX);
    sCloneSignatures(passCtx, keyCTX);

    *symCtx = keyCTX;
    
done:
    if(IsS4Err(err))
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

S4Err S4Key_DecryptFromS4Key( S4KeyContextRef      encodedCtx,
                             S4KeyContextRef       passKeyCtx,
                             S4KeyContextRef       *outKeyCtx)
{
    S4Err               err = kS4Err_NoErr;
    S4KeyContext*       keyCTX = NULL;
    
    int                 encyptAlgor = kCipher_Algorithm_Invalid;
    void*               keyToDecrypt = NULL;
    
    uint8_t             decrypted_key[128] = {0};
    size_t              decryptedLen = 0;
    
    uint8_t*            decrypted_privKey = NULL;
    size_t              decrypted_privKeyLen = 0;
    
    uint8_t*            unlockingKey    = NULL;
    uint8_t             keyHash[kS4KeyPublic_Encrypted_HashBytes] = {0};
    
    validateS4KeyContext(encodedCtx);
    validateS4KeyContext(passKeyCtx);
    ValidateParam(outKeyCtx);
    
    if(encodedCtx->type == kS4KeyType_PublicEncrypted )
    {
        return sDecryptFromPubKey(encodedCtx, passKeyCtx->pub.ecc, outKeyCtx);
    }
    
    ValidateParam(encodedCtx->type == kS4KeyType_SymmetricEncrypted);
    
    if(encodedCtx->symKeyEncoded.keyAlgorithmType == kS4KeyType_Symmetric)
    {
        decryptedLen = sGetKeyLength(kS4KeyType_Symmetric, encodedCtx->symKeyEncoded.cipherAlgor);
        keyToDecrypt = encodedCtx->symKeyEncoded.encrypted;
        encyptAlgor = encodedCtx->symKeyEncoded.encryptingAlgor;
        
    }
    else  if(encodedCtx->symKeyEncoded.keyAlgorithmType == kS4KeyType_Tweekable)
    {
        decryptedLen = sGetKeyLength(kS4KeyType_Tweekable, encodedCtx->symKeyEncoded.cipherAlgor);
        keyToDecrypt = encodedCtx->symKeyEncoded.encrypted;
        encyptAlgor = encodedCtx->symKeyEncoded.encryptingAlgor;
    }
    else  if(encodedCtx->symKeyEncoded.keyAlgorithmType == kS4KeyType_PublicKey)
    {
        keyToDecrypt = encodedCtx->symKeyEncoded.encrypted;
        encyptAlgor = encodedCtx->symKeyEncoded.encryptingAlgor;
    }
    else
    {
        RETERR(kS4Err_FeatureNotAvailable);
    }
    
    unlockingKey = passKeyCtx->sym.symKey;
    ASSERTERR(encyptAlgor == passKeyCtx->sym.symAlgor, kS4Err_BadParams)
    
    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(S4KeyContext));
    
    keyCTX->magic = kS4KeyContextMagic;
    
    if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Symmetric)
    {
        keyCTX->type  = kS4KeyType_Symmetric;
        keyCTX->sym.symAlgor = encodedCtx->symKeyEncoded.cipherAlgor;
        keyCTX->sym.keylen = decryptedLen;
        
        if(encodedCtx->symKeyEncoded.cipherAlgor  ==  kCipher_Algorithm_AES192)
        {
            //  it's padded at the end  (treat it like it was 256 bits)
            decryptedLen = 32;
        }
        
        err =  ECB_Decrypt(encyptAlgor, unlockingKey, keyToDecrypt, decryptedLen, decrypted_key); CKERR;
        
        COPY(decrypted_key, keyCTX->sym.symKey, decryptedLen);
        
        // check integrity of decypted value against the MAC
        err = sKEY_HASH(decrypted_key, decryptedLen, keyCTX->type,  keyCTX->sym.symAlgor,
                        keyHash, kS4KeyPublic_Encrypted_HashBytes ); CKERR;
        
    }
    else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_Tweekable)
    {
        keyCTX->type  = kS4KeyType_Tweekable;
        keyCTX->tbc.tbcAlgor = encodedCtx->symKeyEncoded.cipherAlgor;
        keyCTX->tbc.keybits = decryptedLen << 3;
        
        err =  ECB_Decrypt(encyptAlgor, unlockingKey, keyToDecrypt, decryptedLen, decrypted_key); CKERR;
        
        memcpy(keyCTX->tbc.key, decrypted_key, decryptedLen);
        //        Skein_Get64_LSB_First(keyCTX->tbc.key, decrypted_key, decryptedLen >>2);   /* bytes to words */
        
        // check integrity of decypted value against the MAC
        err = sKEY_HASH(decrypted_key, decryptedLen, keyCTX->type,  keyCTX->sym.symAlgor,
                        keyHash, kS4KeyPublic_Encrypted_HashBytes ); CKERR;
    }
    else  if(encodedCtx->publicKeyEncoded.keyAlgorithmType == kS4KeyType_PublicKey)
    {
        
        keyCTX->type  = kS4KeyType_PublicKey;
        keyCTX->pub.cipherAlgor = encodedCtx->symKeyEncoded.cipherAlgor;
        
        // the private key is CBC encrypted to the unlocking key, we pad and use the keyID as the IV.
        err =  CBC_DecryptPAD (encyptAlgor,unlockingKey,
                               encodedCtx->symKeyEncoded.keyID,
                               encodedCtx->symKeyEncoded.encrypted, encodedCtx->symKeyEncoded.encryptedLen,
                               &decrypted_privKey, &decrypted_privKeyLen); CKERR;
        
        err = ECC_Init(&keyCTX->pub.ecc);
        err = ECC_Import(keyCTX->pub.ecc, decrypted_privKey, decrypted_privKeyLen); CKERR;
        err = sCalculateECCData(keyCTX);
        
        // check integrity of decypted value against the MAC
        err = sKEY_HASH(decrypted_privKey, decrypted_privKeyLen, keyCTX->type,  keyCTX->pub.cipherAlgor,
                        keyHash, kS4KeyPublic_Encrypted_HashBytes ); CKERR;
        
    }
    
    ASSERTERR( CMP(keyHash, encodedCtx->symKeyEncoded.keyHash, kS4KeyPublic_Encrypted_HashBytes),
              kS4Err_BadIntegrity)
    
    sCloneProperties(encodedCtx, keyCTX);
    sCloneSignatures(encodedCtx, keyCTX);
   
    *outKeyCtx = keyCTX;
    
done:
    
    if(IsntNull(decrypted_privKey))
    {
        ZERO(decrypted_privKey, decrypted_privKeyLen);
        XFREE(decrypted_privKey);
    }
    
    if(IsS4Err(err))
    {
        if(IsntNull(keyCTX))
        {
            XFREE(keyCTX);
        }
    }
    
    ZERO(decrypted_key, sizeof(decrypted_key));
    
    return err;
    
}


#ifdef __clang__
#pragma mark - Share key generation.
#endif

S4Err S4Key_SerializeToShares(S4KeyContextRef       ctx,
                              uint32_t              totalShares,
                              uint32_t              threshold,
                              SHARES_ContextRef     *outShares,
                              uint8_t               **outData,
                              size_t                *outSize)
{
    S4Err               err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    uint8_t             *yajlBuf = NULL;
    size_t              yajlLen = 0;
    yajl_gen            g = NULL;
    
    uint8_t             tempBuf[1024];
    size_t              tempLen;
    uint8_t             *outBuf = NULL;
    
    SHARES_ContextRef   shareCTX = NULL;
    int                 i;
    
    Cipher_Algorithm    encyptAlgor = kCipher_Algorithm_Invalid;
    uint8_t             encrypted_key[128] = {0};
    size_t              keyBytes = 0;
    uint8_t             unlocking_key[32] = {0};
    uint8_t             keyHash[kS4KeyPBKDF2_HashBytes] = {0};
    
    void*               keyToEncrypt = NULL;
    
    char*           encodingPropString = NULL;
    char*           keySuiteString = "Invalid";
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };
    
    
    validateS4KeyContext(ctx);
    ValidateParam(outData);
    ValidateParam(outShares)
    
    switch (ctx->type)
    {
        case kS4KeyType_Symmetric:
            keyBytes = ctx->sym.keylen ;
            keyToEncrypt = ctx->sym.symKey;
            
            switch (ctx->sym.symAlgor) {
                case kCipher_Algorithm_2FISH256:
                    encyptAlgor = kCipher_Algorithm_2FISH256;
                    encodingPropString =  kS4KeyProp_Encoding_SPLIT_2FISH256;
                    break;
                    
                case kCipher_Algorithm_AES192:
                    encyptAlgor = kCipher_Algorithm_AES256;
                    encodingPropString =  kS4KeyProp_Encoding_SPLIT_AES256;
                    
                    //  pad the end  (treat it like it was 256 bits)
                    ZERO(&ctx->sym.symKey[24], 8);
                    keyBytes = 32;
                    break;
                    
                default:
                    encyptAlgor = kCipher_Algorithm_AES256;
                    encodingPropString =  kS4KeyProp_Encoding_SPLIT_AES256;
                    break;
            }
            
            keySuiteString = cipher_algor_table(ctx->sym.symAlgor);
            break;
            
        case kS4KeyType_Tweekable:
            keyBytes = ctx->tbc.keybits >> 3 ;
            encyptAlgor = kCipher_Algorithm_2FISH256;
            keySuiteString = cipher_algor_table(ctx->tbc.tbcAlgor);
            encodingPropString =  kS4KeyProp_Encoding_PBKDF2_2FISH256;
            keyToEncrypt = ctx->tbc.key;
            
            break;
            
        case kS4KeyType_Share:
            keyBytes = (int)ctx->share.shareSecretLen ;
            encyptAlgor = kCipher_Algorithm_2FISH256;
            keySuiteString = cipher_algor_table(kCipher_Algorithm_SharedKey);
            keyToEncrypt = ctx->share.shareSecret;
            encodingPropString =  kS4KeyProp_Encoding_PBKDF2_2FISH256;
            
            // we only encode block sizes of 16, 32, 48 and 64
            ASSERTERR((keyBytes % 16) == 0, kS4Err_FeatureNotAvailable);
            ASSERTERR(keyBytes <= 64, kS4Err_FeatureNotAvailable);
            
            break;
            
        default:
            break;
    }
    
    
    err = RNG_GetBytes( unlocking_key, sizeof(unlocking_key) ); CKERR;
    err = ECB_Encrypt(encyptAlgor, unlocking_key, keyToEncrypt, keyBytes, encrypted_key); CKERR;
    err = SHARES_Init(encrypted_key, keyBytes, totalShares, threshold, &shareCTX); CKERR;
    err = SHARES_GetShareHash(encrypted_key, keyBytes, threshold, keyHash, kS4ShareInfo_HashBytes);
    
    g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
    
#if DEBUG
    yajl_gen_config(g, yajl_gen_beautify, 1);
#else
    yajl_gen_config(g, yajl_gen_beautify, 0);
    
#endif
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    stat = yajl_gen_map_open(g);
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)encodingPropString, strlen(encodingPropString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_KeySuite, strlen(kS4KeyProp_KeySuite)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)keySuiteString, strlen(keySuiteString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", threshold);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareThreshold, strlen(kS4KeyProp_ShareThreshold)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", totalShares);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Mac, strlen(kS4KeyProp_Mac)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(keyHash, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_EncryptedKey, strlen(kS4KeyProp_EncryptedKey)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(encrypted_key, keyBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_ShareIDs, strlen(kS4KeyProp_ShareIDs)) ; CKYJAL;
    stat = yajl_gen_array_open(g);
    for(i = 0; i < totalShares; i++ )
    {
        SHARES_ShareInfo*   shareInfo = NULL;
        size_t shareLen = 0;
        uint8_t     shareID[kS4ShareInfo_HashBytes] = {0};
        
        err = SHARES_GetShareInfo(shareCTX, i, &shareInfo, &shareLen); CKERR;
        err = SHARES_GetShareHash(shareInfo->shareSecret, shareInfo->shareSecretLen, threshold, shareID, kS4ShareInfo_HashBytes);
        
        tempLen = sizeof(tempBuf);
        base64_encode(shareID, kS4ShareInfo_HashBytes, tempBuf, &tempLen);
        stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
        
        if(shareInfo)
            XFREE(shareInfo);
        
    }
    stat = yajl_gen_array_close(g);
    
    err = sGenPropStrings(ctx, g); CKERR;
    err = sGenSignablePropString(ctx, g); CKERR;
    err = sGenSignatureStrings(ctx, g); CKERR;
    
    stat = yajl_gen_map_close(g); CKYJAL;
    stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
    
    
    outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
    memcpy(outBuf, yajlBuf, yajlLen);
    outBuf[yajlLen] = 0;
    
    *outData = outBuf;
    
    if(outSize)
        *outSize = yajlLen;
    
    if(outShares)
        *outShares = shareCTX;
done:
    
    
    if(IsS4Err(err))
    {
        if(SHARES_ContextRefIsValid(shareCTX))
            SHARES_Free(shareCTX);
    }
    
    if(IsntNull(g))
        yajl_gen_free(g);
    
    return err;
    
}

#ifdef __clang__
#pragma mark - Public Key Signatures.
#endif

S4Err S4Key_SignHash( S4KeyContextRef      pubKeyCtx,
                     void *hash, size_t hashLen,
                     void *outSig, size_t bufSize, size_t *outSigLen)
{
    S4Err           err = kS4Err_NoErr;
    
    
    validateS4KeyContext(pubKeyCtx);
    ValidateParam(pubKeyCtx->type == kS4KeyType_PublicKey);
    
    bool canSign =  ECC_isPrivate(pubKeyCtx->pub.ecc);
    
    if(!canSign)
        RETERR(kS4Err_BadParams);
    
    err = ECC_Sign(pubKeyCtx->pub.ecc, hash, hashLen,  outSig, bufSize, outSigLen);CKERR;
    
done:
    
    return err;
}
S4Err S4Key_VerifyHash( S4KeyContextRef  pubKeyCtx,
                       void *hash, size_t hashLen,
                       void *sig,  size_t sigLen)
{
    S4Err           err = kS4Err_NoErr;
    
    validateS4KeyContext(pubKeyCtx);
    ValidateParam(pubKeyCtx->type == kS4KeyType_PublicKey);
    
    bool canVerify =  sECC_ContextIsValid(pubKeyCtx->pub.ecc);
    
    if(!canVerify)
        RETERR(kS4Err_BadParams);
    
    err = ECC_Verify(pubKeyCtx->pub.ecc,  sig, sigLen, hash, hashLen);
    
done:
    return err;
    
}



static S4Err sCalulateKeyDigest( S4KeyContextRef  keyCtx,
                              char**            optionalPropNamesList,
                              HASH_Algorithm    hashAlgorithm,
                              time_t            signDate,
                              long              sigExpireTime,
                              uint8_t* hashBuf, size_t *hashBytes )
{
    S4Err             err = kS4Err_NoErr;
    HASH_ContextRef    hash = NULL;
    
    validateS4KeyContext(keyCtx);
    
    size_t      propListEntries = 0;
    char**       propList = NULL;
    
    time_t       issueTime = signDate;
    long         expireTime = sigExpireTime == 0?LONG_MAX:sigExpireTime;

    err = HASH_Init( hashAlgorithm, &hash); CKERR;
    
    if(optionalPropNamesList)
    {
        for(propListEntries = 0; optionalPropNamesList[propListEntries] != 0; propListEntries++);
        propList = optionalPropNamesList;
    }
    else
    {
        err = sGetSignablePropertyNames(keyCtx, &propList, &propListEntries); CKERR;
    }
    
    // sign in issue date and expire
    err  = HASH_Update(hash,kS4KeyProp_SignedDate, strlen(kS4KeyProp_SignedDate)); CKERR;
    err  = HASH_Update(hash, ":", 1); CKERR;
    err  = HASH_Update(hash, &issueTime, sizeof(time_t)); CKERR;
    err  = HASH_Update(hash, ",", 1); CKERR;
    err  = HASH_Update(hash,kS4KeyProp_SigExpire, strlen(kS4KeyProp_SigExpire)); CKERR;
    err  = HASH_Update(hash, ":", 1); CKERR;
    err  = HASH_Update(hash, &expireTime, sizeof(long)); CKERR;
    
    if(propList)
    {
        for(int i = 0; i < propListEntries; i++)
        {
            // hash in the name
            err  = HASH_Update(hash, ",", 1); CKERR;
            err  = HASH_Update(hash,propList[i], strlen(propList[i])); CKERR;
            err  = HASH_Update(hash, ":", 1); CKERR;

            // Handle the special built in properties
            if(STRCMP2(propList[i], kS4KeyProp_KeyType))
            {
                err  = HASH_Update(hash, &keyCtx->type, sizeof(S4KeyType)); CKERR;
            }
            else if(STRCMP2(propList[i], kS4KeyProp_KeySuite))
            {
                Cipher_Algorithm  cipherAlgor = kCipher_Algorithm_Invalid;
                err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeySuite, NULL, &cipherAlgor, sizeof(cipherAlgor), NULL ); CKERR;
                err = HASH_Update(hash, &cipherAlgor, sizeof(Cipher_Algorithm)); CKERR;
            }
            else if(STRCMP2(propList[i], kS4KeyProp_KeyID))
            {
                uint8_t keyID [kS4Key_KeyIDBytes] = {0};
                err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeyID, NULL, &keyID, sizeof(keyID), NULL ); CKERR;
                err  = HASH_Update(hash,keyID, sizeof(keyID)); CKERR;
            }
            else if(STRCMP2(propList[i], kS4KeyProp_SignedBy))
            {
                uint8_t keyID [kS4Key_KeyIDBytes] = {0};
                err = S4Key_GetProperty(keyCtx, kS4KeyProp_SignedBy, NULL, &keyID, sizeof(keyID), NULL ); CKERR;
                err  = HASH_Update(hash,keyID, sizeof(keyID)); CKERR;
            }
            else if(STRCMP2(propList[i], kS4KeyProp_Signature))
            {
                err  = HASH_Update(hash,keyCtx->sig.signature, keyCtx->sig.signatureLen);  CKERR;
            }
            else if(STRCMP2(propList[i], kS4KeyProp_SignedDate))
            {
                err  = HASH_Update(hash, &keyCtx->sig.signDate, sizeof(time_t)); CKERR;
            }
            else if(STRCMP2(propList[i], kS4KeyProp_SigExpire))
            {
                long  expireTime = keyCtx->sig.expirationTime == 0?LONG_MAX:keyCtx->sig.expirationTime;
                err  = HASH_Update(hash, &expireTime, sizeof(expireTime)); CKERR;
            }
            else if(STRCMP2(propList[i], kS4KeyProp_SigID))
            {
                uint8_t keyID [kS4Key_KeyIDBytes] = {0};
                err = S4Key_GetProperty(keyCtx, kS4KeyProp_SigID, NULL, &keyID, sizeof(keyID), NULL ); CKERR;
                err  = HASH_Update(hash,keyID, sizeof(keyID)); CKERR;
            }
            
            else if(STRCMP2(propList[i], kS4KeyProp_PubKey))
            {
                uint8_t         keyData[256];
                size_t          keyDataLen = 0;
                
                err = ECC_Export_ANSI_X963(keyCtx->pub.ecc, keyData, sizeof(keyData), &keyDataLen);CKERR;
                err  = HASH_Update(hash,keyData, keyDataLen); CKERR;
            }
          
            // handle the properties found on proplist
            else
            {
                S4KeyProperty* prop = sFindProperty(keyCtx,propList[i]);
                
                if(!prop) continue;
                
                if(!optionalPropNamesList
                   && ((prop->extended && S4KeyPropertyExtended_Signable) != S4KeyPropertyExtended_Signable))
                    continue;
                
                switch(prop->type)
                {
                    case S4KeyPropertyType_UTF8String:
                    {
                        err  = HASH_Update(hash,prop->value, prop->valueLen); CKERR;
                    }
                        break;
                        
                    case S4KeyPropertyType_Binary:
                    {
                        err  = HASH_Update(hash,prop->value, prop->valueLen); CKERR;
                    }
                        break;
                        
                    case S4KeyPropertyType_Time:
                    {
                        uint8_t     tempBuf[32];
                        size_t      tempLen;
                        time_t      gTime;
                        struct      tm *nowtm;
                        
                        COPY(prop->value, &gTime, sizeof(gTime));
                        nowtm = gmtime(&gTime);
                        tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
                        err  = HASH_Update(hash,tempBuf, tempLen); CKERR;
                    }
                        break;
                        
                    default:
                        ;
                        
                }
                
            }
        }
    }
    
    HASH_GetSize(hash, hashBytes);
    HASH_Final(hash,hashBuf);
    
done:
    
    if(!optionalPropNamesList  && propList)
    {
        for(int i = 0; propList[i]; i++)
            XFREE(propList[i]);
        
        XFREE(propList);
    }
    
    if(!IsNull(hash))
        HASH_Free(hash);
    
    return err;
    
}

#ifdef __clang__
#pragma mark -  Key Signing/Verify
#endif
static void sCloneSignatures(S4KeyContext  *src, S4KeyContext  *dest )
{

    S4KeySigItem* item = NULL;
    S4KeySigItem** lastSig = &dest->sigList;
    
    for(item = src->sigList; item; item = item->next)
    {
        S4KeySigItem* newItem =  XMALLOC(sizeof(S4KeySigItem));
        ZERO(newItem,sizeof(S4KeySigItem));
        
        if(item->sig.signature)
        {
            newItem->sig.signature = XMALLOC(item->sig.signatureLen );
            COPY(item->sig.signature, newItem->sig.signature, item->sig.signatureLen );
            newItem->sig.signatureLen = item->sig.signatureLen;
            newItem->sig.hashAlgorithm  = item->sig.hashAlgorithm;
            
            COPY(item->sig.issuerID, newItem->sig.issuerID, kS4Key_KeyIDBytes );
            COPY(item->sig.sigID, newItem->sig.sigID, kS4Key_KeyIDBytes );
            
            newItem->sig.signDate = item->sig.signDate;
            newItem->sig.expirationTime  = item->sig.expirationTime;
            newItem->sig.propNameList = sDeepStrDup(item->sig.propNameList);
            
            *lastSig = newItem;
            lastSig = &newItem->next;
        }
        
        *lastSig = NULL;
    }
}

static char** sDeepStrDup( char** list)
{
    size_t          listCount = 0;
    char**          newList = NULL;
    
    if(list)
    {
        for(int i = 0; list[i]; i++)
            listCount++;
        
        if(listCount)
        {
            int i = 0;
            newList = XMALLOC((listCount + 1 ) * sizeof(char*) );
            
            for(i = 0; list[i]; i++)
                newList[i] = strdup(list[i]);
            
            newList[i++] = NULL;
        }
        
  
    }
      return newList;
}


static void sInsertSig(S4KeyContextRef      signingCtx,
                       S4KeyContextRef      pubCtx,
                       uint8_t              sigID[kS4Key_KeyIDBytes],
                       uint8_t              *sigData,
                       size_t               sigDataLen,
                       HASH_Algorithm       hashAlgorithm,
                       time_t               signDate,
                       time_t               expirationTime,
                       char**               propNameList)
{
    S4KeySigItem* sigItem = XMALLOC(sizeof(S4KeySigItem));
    if(sigItem)
    {
        ZERO(sigItem,sizeof(S4KeySigItem));
        
        sigItem->sig.signature = XMALLOC(sigDataLen);
        COPY(sigData, sigItem->sig.signature, sigDataLen );
        sigItem->sig.signatureLen = sigDataLen;
        COPY(&signingCtx->pub.keyID ,  &sigItem->sig.issuerID, kS4Key_KeyIDBytes);
        COPY(sigID ,  &sigItem->sig.sigID, kS4Key_KeyIDBytes);
        
        sigItem->sig.hashAlgorithm = hashAlgorithm;
        sigItem->sig.signDate = signDate;
        sigItem->sig.expirationTime = expirationTime;
        sigItem->sig.propNameList = sDeepStrDup(propNameList);
        
        sigItem->next = pubCtx->sigList;
        pubCtx->sigList = sigItem;
    }
}
    
S4Err S4Key_SignKey( S4KeyContextRef      signingCtx,
                     S4KeyContextRef      keyCtx,
                     long                 sigExpireTime
                    )
{
    S4Err           err = kS4Err_NoErr;
    
    size_t          propNameCount = 0;
    char**          propNameList = NULL;

    uint8_t        keyHash [32] = {0};
    size_t         keyHashLen = 0;
    
     uint8_t        sigBuff[256];
    size_t          sigBuffLen = 0;
    
    time_t          signDate = time(NULL);
    long            expireTime = sigExpireTime == 0?LONG_MAX:sigExpireTime;
    
    uint8_t        sigID [kS4Key_KeyIDBytes] = {0};
    
    HASH_Algorithm  hashAlgorithm = kHASH_Algorithm_SHA256;
    
    validateS4KeyContext(signingCtx);
    validateS4KeyContext(keyCtx);
    ValidateParam(keyCtx->type == kS4KeyType_PublicKey
                  || keyCtx->type == kS4KeyType_Signature );
    ValidateParam(signingCtx->type == kS4KeyType_PublicKey);
    
    bool canSign =  ECC_isPrivate(signingCtx->pub.ecc);
    
    if(!canSign)
        RETERR(kS4Err_BadParams);
   
    // Get the properties we use for signing.
    err = sGetSignablePropertyNames(keyCtx, &propNameList, &propNameCount); CKERR;

    // caclulate the key hash
    err = sCalulateKeyDigest(keyCtx,
                             propNameList,
                             hashAlgorithm,
                             signDate, expireTime,
                             keyHash, &keyHashLen); CKERR;
    
    // generate a random SigID
    err = RNG_GetBytes( sigID, sizeof(sigID)); CKERR;

     // calculate the key sig
    err = ECC_Sign(signingCtx->pub.ecc,
                   keyHash, keyHashLen,
                   sigBuff, sizeof(sigBuff), &sigBuffLen);CKERR;
    
    sInsertSig(signingCtx,
               keyCtx,
               sigID,
               sigBuff, sigBuffLen,
               hashAlgorithm,
               signDate, expireTime,
               propNameList);
    
done:
    
    if(propNameList)
   {
       for(int i = 0; propNameList[i]; i++)
           XFREE(propNameList[i]);
       XFREE(propNameList);
   }
    
    return err;
}

S4Err S4Key_GetKeySignatures( S4KeyContextRef      ctx,
                                size_t              *outCount,
                                S4KeyContextRef     *ctxArrayOut[])
{
    S4Err           err = kS4Err_NoErr;

    size_t                  keyCount = 0;
    S4KeyContextRef*         ctxArray = NULL;
    S4KeySigItem *sigItem   = NULL;
    int i;
    
    validateS4KeyContext(ctx);
    
    // get number of signatures
    for(sigItem = ctx->sigList; sigItem; sigItem = sigItem->next)
        keyCount++;
   
    // allocate the ctxArray
    ctxArray = XMALLOC(sizeof(S4KeyContext) * keyCount);
    ZERO(ctxArray, sizeof(S4KeyContext) * keyCount);
    
    for(i=0 , sigItem = ctx->sigList ; i < keyCount; i++, sigItem = sigItem->next)
    {
        
        S4KeyContext* keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
        ZERO(keyCTX, sizeof(S4KeyContext));
        
        keyCTX->magic = kS4KeyContextMagic;
        keyCTX->type  = kS4KeyType_Signature;
        keyCTX->propList = NULL;
        keyCTX->sigList = NULL;
      
        COPY(sigItem->sig.issuerID, keyCTX->sig.issuerID, kS4Key_KeyIDBytes);
        keyCTX->sig.signDate = sigItem->sig.signDate;
        keyCTX->sig.expirationTime = sigItem->sig.expirationTime;
       
        for(int offset = 0; sigItem->sig.propNameList[offset] != NULL; offset++)
        {
            sAppendSigProp(&keyCTX->sig,
                           (char *)sigItem->sig.propNameList[offset],
                           strlen(sigItem->sig.propNameList[offset]));
 
        }

        keyCTX->sig.hashAlgorithm  = sigItem->sig.hashAlgorithm;
        
        keyCTX->sig.signature = XMALLOC(sigItem->sig.signatureLen);
        COPY(sigItem->sig.signature, keyCTX->sig.signature, sigItem->sig.signatureLen);
        keyCTX->sig.signatureLen =  sigItem->sig.signatureLen;
        
        ctxArray[i] = keyCTX;
    }
    
    
done:

    if(ctxArrayOut)
    {
        if(!keyCount)
        {
            *ctxArrayOut = NULL;
        }
        else
        {
            *ctxArrayOut = ctxArray;
        }
    }

    if(outCount) *outCount = keyCount;
    
    return err;

}



S4Err S4Key_VerfiyKeySig( S4KeyContextRef      keyCtx,
                          S4KeyContextRef      sigingKeyCtx,
                          S4KeyContextRef      sigCtx)
{
    S4Err           err = kS4Err_NoErr;

    uint8_t        keyHash1[32] = {0};
    size_t         keyHash1Len = 0;
    
    validateS4KeyContext(keyCtx);
    validateS4KeyContext(sigingKeyCtx);

    ValidateParam(keyCtx->type == kS4KeyType_PublicKey
                  || keyCtx->type == kS4KeyType_Signature );
    
    ValidateParam(sigingKeyCtx->type == kS4KeyType_PublicKey);
    
    bool isPubKey = sECC_ContextIsValid(sigingKeyCtx->pub.ecc);
    if(!isPubKey)
        RETERR(kS4Err_BadParams);
   
    bool isSig =  sigCtx->type == kS4KeyType_Signature;
    if(!isSig)
        RETERR(kS4Err_BadParams);
    
    bool isCorrectKey = S4Key_CompareKeyID(sigingKeyCtx->pub.keyID, sigCtx->sig.issuerID);
    if(!isCorrectKey)
        RETERR(kS4Err_BadParams);
  

    err = sCalulateKeyDigest(keyCtx,sigCtx->sig.propNameList ,
                                  kHASH_Algorithm_SHA256,
                                  sigCtx->sig.signDate,
                                  sigCtx->sig.expirationTime,
                                  keyHash1, &keyHash1Len); CKERR;
    
    err = S4Key_VerifyHash(sigingKeyCtx,
                           keyHash1,keyHash1Len,
                           sigCtx->sig.signature, sigCtx->sig.signatureLen);  CKERR;
    
done:
    
    return err;

}

bool S4Key_CompareKeyID(uint8_t* keyID1, uint8_t* keyID2)
{
    return CMP(keyID1, keyID2, kS4Key_KeyIDBytes);
    
}


#ifdef __clang__
#pragma mark -  Deatched Sigs.
#endif

S4Err S4Key_NewSignature( S4KeyContextRef       pubCtx,
                         void                   *hashData,
                         size_t                 hashDataLen,
                         HASH_Algorithm         hashAlgorithm,
                         long                   sigExpireTime,
                         S4KeyContextRef        *ctxOut)
{
    S4Err           err = kS4Err_NoErr;
    S4KeyContext*    keyCTX  = NULL;
    
    int             keyBytes  = 0;
    uint8_t         *keyData = NULL;
  
    uint8_t         SIG[256];
    size_t          SIGlen = 0;

    uint8_t         sigID [kS4Key_KeyIDBytes] = {0};

    time_t          signDate = time(NULL);
    long            expireTime = sigExpireTime == 0?LONG_MAX:sigExpireTime;

    HASH_ContextRef hashCtx = kInvalidHASH_ContextRef;
    size_t hashSize = 0;
    
    validateS4KeyContext(pubCtx);
    ValidateParam(pubCtx->type == kS4KeyType_PublicKey);
    ValidateParam(ctxOut);
    
    // check if hashAlgorithm is appropriate for hashLen
    err = HASH_Init(hashAlgorithm, &hashCtx); CKERR;
    err = HASH_GetSize(hashCtx, &hashSize); CKERR;
    ValidateParam(hashDataLen == hashSize);
    HASH_Free(hashCtx); hashCtx = kInvalidHASH_ContextRef;

    err = S4Key_SignHash(pubCtx, hashData,hashDataLen, SIG, sizeof(SIG), &SIGlen); CKERR;
    
    // generate a randome SigID
    err = RNG_GetBytes( sigID, sizeof(sigID)); CKERR;

    keyCTX = XMALLOC(sizeof (S4KeyContext)); CKNULL(keyCTX);
    ZERO(keyCTX, sizeof(S4KeyContext));
    
    keyCTX->magic = kS4KeyContextMagic;
    keyCTX->type  = kS4KeyType_Signature;
    keyCTX->propList = NULL;
    keyCTX->sigList = NULL;

    COPY(pubCtx->pub.keyID, keyCTX->sig.issuerID, kS4Key_KeyIDBytes );
    
    keyCTX->sig.signature = XMALLOC(SIGlen );  CKNULL(keyCTX->sig.signature);
    COPY(SIG, keyCTX->sig.signature, SIGlen );
    keyCTX->sig.signatureLen = SIGlen;
    
    COPY(sigID, keyCTX->sig.sigID, sizeof(keyCTX->sig.sigID));
  
    keyCTX->sig.hashAlgorithm   = hashAlgorithm;
    keyCTX->sig.signDate        = signDate;
    keyCTX->sig.expirationTime  = expireTime;

    *ctxOut = keyCTX;
    
done:
    
    if(hashCtx)
        HASH_Free(hashCtx);
    
    if(keyData && keyBytes)
    {
        ZERO(keyData, keyBytes);
        XFREE(keyData);
    }
    
    if(IsS4Err(err))
    {
        if(keyCTX)
        {
            memset(keyCTX, sizeof (S4KeyContext), 0);
            XFREE(keyCTX);
        }
    }
    
    return err;


}

S4Err S4Key_SerializeSignature( S4KeyContextRef      sigCtx,
                               uint8_t          **outData,
                               size_t           *outSize)
{
    S4Err           err = kS4Err_NoErr;
    yajl_gen_status     stat = yajl_gen_status_ok;
    
    uint8_t             *yajlBuf = NULL;
    size_t              yajlLen = 0;
    yajl_gen            g = NULL;
    
    uint8_t             tempBuf[1024];
    size_t              tempLen;
    uint8_t             *outBuf = NULL;
    char*               hashAlgorString = "Invalid";
    
    yajl_alloc_funcs allocFuncs = {
        yajlMalloc,
        yajlRealloc,
        yajlFree,
        (void *) NULL
    };
    
    validateS4KeyContext(sigCtx);
    ValidateParam(outData);
 
    ValidateParam(sigCtx->type == kS4KeyType_Signature);
  
    g = yajl_gen_alloc(&allocFuncs); CKNULL(g);
    
#if DEBUG
    yajl_gen_config(g, yajl_gen_beautify, 1);
#else
    yajl_gen_config(g, yajl_gen_beautify, 0);
    
#endif
    yajl_gen_config(g, yajl_gen_validate_utf8, 1);
    stat = yajl_gen_map_open(g);
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Version, strlen(kS4KeyProp_Version)) ; CKYJAL;
    sprintf((char *)tempBuf, "%d", kS4KeyProtocolVersion);
    stat = yajl_gen_number(g, (char *)tempBuf, strlen((char *)tempBuf)) ; CKYJAL;
   
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding, strlen(kS4KeyProp_Encoding)) ; CKYJAL;
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Encoding_Signature, strlen(kS4KeyProp_Encoding_Signature)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SigID, strlen(kS4KeyProp_SigID)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(sigCtx->sig.sigID, kS4Key_KeyIDBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_HashAlgorithm, strlen(kS4KeyProp_HashAlgorithm)) ; CKYJAL
    hashAlgorString = hash_algor_table(sigCtx->sig.hashAlgorithm);
    stat = yajl_gen_string(g, (uint8_t *)hashAlgorString, strlen(hashAlgorString)) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_Signature, strlen(kS4KeyProp_Signature)) ; CKYJAL
    tempLen = sizeof(tempBuf);
    base64_encode(sigCtx->sig.signature, sigCtx->sig.signatureLen, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedBy, strlen(kS4KeyProp_SignedBy)) ; CKYJAL;
    tempLen = sizeof(tempBuf);
    base64_encode(sigCtx->sig.issuerID, kS4Key_KeyIDBytes, tempBuf, &tempLen);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;
    
    stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SignedDate, strlen(kS4KeyProp_SignedDate)) ; CKYJAL;
    struct tm *nowtm;
    nowtm = gmtime(&sigCtx->sig.signDate);
    tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
    stat = yajl_gen_string(g, tempBuf, (size_t)tempLen) ; CKYJAL;

    if(sigCtx->sig.expirationTime != LONG_MAX)
    {
        stat = yajl_gen_string(g, (uint8_t *)kS4KeyProp_SigExpire, strlen(kS4KeyProp_SigExpire)) ; CKYJAL;
        stat = yajl_gen_integer(g, sigCtx->sig.expirationTime) ; CKYJAL;
    }
    
    err = sGenPropStrings(sigCtx, g); CKERR;
    err = sGenSignatureStrings(sigCtx, g); CKERR;

    stat = yajl_gen_map_close(g); CKYJAL;
    stat =  yajl_gen_get_buf(g, (const unsigned char**) &yajlBuf, &yajlLen);CKYJAL;
    
    outBuf = XMALLOC(yajlLen+1); CKNULL(outBuf);
    memcpy(outBuf, yajlBuf, yajlLen);
    outBuf[yajlLen] = 0;
    
    
    *outData = outBuf;
    
    if(outSize)
        *outSize = yajlLen;
    
done:
    if(IsntNull(g))
        yajl_gen_free(g);
    
    return err;

}

S4Err S4Key_VerifySignature( S4KeyContextRef      sigCtx,
                            S4KeyContextRef       sigingKeyCtx,
                            void                   *hash,
                            size_t                 hashLen )
{
    S4Err           err = kS4Err_NoErr;
    
 
    validateS4KeyContext(sigingKeyCtx);
    validateS4KeyContext(sigCtx);
    
    ValidateParam(sigingKeyCtx->type == kS4KeyType_PublicKey);
    ValidateParam(sigCtx->type == kS4KeyType_Signature);
    
    bool isPubKey =  sECC_ContextIsValid(sigingKeyCtx->pub.ecc);
    if(!isPubKey)
        RETERR(kS4Err_BadParams);
    
    bool isCorrectKey = S4Key_CompareKeyID(sigingKeyCtx->pub.keyID, sigCtx->sig.issuerID);
    if(!isCorrectKey)
        RETERR(kS4Err_BadParams);
    
    err = S4Key_VerifyHash(sigingKeyCtx,
                           hash,hashLen,
                           sigCtx->sig.signature, sigCtx->sig.signatureLen);  CKERR;
    
done:
    
    return err;


}
