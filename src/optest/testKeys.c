//
//  testKeys.c
//  S4
//
//  Created by vincent Moscaritolo on 11/9/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include <stdio.h>
#include "s4.h"
#include "optest.h"
#include <time.h>

static char *const kS4KeyProp_Time   = "testTime";

static char *const kS4KeyProp_TestPassCodeID   = "passcodeID";

typedef struct  {
    char*               comment;
    Cipher_Algorithm    algor;
    int                 keysize;
    uint8_t             *key;
    uint8_t             *passPhrase;
    
} cipherKATvector;



static char *exported_keys   = NULL;
static int exported_key_count   = 0;

static S4Err sCompareKeys( S4KeyContext  *keyCtx, S4KeyContext  *keyCtx1)
{
    S4Err err = kS4Err_NoErr;
    
    ValidateParam(keyCtx);
    ValidateParam(keyCtx1);
    
    S4KeyType   type1,type2;
    int8_t     algor1, algor2;

    int8_t      key1[128], key2[128];
    size_t      keyLen1, keyLen2;
    
    uint8_t         keyHash1[kS4KeyPBKDF2_HashBytes] = {0};
    uint8_t         keyHash2[kS4KeyPBKDF2_HashBytes] = {0};

    err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeyType, NULL, &type1, sizeof(type1), NULL ); CKERR;
    err = S4Key_GetProperty(keyCtx1, kS4KeyProp_KeyType, NULL, &type2, sizeof(type1), NULL ); CKERR;
    ASSERTERR(type1 != type2,  kS4Err_SelfTestFailed);

    switch (type1) {
        case kS4KeyType_Symmetric:
            
            err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeySuite, NULL, &algor1, sizeof(algor1), NULL ); CKERR;
            err = S4Key_GetProperty(keyCtx1, kS4KeyProp_KeySuite, NULL, &algor2, sizeof(algor2), NULL ); CKERR;
            ASSERTERR(algor1 != algor2,  kS4Err_SelfTestFailed);
            
            err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeyData, NULL, &key1 , sizeof(key1), &keyLen1 ); CKERR;
            err = S4Key_GetProperty(keyCtx1, kS4KeyProp_KeyData, NULL, &key2 , sizeof(key2), &keyLen2 ); CKERR;
            ASSERTERR(keyLen1 != keyLen2,  kS4Err_SelfTestFailed);
            err = compareResults( key1, key2, keyLen1,
                                 kResultFormat_Byte, "Symmetric key"); CKERR;
            
            err = S4Key_GetProperty(keyCtx, kS4KeyProp_Mac, NULL, &keyHash1, sizeof(keyHash1), NULL ); CKERR;
            err = S4Key_GetProperty(keyCtx1, kS4KeyProp_Mac, NULL, &keyHash2, sizeof(keyHash2), NULL ); CKERR;
            
            err = compareResults( keyHash1, keyHash1, kS4KeyPBKDF2_HashBytes,
                                 kResultFormat_Byte, "KeyHash"); CKERR;
            
             break;
            
        case kS4KeyType_Tweekable:
            
            err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeySuite, NULL, &algor1, sizeof(algor1), NULL ); CKERR;
            err = S4Key_GetProperty(keyCtx1, kS4KeyProp_KeySuite, NULL, &algor2, sizeof(algor2), NULL ); CKERR;
            ASSERTERR(algor1 != algor2,  kS4Err_SelfTestFailed);

            err = S4Key_GetProperty(keyCtx, kS4KeyProp_KeyData, NULL, &key1 , sizeof(key1), &keyLen1 ); CKERR;
            err = S4Key_GetProperty(keyCtx1, kS4KeyProp_KeyData, NULL, &key2 , sizeof(key2), &keyLen2 ); CKERR;
            ASSERTERR(keyLen1 != keyLen2,  kS4Err_SelfTestFailed);
            err = compareResults( key1, key2, keyLen1,
                                 kResultFormat_Byte, "TBC key"); CKERR;
            
            err = S4Key_GetProperty(keyCtx, kS4KeyProp_Mac, NULL, &keyHash1, sizeof(keyHash1), NULL ); CKERR;
            err = S4Key_GetProperty(keyCtx1, kS4KeyProp_Mac, NULL, &keyHash2, sizeof(keyHash2), NULL ); CKERR;
            
            err = compareResults( keyHash1, keyHash1, kS4KeyPBKDF2_HashBytes,
                                 kResultFormat_Byte, "KeyHash"); CKERR;
            
            break;
    
        case kS4KeyType_Share:
            ASSERTERR(keyCtx->share.threshold != keyCtx1->share.threshold,  kS4Err_SelfTestFailed);
            ASSERTERR(keyCtx->share.xCoordinate != keyCtx1->share.xCoordinate,  kS4Err_SelfTestFailed);
            ASSERTERR(keyCtx->share.shareSecretLen != keyCtx1->share.shareSecretLen,  kS4Err_SelfTestFailed);
      
            err = compareResults( keyCtx->share.shareHash, keyCtx1->share.shareHash, kS4ShareInfo_HashBytes,
                                 kResultFormat_Byte, "Share Hash"); CKERR;
            
            
            err = compareResults( keyCtx->share.shareSecret, keyCtx1->share.shareSecret, keyCtx->share.shareSecretLen,
                                 kResultFormat_Byte, "Share Hash"); CKERR;
  
            err = S4Key_GetProperty(keyCtx, kS4KeyProp_Mac, NULL, &keyHash1, sizeof(keyHash1), NULL ); CKERR;
            err = S4Key_GetProperty(keyCtx1, kS4KeyProp_Mac, NULL, &keyHash2, sizeof(keyHash2), NULL ); CKERR;
            
            err = compareResults( keyHash1, keyHash1, kS4KeyPBKDF2_HashBytes,
                                 kResultFormat_Byte, "KeyHash"); CKERR;
  
            break;
            

        case kS4KeyType_PBKDF2:
            switch (keyCtx->pbkdf2.keyAlgorithmType)
        {
            case kS4KeyType_Symmetric:
                 break;
                
            case kS4KeyType_Tweekable:
                 break;
                
            default:;
                
        };
            break;
            
        default:
            err = kS4Err_UnknownError;
            break;
    }

    // compare additional properties
    S4KeyProperty* prop = keyCtx->propList;
    while(prop)
    {
        S4KeyPropertyType type2 = S4KeyPropertyType_Invalid;
        void     *data2 = NULL;
        size_t      data2Len = 0;
 
        S4KeyPropertyType type1 = S4KeyPropertyType_Invalid;
        void     *data1 = NULL;
        size_t      data1Len = 0;
        
        err = SCKeyGetAllocatedProperty(keyCtx, (const char*) prop->prop, &type1, &data1, &data1Len); CKERR;
        err = SCKeyGetAllocatedProperty(keyCtx, (const char*) prop->prop, &type2, &data2, &data2Len); CKERR;
        
        ASSERTERR(type1 != type2,  kS4Err_SelfTestFailed);
        
        err = compare2Results( data1, data1Len, data2, data2Len, kResultFormat_Byte, ( char*) prop->prop); CKERR;
        
        if(data1) free(data1);
        if(data2) free(data2);
        
        prop = prop->next;
    }

done:
    return err;
}


static S4Err sRunCipherPBKDF2ImportExportKAT(  cipherKATvector *kat)
{
    S4Err err = kS4Err_NoErr;
    S4KeyContextRef keyCtx =  kInvalidS4KeyContextRef;
    S4KeyContextRef keyCtx1 =  kInvalidS4KeyContextRef;
    
    S4KeyContextRef  *passCtx = NULL;
    size_t      keyCount = 0;
     
    char* name = NULL;
    
    uint8_t     *data = NULL;
    size_t      dataLen = 0;
    
    time_t          testDate  = time(NULL) ;
    
    name = cipher_algor_table(kat->algor);
    
    OPTESTLogVerbose("\t%-14s ", name);
    OPTESTLogVerbose("%8s", "Export");
    
    err = S4Key_NewSymmetric(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = S4Key_SetProperty(keyCtx,kS4KeyProp_TestPassCodeID,S4KeyPropertyType_UTF8String, kat->comment, strlen(kat->comment)); CKERR;
    err = S4Key_SetProperty(keyCtx, kS4KeyProp_Time, S4KeyPropertyType_Time ,  &testDate, sizeof(time_t)); CKERR;
  
    err = S4Key_SerializeToPassPhrase(keyCtx, kat->passPhrase, strlen((char*)kat->passPhrase), &data, &dataLen); CKERR;
    
      OPTESTLogDebug("\n------\n%s------\n",data);
    
    OPTESTLogVerbose("%8s", "Import");
    err = S4Key_DeserializeKeys(data, dataLen, &keyCount, &passCtx ); CKERR;
    
 //   sDumpS4Key(OPTESTLOG_LEVEL_DEBUG, passCtx);
    
    OPTESTLogVerbose("%8s", "Verify");
    err = S4Key_VerifyPassPhrase(passCtx[0], kat->passPhrase, strlen((char*)kat->passPhrase)); CKERR;

    err = S4Key_DecryptFromPassPhrase(passCtx[0],kat->passPhrase, strlen((char*)kat->passPhrase), &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;

    if(data)
    {
        asprintf(&exported_keys,"%s %s %s", exported_keys,strlen(exported_keys) > 1?",":"", data );
        exported_key_count++;
     }
    
done:
    if(data)
        XFREE(data);
 
    if(S4KeyContextRefIsValid(keyCtx))
    {
        S4Key_Free(keyCtx);
    }
    if(passCtx)
    {
        if(S4KeyContextRefIsValid(passCtx[0]))
        {
             S4Key_Free(passCtx[0]);
        }
        XFREE(passCtx);
        
    }
      if(S4KeyContextRefIsValid(keyCtx1))
    {
        S4Key_Free(keyCtx1);
    }
  
    OPTESTLogVerbose("\n");

    return err;
}

static S4Err sRunCipherImportExportKAT(  cipherKATvector *kat)
{
    S4Err err = kS4Err_NoErr;
    S4KeyContextRef passKeyCtx =  kInvalidS4KeyContextRef;
    S4KeyContextRef keyCtx =  kInvalidS4KeyContextRef;
    S4KeyContextRef keyCtx1 =  kInvalidS4KeyContextRef;
    
    S4KeyContextRef  *importCtx = NULL;
    uint8_t         unlockingKey[32];
    size_t      keyCount = 0;
    
    char* name = NULL;
    
    uint8_t     *data = NULL;
    size_t      dataLen = 0;
    
    time_t          testDate  = time(NULL) ;
    
    name = cipher_algor_table(kat->algor);
    
    OPTESTLogVerbose("\t%-14s ", name);
    OPTESTLogVerbose("%8s", "Export");
    
    // create a random  unlocking key
    err = RNG_GetBytes(unlockingKey, sizeof(unlockingKey)); CKERR;
    
    err = S4Key_NewSymmetric(kCipher_Algorithm_2FISH256, unlockingKey, &passKeyCtx  ); CKERR;
  
    err = S4Key_NewSymmetric(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = S4Key_SetProperty(keyCtx,kS4KeyProp_TestPassCodeID,S4KeyPropertyType_UTF8String, kat->comment, strlen(kat->comment)); CKERR;
    err = S4Key_SetProperty(keyCtx, kS4KeyProp_Time, S4KeyPropertyType_Time ,  &testDate, sizeof(time_t)); CKERR;
    
    err = S4Key_SerializeToS4Key(keyCtx, passKeyCtx, &data, &dataLen); CKERR;
    
    OPTESTLogDebug("\n------\n%s------\n",data);
    
    OPTESTLogVerbose("%8s", "Import");
    err = S4Key_DeserializeKeys(data, dataLen, &keyCount, &importCtx ); CKERR;
    ASSERTERR(keyCount != 1,  kS4Err_SelfTestFailed);
    
    OPTESTLogVerbose("%8s", "Verify");
    err = S4Key_DecryptFromS4Key(importCtx[0], passKeyCtx , &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;
    
    
    if(data)
    {
        asprintf(&exported_keys,"%s %s %s", exported_keys,strlen(exported_keys) > 1?",":"", data );
        exported_key_count++;
    }
    
done:
    if(data)
        XFREE(data);
    
    if(S4KeyContextRefIsValid(keyCtx))
    {
        S4Key_Free(keyCtx);
    }

    if(importCtx)
    {
        if(S4KeyContextRefIsValid(importCtx[0]))
        {
            S4Key_Free(importCtx[0]);
        }
        XFREE(importCtx);
        
    }
    
    if(S4KeyContextRefIsValid(passKeyCtx))
    {
        S4Key_Free(passKeyCtx);
    }
 
    if(S4KeyContextRefIsValid(keyCtx1))
    {
        S4Key_Free(keyCtx1);
    }
    
    OPTESTLogVerbose("\n");
    
    return err;
}


static S4Err  sTestSymmetricKeys()
{
    S4Err     err = kS4Err_NoErr;
    int i;
    
    uint8_t* passPhrase1 = (uint8_t*)"Tant las fotei com auziretz";
   
    /* AES 128 bit key */
    uint8_t K1[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12
    };
    
    /* AES 192 bit key */
    uint8_t K2[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
        0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C
    };
    
    /* AES 256 bit key */
    uint8_t K3[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
        0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C,
        0x1E, 0x1F, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26
    };
    
    cipherKATvector kat_vector_array[] =
    {
        {"Key 1",	kCipher_Algorithm_AES128, 128,	K1, passPhrase1},
        {"Key 2",    kCipher_Algorithm_AES192, 192,	K2, passPhrase1},
        {"Key 3",   kCipher_Algorithm_AES256, 256,   K3, passPhrase1},
        {"Key 4",   kCipher_Algorithm_2FISH256, 256,   K3, passPhrase1},
    };
    
    
    
    OPTESTLogInfo("\nTesting Symmetric S4Key Encoding\n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunCipherImportExportKAT( &kat_vector_array[i] ); CKERR;
    }
    
    OPTESTLogInfo("\nTesting  Symmetric PBKDF2 S4Key Encoding\n");

    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunCipherPBKDF2ImportExportKAT( &kat_vector_array[i] ); CKERR;
      }
    
  
done:
     return err;
}




static S4Err sRunSharedPBKDF2ImportExportKAT(  cipherKATvector *kat)
{
    
#define kNumShares				8
#define kShareThreshold			6
    
    S4Err               err = kS4Err_NoErr;
    
    SHARES_ContextRef   ctx  			= kInvalidSHARES_ContextRef;
    SHARES_ShareInfo*   shares[kNumShares] = {NULL};
    SHARES_ShareInfo*   recoveredShares[kNumShares] = {NULL};
    
    S4KeyContextRef     shareCtx[kNumShares] = {kInvalidS4KeyContextRef};
    uint8_t*            shareData[kNumShares] = {NULL};
    
    S4KeyContextRef *encodedCtx =  NULL;
    size_t          keyCount = 0;
    
    uint8_t             PT1[128];
    size_t              PT1len;
    
    int                 i;
    char* name = NULL;
   
    
    name = cipher_algor_table(kat->algor);
    
    OPTESTLogVerbose("\t%-14s ", name);
    // skip AES-192
    if(kat->algor == kCipher_Algorithm_AES192)
    {
        OPTESTLogVerbose("%s", " -- Not Supported --");
        goto done;
 
    }
    
    OPTESTLogVerbose("%s", "Split");
    
    err = SHARES_Init( kat->key, kat->keysize >>3 ,
                      kNumShares,
                      kShareThreshold,
                      &ctx); CKERR;
    
    OPTESTLogVerbose("%8s", "Export");
    for(i = 0; i < kNumShares; i++)
    {
        size_t shareLen = 0;
        
        err = SHARES_GetShareInfo(ctx, i, &shares[i], &shareLen); CKERR;
        err = S4Key_NewShare( shares[i], &shareCtx[i]); CKERR;
        
        err = S4Key_SetProperty(shareCtx[i],kS4KeyProp_TestPassCodeID,S4KeyPropertyType_UTF8String, kat->comment, strlen(kat->comment)); CKERR;
        err = S4Key_SerializeToPassPhrase(shareCtx[i], kat->passPhrase, strlen((char*)kat->passPhrase),&shareData[i], NULL); CKERR;
        
        
        OPTESTLogDebug("\n------\n%s",shareData[i]);
        
        if(shareData[i])
        {
            asprintf(&exported_keys,"%s %s %s", exported_keys,strlen(exported_keys) > 1?",":"", shareData[i] );
            exported_key_count++;
        }

    }
    
    OPTESTLogVerbose("%8s", "Decode");
    for(i = 0; i < kNumShares; i++)
    {
        S4KeyContextRef decodedCtx =  kInvalidS4KeyContextRef;
        
        err = S4Key_DeserializeKeys(shareData[i], strlen((char*)shareData[i]), &keyCount, &encodedCtx ); CKERR;
        ASSERTERR(keyCount != 1,  kS4Err_SelfTestFailed);
        
        err = S4Key_DecryptFromPassPhrase(encodedCtx[0],kat->passPhrase, strlen((char*)kat->passPhrase), &decodedCtx); CKERR;
        
        err = sCompareKeys(decodedCtx, shareCtx[i]); CKERR;
        
        recoveredShares[i] = XMALLOC(sizeof(SHARES_ShareInfo)); CKNULL(recoveredShares[i]);
        COPY(&decodedCtx->share, recoveredShares[i], sizeof(SHARES_ShareInfo));
        
        S4Key_Free(decodedCtx);
        
        S4Key_Free(encodedCtx[0]);
        XFREE(encodedCtx);
        encodedCtx = NULL;
    }
    
    OPTESTLogVerbose("%14s", "Reconstruct");
    err = SHARES_CombineShareInfo(kNumShares, recoveredShares, PT1, sizeof(PT1), &PT1len); CKERR;
    
    err = compare2Results( kat->key, kat->keysize >>3 ,PT1 ,PT1len, kResultFormat_Byte, "reconstructed key"); CKERR;
    
done:

    if(encodedCtx)
    {
        if(S4KeyContextRefIsValid(encodedCtx[0]))
        {
            S4Key_Free(encodedCtx[0]);
        }
        XFREE(encodedCtx);
    }
    
    
    for(i = 0; i < kNumShares; i++)
    {
        if(shares[i])
            XFREE(shares[i]);
        
        if(S4KeyContextRefIsValid(shareCtx[i]))
            S4Key_Free(shareCtx[i]);
        
        if(shareData[i])
            XFREE(shareData[i]);
        
        if(recoveredShares[i])
            XFREE(recoveredShares[i]);
        
    }
    
    if(SHARES_ContextRefIsValid(ctx))
        SHARES_Free(ctx);
    
    OPTESTLogVerbose("\n");
    
    return err;
}

static S4Err sRunSharedECCImportExportKAT(  cipherKATvector *kat)
{
    
#define kNumShares				8
#define kShareThreshold			6
    
    S4Err               err = kS4Err_NoErr;
    ECC_ContextRef      eccPub = kInvalidECC_ContextRef;
    ECC_ContextRef      eccPriv = kInvalidECC_ContextRef;
    
    
    SHARES_ContextRef   ctx  			= kInvalidSHARES_ContextRef;
    SHARES_ShareInfo*   shares[kNumShares] = {NULL};
    SHARES_ShareInfo*   recoveredShares[kNumShares] = {NULL};
    
    S4KeyContextRef     shareCtx[kNumShares] = {kInvalidS4KeyContextRef};
    uint8_t*            shareData[kNumShares] = {NULL};
    
    S4KeyContextRef *encodedCtx =  NULL;
    size_t          keyCount = 0;
    
    uint8_t             keyID[kS4Key_KeyIDBytes]  = {0};
    size_t              keyIDLen = 0;
    
    uint8_t             keyID1[kS4Key_KeyIDBytes] = {0};
    size_t              keyIDLen1 = 0;
    
    uint8_t             PT1[128];
    size_t              PT1len;
    
    int                 i;
    char* name = NULL;
    
    
    uint8_t ecc414_pubkey[] = {
        0x04,0x06,0x8b,0x14,0xa4,0x14,0x6a,0x2a,
        0x3d,0xab,0x05,0xda,0xdf,0x75,0xef,0x5f,
        0xaf,0x7c,0xbf,0x8e,0x92,0x75,0x6c,0xe4,
        0x9f,0x93,0x69,0x6e,0x42,0x15,0x2e,0x9d,
        0xb2,0xde,0xd7,0xf0,0x79,0xbe,0xb6,0x12,
        0x1a,0x73,0x70,0x17,0x15,0x93,0x6f,0xa4,
        0x2c,0xbf,0x21,0x99,0xb6,0x23,0xa7,0xb7,
        0x0e,0x15,0x35,0x0d,0xf5,0x0e,0xc7,0xa0,
        0x2e,0xcf,0x66,0xac,0x65,0x3b,0x5c,0xf6,
        0x19,0xa1,0xdb,0x16,0x41,0x7f,0xef,0xb4,
        0x19,0x6a,0xd1,0xa4,0x91,0x4c,0x4e,0x6a,
        0x11,0xb6,0xfd,0xfa,0x90,0x11,0x13,0x10,
        0x0f,0x64,0xaf,0x65,0x0a,0x74,0x85,0x53,
        0x0d};
    
    
    uint8_t ecc414_privkey[] = {
        0x30,0x81,0xa9,0x03,0x02,0x07,0x80,0x02,
        0x01,0x34,0x02,0x34,0x06,0x8b,0x14,0xa4,
        0x14,0x6a,0x2a,0x3d,0xab,0x05,0xda,0xdf,
        0x75,0xef,0x5f,0xaf,0x7c,0xbf,0x8e,0x92,
        0x75,0x6c,0xe4,0x9f,0x93,0x69,0x6e,0x42,
        0x15,0x2e,0x9d,0xb2,0xde,0xd7,0xf0,0x79,
        0xbe,0xb6,0x12,0x1a,0x73,0x70,0x17,0x15,
        0x93,0x6f,0xa4,0x2c,0xbf,0x21,0x99,0xb6,
        0x02,0x34,0x23,0xa7,0xb7,0x0e,0x15,0x35,
        0x0d,0xf5,0x0e,0xc7,0xa0,0x2e,0xcf,0x66,
        0xac,0x65,0x3b,0x5c,0xf6,0x19,0xa1,0xdb,
        0x16,0x41,0x7f,0xef,0xb4,0x19,0x6a,0xd1,
        0xa4,0x91,0x4c,0x4e,0x6a,0x11,0xb6,0xfd,
        0xfa,0x90,0x11,0x13,0x10,0x0f,0x64,0xaf,
        0x65,0x0a,0x74,0x85,0x53,0x0d,0x02,0x34,
        0x2b,0x30,0xd2,0xe0,0x76,0xfd,0x09,0x6b,
        0xcc,0xd2,0xeb,0x4b,0x8d,0x45,0xa8,0x68,
        0xea,0xf5,0xd3,0x49,0xe3,0xf8,0x44,0xf5,
        0xad,0xe7,0xd7,0x31,0x2e,0xfa,0xe1,0xd1,
        0x18,0x27,0x43,0x69,0x2c,0x9f,0xea,0x3d,
        0xc3,0x8f,0xf8,0x94,0x1d,0x53,0x48,0xe9,
        0x0a,0x33,0x59,0x90 };
    
    name = cipher_algor_table(kat->algor);
    
    err = ECC_Init(&eccPub);
    err = ECC_Import_ANSI_X963( eccPub, ecc414_pubkey, sizeof(ecc414_pubkey));CKERR;
    err = ECC_PubKeyHash(eccPub, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;
    
    err = ECC_Init(&eccPriv);
    err = ECC_Import(eccPriv, ecc414_privkey, sizeof(ecc414_privkey));CKERR;
    
    OPTESTLogVerbose("\t%-14s ", name);
    OPTESTLogVerbose("%6s", "Split");
    
    err = SHARES_Init( kat->key, kat->keysize >>3 ,
                      kNumShares,
                      kShareThreshold,
                      &ctx); CKERR;
    
    OPTESTLogVerbose("%8s", "Export");
    for(i = 0; i < kNumShares; i++)
    {
        size_t shareLen = 0;
        
        err = SHARES_GetShareInfo(ctx, i, &shares[i], &shareLen); CKERR;
        err = S4Key_NewShare( shares[i], &shareCtx[i]); CKERR;
        err = S4Key_SerializeToPubKey(shareCtx[i], eccPub, &shareData[i], NULL); CKERR;
        
        OPTESTLogDebug("\n------\n%s",shareData[i]);
        
        if(shareData[i])
        {
            asprintf(&exported_keys,"%s %s %s", exported_keys,strlen(exported_keys) > 1?",":"", shareData[i] );
            exported_key_count++;
        }

    }
    
    OPTESTLogVerbose("%8s", "Decode");
    for(i = 0; i < kNumShares; i++)
    {
        S4KeyContextRef decodedCtx =  kInvalidS4KeyContextRef;
        
        err = S4Key_DeserializeKeys(shareData[i], strlen((char*)shareData[i]), &keyCount, &encodedCtx ); CKERR;
        ASSERTERR(keyCount != 1,  kS4Err_SelfTestFailed);
        
        err = S4Key_GetProperty(encodedCtx[0], kS4KeyProp_KeyID, NULL, keyID1, sizeof(keyID1), &keyIDLen1);
        ASSERTERR(keyIDLen != keyIDLen1,  kS4Err_SelfTestFailed);
        err = compareResults( keyID, keyID1, keyIDLen,
                             kResultFormat_Byte, "Pub KeyID"); CKERR;
        
        err = S4Key_DecryptFromPubKey(encodedCtx[0], eccPriv, &decodedCtx); CKERR;
        
        err = sCompareKeys(decodedCtx, shareCtx[i]); CKERR;
        
        recoveredShares[i] = XMALLOC(sizeof(SHARES_ShareInfo)); CKNULL(recoveredShares[i]);
        COPY(&decodedCtx->share, recoveredShares[i], sizeof(SHARES_ShareInfo));
        
        S4Key_Free(decodedCtx);
        
        S4Key_Free(encodedCtx[0]);
        XFREE(encodedCtx);
        encodedCtx = NULL;
    }
    
    OPTESTLogVerbose("%14s", "Reconstruct");
    err = SHARES_CombineShareInfo(kNumShares, recoveredShares, PT1, sizeof(PT1), &PT1len); CKERR;

    err = compare2Results( kat->key, kat->keysize >>3 ,PT1 ,PT1len, kResultFormat_Byte, "reconstructed key"); CKERR;
    
 done:
    
    if(encodedCtx)
    {
        if(S4KeyContextRefIsValid(encodedCtx[0]))
        {
            S4Key_Free(encodedCtx[0]);
        }
        XFREE(encodedCtx);
    }
    
    if(eccPub)
    {
        ECC_Free(eccPub);
        eccPub = kInvalidECC_ContextRef;
    }
    
    if(eccPriv)
    {
        ECC_Free(eccPriv);
        eccPriv = kInvalidECC_ContextRef;
    }
    
    
    for(i = 0; i < kNumShares; i++)
    {
        if(shares[i])
            XFREE(shares[i]);
        
        if(S4KeyContextRefIsValid(shareCtx[i]))
            S4Key_Free(shareCtx[i]);
        
        if(shareData[i])
            XFREE(shareData[i]);
        
        if(recoveredShares[i])
            XFREE(recoveredShares[i]);
        
    }
    
    if(SHARES_ContextRefIsValid(ctx))
        SHARES_Free(ctx);
    
    OPTESTLogVerbose("\n");
    
    return err;
}



static S4Err  sTest_SharedSymTBCKeys()
{
    S4Err     err = kS4Err_NoErr;
    int i;
    
    uint8_t* passPhrase1 = (uint8_t*)"Tant las fotei com auziretz";

    /* AES 128 bit key */
    uint8_t K1[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12
    };
    
    /* AES 192 bit key */
    uint8_t K2[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
        0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C
    };
    
    /* AES 256 bit key */
    uint8_t K3[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
        0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C,
        0x1E, 0x1F, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26
    };
 
    
    /* ThreeFish 256 bit key */
    uint64_t three_256_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L
    };
    
    
    uint64_t three_512_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L
    };
    
    //
    //    uint64_t three_1024_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
    //        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
    //        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L,
    //        0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L,
    //        0x6F6E6D6C6B6A6968L, 0x7776757473727170L, 0x7F7E7D7C7B7A7978L,
    //        0x8786858483828180L, 0x8F8E8D8C8B8A8988L
    //    };
    
 
    cipherKATvector kat_vector_array[] =
    {
        {"Key 1",       kCipher_Algorithm_AES128, 128,	K1, passPhrase1},
        {"Key 2",       kCipher_Algorithm_AES192, 192,	K2, passPhrase1},
        {"Key 3",       kCipher_Algorithm_AES256, 256,   K3, passPhrase1},
        {"Key 4",       kCipher_Algorithm_2FISH256, 256,   K3, passPhrase1},
        {"TBC Key 256",	kCipher_Algorithm_3FISH256,   256,   (void*)  three_256_key , passPhrase1 },
        {"TBC Key 512",	kCipher_Algorithm_3FISH512,   512,   (void*)  three_512_key , passPhrase1 },
        
        // we dont support ECC encytion of the kCipher_Algorithm_3FISH1024 keys, Too big!
        
        //         {	kCipher_Algorithm_3FISH1024,  1024,  three_1024_key, NULL, NULL  },

    };

    OPTESTLogInfo("\nTesting Shared ECC Encrypted Symmetric and TBC S4Key Encoding\n");
      /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunSharedECCImportExportKAT( &kat_vector_array[i] ); CKERR;
    }

    OPTESTLogInfo("\nTesting Shared PBKDF2 Encrypted Symmetric and TBC S4Key Encoding\n");
     /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunSharedPBKDF2ImportExportKAT( &kat_vector_array[i] ); CKERR;
    }

done:
    return err;
}

static S4Err sRunTBCImportExportKAT(  cipherKATvector *kat)
{
    S4Err err = kS4Err_NoErr;
    S4KeyContextRef keyCtx =  kInvalidS4KeyContextRef;
    S4KeyContextRef keyCtx1=  kInvalidS4KeyContextRef;
    S4KeyContextRef passKeyCtx =  kInvalidS4KeyContextRef;

    S4KeyContextRef  *importCtx = NULL;
    
    uint8_t         unlockingKey[32];

    size_t      keyCount = 0;
    
    char* name = NULL;
    
    uint8_t     *data = NULL;
    size_t      dataLen = 0;
    time_t          testDate  = time(NULL) ;
    
    name = cipher_algor_table(kat->algor);
    
    OPTESTLogVerbose("\t%-14s ", name);
    
    OPTESTLogVerbose("%8s", "Export");
    
    // create a random  unlocking key
    err = RNG_GetBytes(unlockingKey, sizeof(unlockingKey)); CKERR;
    
    err = S4Key_NewSymmetric(kCipher_Algorithm_2FISH256, unlockingKey, &passKeyCtx  ); CKERR;

    err = S4Key_NewTBC(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = S4Key_SetProperty(keyCtx,kS4KeyProp_TestPassCodeID,S4KeyPropertyType_UTF8String, kat->comment, strlen(kat->comment)); CKERR;
    err = S4Key_SetProperty(keyCtx, kS4KeyProp_Time, S4KeyPropertyType_Time ,  &testDate, sizeof(time_t)); CKERR;
    
    err = S4Key_SerializeToS4Key(keyCtx, passKeyCtx, &data, &dataLen); CKERR;
    
    OPTESTLogDebug("\n------\n%s------\n",data);
    
    OPTESTLogVerbose("%8s", "Import");
    err = S4Key_DeserializeKeys(data, dataLen, &keyCount, &importCtx ); CKERR;
    ASSERTERR(keyCount != 1,  kS4Err_SelfTestFailed);
    
    OPTESTLogVerbose("%8s", "Verify");
    err = S4Key_DecryptFromS4Key(importCtx[0], passKeyCtx , &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;
    
    if(data)
    {
        asprintf(&exported_keys,"%s %s %s", exported_keys,strlen(exported_keys) > 1?",":"", data );
        exported_key_count++;
    }

done:
    
    if(data)
        XFREE(data);
    
    if(S4KeyContextRefIsValid(keyCtx))
    {
        S4Key_Free(keyCtx);
    }
    
    if(importCtx)
    {
        if(S4KeyContextRefIsValid(importCtx[0]))
        {
            S4Key_Free(importCtx[0]);
        }
        XFREE(importCtx);
        
    }
    
    if(S4KeyContextRefIsValid(passKeyCtx))
    {
        S4Key_Free(passKeyCtx);
    }
    
    if(S4KeyContextRefIsValid(keyCtx1))
    {
        S4Key_Free(keyCtx1);
    }
    
    
    OPTESTLogVerbose("\n");
    
    return err;

}

static S4Err sRunTBCPBKDF2ImportExportKAT(  cipherKATvector *kat)
{
    S4Err err = kS4Err_NoErr;
    S4KeyContextRef keyCtx =  kInvalidS4KeyContextRef;
    S4KeyContextRef keyCtx1=  kInvalidS4KeyContextRef;
    S4KeyContextRef  *passCtx = NULL;
    size_t      keyCount = 0;
 
    char* name = NULL;
    
    uint8_t     *data = NULL;
    size_t      dataLen = 0;
     
    name = cipher_algor_table(kat->algor);
    
    OPTESTLogVerbose("\t%-14s ", name);
    
    OPTESTLogVerbose("%8s", "Export");
    
    err = S4Key_NewTBC(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = S4Key_SerializeToPassPhrase(keyCtx, kat->passPhrase, strlen((char*)kat->passPhrase), &data, &dataLen); CKERR;
    err = S4Key_SetProperty(keyCtx,kS4KeyProp_TestPassCodeID,S4KeyPropertyType_UTF8String, kat->comment, strlen(kat->comment)); CKERR;
    
    OPTESTLogDebug("\n------\n%s------\n",data);

    OPTESTLogVerbose("%8s", "Import");
    err = S4Key_DeserializeKeys(data, dataLen, &keyCount, &passCtx ); CKERR;
    
  //  sDumpS4Key(OPTESTLOG_LEVEL_DEBUG, passCtx);

    OPTESTLogVerbose("%8s", "Verify");
    err = S4Key_VerifyPassPhrase(passCtx[0], kat->passPhrase, strlen((char*)kat->passPhrase)); CKERR;
    
    err = S4Key_DecryptFromPassPhrase(passCtx[0],kat->passPhrase, strlen((char*)kat->passPhrase), &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;
    
done:
    
    if(data)
        XFREE(data);

    if(S4KeyContextRefIsValid(keyCtx))
    {
        S4Key_Free(keyCtx);
    }
    if(passCtx)
    {
        if(S4KeyContextRefIsValid(passCtx[0]))
        {
            S4Key_Free(passCtx[0]);
        }
        XFREE(passCtx);
        
    }
    if(S4KeyContextRefIsValid(keyCtx1))
    {
        S4Key_Free(keyCtx1);
    }

    
    OPTESTLogVerbose("\n");
    
    return err;
}


static S4Err  sTestTBCKeys()
{
    S4Err     err = kS4Err_NoErr;
    int i;
    
    
    uint8_t* passPhrase1 =  (uint8_t*)"Tant las fotei com auziretz";
    
//    uint64_t three_256_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
 
    /* ThreeFish 256 bit key */
    uint64_t three_256_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L
    };
 
    
    uint64_t three_512_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L
    };
    
 //   uint64_t three_512_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
    

    uint64_t three_1024_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L,
        0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L,
        0x6F6E6D6C6B6A6968L, 0x7776757473727170L, 0x7F7E7D7C7B7A7978L,
        0x8786858483828180L, 0x8F8E8D8C8B8A8988L
    };
//    uint64_t three_1024_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
    
    
    cipherKATvector kat_vector_array[] =
    {
        {"TBC Key 256", kCipher_Algorithm_3FISH256,   256,   (void*)  three_256_key , passPhrase1 },
        {"TBC Key 512", kCipher_Algorithm_3FISH512,   512,   (void*)  three_512_key , passPhrase1 },
        {"TBC Key 1K",	kCipher_Algorithm_3FISH1024,  1024,  (void*) three_1024_key  , passPhrase1  },
    };
    
    
    
    OPTESTLogInfo("\nTesting TBC S4Key Import / Export\n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunTBCImportExportKAT( &kat_vector_array[i] ); CKERR;
    }

    OPTESTLogInfo("\nTesting PBKDF2 TBC S4Key Import / Export\n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunTBCPBKDF2ImportExportKAT( &kat_vector_array[i] ); CKERR;
    }
    
    
done:
    return err;
}




static S4Err sRunCipherECCImportExportKAT(  cipherKATvector *kat)
{
    S4Err     err = kS4Err_NoErr;
    ECC_ContextRef eccPub = kInvalidECC_ContextRef;
    ECC_ContextRef eccPriv = kInvalidECC_ContextRef;
    
    S4KeyContextRef keyCtx =  kInvalidS4KeyContextRef;
    S4KeyContextRef keyCtx1=  kInvalidS4KeyContextRef;
    S4KeyContextRef *encodedCtx =  NULL;
    size_t          keyCount = 0;
    
    uint8_t             keyID[kS4Key_KeyIDBytes]  = {0};
    size_t              keyIDLen = 0;
    
    uint8_t             keyID1[kS4Key_KeyIDBytes] = {0};
    size_t              keyIDLen1 = 0;

    uint8_t     *data = NULL;
    size_t      dataLen = 0;
    char* name = NULL;
    
    uint8_t ecc414_pubkey[] = {
        0x04,0x06,0x8b,0x14,0xa4,0x14,0x6a,0x2a,
        0x3d,0xab,0x05,0xda,0xdf,0x75,0xef,0x5f,
        0xaf,0x7c,0xbf,0x8e,0x92,0x75,0x6c,0xe4,
        0x9f,0x93,0x69,0x6e,0x42,0x15,0x2e,0x9d,
        0xb2,0xde,0xd7,0xf0,0x79,0xbe,0xb6,0x12,
        0x1a,0x73,0x70,0x17,0x15,0x93,0x6f,0xa4,
        0x2c,0xbf,0x21,0x99,0xb6,0x23,0xa7,0xb7,
        0x0e,0x15,0x35,0x0d,0xf5,0x0e,0xc7,0xa0,
        0x2e,0xcf,0x66,0xac,0x65,0x3b,0x5c,0xf6,
        0x19,0xa1,0xdb,0x16,0x41,0x7f,0xef,0xb4,
        0x19,0x6a,0xd1,0xa4,0x91,0x4c,0x4e,0x6a,
        0x11,0xb6,0xfd,0xfa,0x90,0x11,0x13,0x10,
        0x0f,0x64,0xaf,0x65,0x0a,0x74,0x85,0x53,
        0x0d};
    
    
    uint8_t ecc414_privkey[] = {
        0x30,0x81,0xa9,0x03,0x02,0x07,0x80,0x02,
        0x01,0x34,0x02,0x34,0x06,0x8b,0x14,0xa4,
        0x14,0x6a,0x2a,0x3d,0xab,0x05,0xda,0xdf,
        0x75,0xef,0x5f,0xaf,0x7c,0xbf,0x8e,0x92,
        0x75,0x6c,0xe4,0x9f,0x93,0x69,0x6e,0x42,
        0x15,0x2e,0x9d,0xb2,0xde,0xd7,0xf0,0x79,
        0xbe,0xb6,0x12,0x1a,0x73,0x70,0x17,0x15,
        0x93,0x6f,0xa4,0x2c,0xbf,0x21,0x99,0xb6,
        0x02,0x34,0x23,0xa7,0xb7,0x0e,0x15,0x35,
        0x0d,0xf5,0x0e,0xc7,0xa0,0x2e,0xcf,0x66,
        0xac,0x65,0x3b,0x5c,0xf6,0x19,0xa1,0xdb,
        0x16,0x41,0x7f,0xef,0xb4,0x19,0x6a,0xd1,
        0xa4,0x91,0x4c,0x4e,0x6a,0x11,0xb6,0xfd,
        0xfa,0x90,0x11,0x13,0x10,0x0f,0x64,0xaf,
        0x65,0x0a,0x74,0x85,0x53,0x0d,0x02,0x34,
        0x2b,0x30,0xd2,0xe0,0x76,0xfd,0x09,0x6b,
        0xcc,0xd2,0xeb,0x4b,0x8d,0x45,0xa8,0x68,
        0xea,0xf5,0xd3,0x49,0xe3,0xf8,0x44,0xf5,
        0xad,0xe7,0xd7,0x31,0x2e,0xfa,0xe1,0xd1,
        0x18,0x27,0x43,0x69,0x2c,0x9f,0xea,0x3d,
        0xc3,0x8f,0xf8,0x94,0x1d,0x53,0x48,0xe9,
        0x0a,0x33,0x59,0x90 };
    
    name = cipher_algor_table(kat->algor);
    
    err = ECC_Init(&eccPub);
    err = ECC_Import_ANSI_X963( eccPub, ecc414_pubkey, sizeof(ecc414_pubkey));CKERR;
    err = ECC_PubKeyHash(eccPub, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;

    err = ECC_Init(&eccPriv);
    err = ECC_Import(eccPriv, ecc414_privkey, sizeof(ecc414_privkey));CKERR;

    OPTESTLogVerbose("\t%-14s ", name);
    OPTESTLogVerbose("%8s", "Export");

    err = S4Key_NewSymmetric(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = S4Key_SerializeToPubKey(keyCtx, eccPub, &data, &dataLen); CKERR;
    
    OPTESTLogDebug("\n------\n%s------\n",data);
    
    OPTESTLogVerbose("%8s", "Import");
    err = S4Key_DeserializeKeys(data, dataLen, &keyCount, &encodedCtx ); CKERR;
    
    err = S4Key_GetProperty(encodedCtx[0], kS4KeyProp_KeyID, NULL, keyID1, sizeof(keyID1), &keyIDLen1);
    ASSERTERR(keyIDLen != keyIDLen1,  kS4Err_SelfTestFailed);
    err = compareResults( keyID, keyID1, keyIDLen,
                         kResultFormat_Byte, "Pub KeyID"); CKERR;
    
    OPTESTLogVerbose("%8s", "Verify");
    err = S4Key_DecryptFromPubKey(encodedCtx[0], eccPriv, &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;

    if(data)
    {
        asprintf(&exported_keys,"%s %s %s", exported_keys,strlen(exported_keys) > 1?",":"", data );
        exported_key_count++;
    }
    
done:
    
    if(eccPub)
    {
        ECC_Free(eccPub);
        eccPub = kInvalidECC_ContextRef;
    }
    
    if(eccPriv)
    {
        ECC_Free(eccPriv);
        eccPriv = kInvalidECC_ContextRef;
    }
    
    if(keyCtx)
    {
        S4Key_Free(keyCtx);
    }
    if(keyCtx1)
    {
        S4Key_Free(keyCtx1);
    }
    
    if(encodedCtx)
    {
        if(S4KeyContextRefIsValid(encodedCtx[0]))
        {
            S4Key_Free(encodedCtx[0]);
        }
        XFREE(encodedCtx);
        
    }
    
     OPTESTLogVerbose("\n");

    return err;
}


static S4Err  sTestECC_SymmetricKeys()
{
    S4Err     err = kS4Err_NoErr;
    int i;
    
     /* AES 128 bit key */
    uint8_t K1[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12
    };
    
    /* AES 192 bit key */
    uint8_t K2[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
        0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C
    };
    
    /* AES 256 bit key */
    uint8_t K3[] = {
        0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0x11, 0x12,
        0x14, 0x15, 0x16, 0x17, 0x19, 0x1A, 0x1B, 0x1C,
        0x1E, 0x1F, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26
    };
    
    cipherKATvector kat_vector_array[] =
    {
        {"Key 1",	kCipher_Algorithm_AES128, 128,	K1, NULL},
        {"Key 2",    kCipher_Algorithm_AES192, 192,	K2, NULL},
        {"Key 3",   kCipher_Algorithm_AES256, 256,   K3, NULL},
        {"Key 4",   kCipher_Algorithm_2FISH256, 256,   K3, NULL},
    };
    
    OPTESTLogInfo("\nTesting ECC Symmetric S4Key Encoding \n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunCipherECCImportExportKAT( &kat_vector_array[i] ); CKERR;
    }
    
    
done:
    return err;
}


static S4Err sRunTBC_ECCImportExportKAT(  cipherKATvector *kat)
{
    S4Err     err = kS4Err_NoErr;
    ECC_ContextRef eccPub = kInvalidECC_ContextRef;
    ECC_ContextRef eccPriv = kInvalidECC_ContextRef;
    
    S4KeyContextRef keyCtx =  kInvalidS4KeyContextRef;
    S4KeyContextRef keyCtx1=  kInvalidS4KeyContextRef;
    S4KeyContextRef *encodedCtx =  NULL;
    size_t          keyCount = 0;
    
    uint8_t             keyID[kS4Key_KeyIDBytes]  = {0};
    size_t              keyIDLen = 0;
    
    uint8_t             keyID1[kS4Key_KeyIDBytes] = {0};
    size_t              keyIDLen1 = 0;

    uint8_t     *data = NULL;
    size_t      dataLen = 0;
    char* name = NULL;
    
    uint8_t ecc414_pubkey[] = {
        0x04,0x06,0x8b,0x14,0xa4,0x14,0x6a,0x2a,
        0x3d,0xab,0x05,0xda,0xdf,0x75,0xef,0x5f,
        0xaf,0x7c,0xbf,0x8e,0x92,0x75,0x6c,0xe4,
        0x9f,0x93,0x69,0x6e,0x42,0x15,0x2e,0x9d,
        0xb2,0xde,0xd7,0xf0,0x79,0xbe,0xb6,0x12,
        0x1a,0x73,0x70,0x17,0x15,0x93,0x6f,0xa4,
        0x2c,0xbf,0x21,0x99,0xb6,0x23,0xa7,0xb7,
        0x0e,0x15,0x35,0x0d,0xf5,0x0e,0xc7,0xa0,
        0x2e,0xcf,0x66,0xac,0x65,0x3b,0x5c,0xf6,
        0x19,0xa1,0xdb,0x16,0x41,0x7f,0xef,0xb4,
        0x19,0x6a,0xd1,0xa4,0x91,0x4c,0x4e,0x6a,
        0x11,0xb6,0xfd,0xfa,0x90,0x11,0x13,0x10,
        0x0f,0x64,0xaf,0x65,0x0a,0x74,0x85,0x53,
        0x0d};
    
    
    uint8_t ecc414_privkey[] = {
        0x30,0x81,0xa9,0x03,0x02,0x07,0x80,0x02,
        0x01,0x34,0x02,0x34,0x06,0x8b,0x14,0xa4,
        0x14,0x6a,0x2a,0x3d,0xab,0x05,0xda,0xdf,
        0x75,0xef,0x5f,0xaf,0x7c,0xbf,0x8e,0x92,
        0x75,0x6c,0xe4,0x9f,0x93,0x69,0x6e,0x42,
        0x15,0x2e,0x9d,0xb2,0xde,0xd7,0xf0,0x79,
        0xbe,0xb6,0x12,0x1a,0x73,0x70,0x17,0x15,
        0x93,0x6f,0xa4,0x2c,0xbf,0x21,0x99,0xb6,
        0x02,0x34,0x23,0xa7,0xb7,0x0e,0x15,0x35,
        0x0d,0xf5,0x0e,0xc7,0xa0,0x2e,0xcf,0x66,
        0xac,0x65,0x3b,0x5c,0xf6,0x19,0xa1,0xdb,
        0x16,0x41,0x7f,0xef,0xb4,0x19,0x6a,0xd1,
        0xa4,0x91,0x4c,0x4e,0x6a,0x11,0xb6,0xfd,
        0xfa,0x90,0x11,0x13,0x10,0x0f,0x64,0xaf,
        0x65,0x0a,0x74,0x85,0x53,0x0d,0x02,0x34,
        0x2b,0x30,0xd2,0xe0,0x76,0xfd,0x09,0x6b,
        0xcc,0xd2,0xeb,0x4b,0x8d,0x45,0xa8,0x68,
        0xea,0xf5,0xd3,0x49,0xe3,0xf8,0x44,0xf5,
        0xad,0xe7,0xd7,0x31,0x2e,0xfa,0xe1,0xd1,
        0x18,0x27,0x43,0x69,0x2c,0x9f,0xea,0x3d,
        0xc3,0x8f,0xf8,0x94,0x1d,0x53,0x48,0xe9,
        0x0a,0x33,0x59,0x90 };
    
    
    name = cipher_algor_table(kat->algor);
    
    err = ECC_Init(&eccPub);
    err = ECC_Import_ANSI_X963( eccPub, ecc414_pubkey, sizeof(ecc414_pubkey));CKERR;
    err = ECC_PubKeyHash(eccPub, keyID, kS4Key_KeyIDBytes, &keyIDLen);CKERR;

    err = ECC_Init(&eccPriv);
    err = ECC_Import(eccPriv, ecc414_privkey, sizeof(ecc414_privkey));CKERR;
    
    OPTESTLogVerbose("\t%-14s ", name);
    OPTESTLogVerbose("%8s", "Export");
    
    err = S4Key_NewTBC(kat->algor, kat->key, &keyCtx  ); CKERR;
   
    err = S4Key_SerializeToPubKey(keyCtx, eccPub, &data, &dataLen); CKERR;
    
    OPTESTLogDebug("\n------\n%s------\n",data);
    
    OPTESTLogVerbose("%8s", "Import");
    err = S4Key_DeserializeKeys(data, dataLen, &keyCount, &encodedCtx ); CKERR;
    
    err = S4Key_GetProperty(encodedCtx[0], kS4KeyProp_KeyID, NULL, keyID1, sizeof(keyID1), &keyIDLen1);
    ASSERTERR(keyIDLen != keyIDLen1,  kS4Err_SelfTestFailed);
    err = compareResults( keyID, keyID1, keyIDLen,
                         kResultFormat_Byte, "Pub KeyID"); CKERR;
    
    OPTESTLogVerbose("%8s", "Verify");
    err = S4Key_DecryptFromPubKey(encodedCtx[0], eccPriv, &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;

    if(data)
    {
        asprintf(&exported_keys,"%s %s %s", exported_keys,strlen(exported_keys) > 1?",":"", data );
        exported_key_count++;
    }
    
    
done:
    if(eccPub)
    {
        ECC_Free(eccPub);
        eccPub = kInvalidECC_ContextRef;
    }
    
    if(eccPriv)
    {
        ECC_Free(eccPriv);
        eccPriv = kInvalidECC_ContextRef;
    }
    
    if(keyCtx)
    {
        S4Key_Free(keyCtx);
    }
    if(keyCtx1)
    {
        S4Key_Free(keyCtx1);
    }
    if(encodedCtx)
    {
        if(S4KeyContextRefIsValid(encodedCtx[0]))
        {
            S4Key_Free(encodedCtx[0]);
        }
        XFREE(encodedCtx);
        
    }
    
    OPTESTLogVerbose("\n");
    
    return err;
}



static S4Err  sTestECC_TBCKeys()
{
    S4Err     err = kS4Err_NoErr;
    int i;

    
    /* ThreeFish 256 bit key */
    uint64_t three_256_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L
    };
    
    
    uint64_t three_512_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L
    };
    
//    
//    uint64_t three_1024_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
//        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
//        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L,
//        0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L,
//        0x6F6E6D6C6B6A6968L, 0x7776757473727170L, 0x7F7E7D7C7B7A7978L,
//        0x8786858483828180L, 0x8F8E8D8C8B8A8988L
//    };
    
    cipherKATvector kat_vector_array[] =
    {
        {"TBC Key 256",	kCipher_Algorithm_3FISH256,   256,     (void*)three_256_key, NULL },
        {"TBC Key 512",	kCipher_Algorithm_3FISH512,   512,     (void*)three_512_key, NULL },
        
// we dont support ECC encytion of the kCipher_Algorithm_3FISH1024 keys, Too big!
        
//         {	kCipher_Algorithm_3FISH1024,  1024,  three_1024_key, NULL, NULL  },
    };
    
    OPTESTLogInfo("\nTesting ECC TCC S4Key Import / Export\n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunTBC_ECCImportExportKAT( &kat_vector_array[i] ); CKERR;
    }
    
done:
    return err;

}

S4Err  TestKeys()
{
    S4Err     err = kS4Err_NoErr;
    S4KeyContextRef *encodedCtx =  NULL;
    size_t          keyCount = 0;
    int i;
    
    asprintf(&exported_keys,"[" );

    err = sTestSymmetricKeys(); CKERR;
    err = sTestTBCKeys(); CKERR;
    err = sTestECC_TBCKeys(); CKERR;
    err = sTestECC_SymmetricKeys(); CKERR;

    err = sTest_SharedSymTBCKeys(); CKERR;
    

    OPTESTLogInfo("\nTesting decoding of exported key array\n");
    asprintf(&exported_keys,"%s ]", exported_keys );
    err = S4Key_DeserializeKeys((uint8_t*)exported_keys, strlen(exported_keys), &keyCount, &encodedCtx ); CKERR;
    OPTESTLogInfo("\tDecoded %d Items\n", keyCount);
    ASSERTERR(keyCount != exported_key_count, kS4Err_SelfTestFailed);
    
    for(i = 0; i < keyCount; i++)
    {
        if(S4KeyContextRefIsValid(encodedCtx[i]))
        {
            S4KeyContextRef keyP = encodedCtx[i];
            
            S4KeyType   type1;
            char**       keyIDStr = NULL;
            
            err = S4Key_GetProperty(keyP, kS4KeyProp_KeyType, NULL, &type1, sizeof(type1), NULL ); CKERR;
            switch (type1) {
                case kS4KeyType_PBKDF2:
                    err = SCKeyGetAllocatedProperty(keyP, kS4KeyProp_TestPassCodeID, NULL, (void**)&keyIDStr, NULL);
                    OPTESTLogDebug("\t%2d %10s %s\n", i,  key_type_table(type1), keyIDStr);
                    break;
                    
                case kS4KeyType_PublicEncrypted:
                     err = SCKeyGetAllocatedProperty(keyP, kS4KeyProp_KeyIDString, NULL, (void**)&keyIDStr, NULL); CKERR;
                    OPTESTLogDebug("\t%2d %10s %s\n", i,  key_type_table(type1), keyIDStr);
                    
                break;
                    
                default:
                    break;
            }
            
            if(keyIDStr) XFREE(keyIDStr);
            
        }
    }
    
    
done:
    
    if(encodedCtx)
    {
       
        for(i = 0; i < keyCount; i++)
            if(S4KeyContextRefIsValid(encodedCtx[i]))
            {
                S4Key_Free(encodedCtx[i]);
            }
        XFREE(encodedCtx);
    }
 
    if(exported_keys)
        free(exported_keys);
    
    return err;
    
}