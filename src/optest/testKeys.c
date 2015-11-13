//
//  testKeys.c
//  C4
//
//  Created by vincent Moscaritolo on 11/9/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include <stdio.h>
#include "c4.h"
#include "optest.h"



typedef struct  {
    Cipher_Algorithm    algor;
    int                 keysize;
    uint8_t             *key;
    char                *passPhrase;
    
} cipherKATvector;

//static char *new_str;

static C4Err sCompareKeys( C4KeyContext  *keyCtx, C4KeyContext  *keyCtx1)
{
    C4Err err = kC4Err_NoErr;
    
    ValidateParam(keyCtx);
    ValidateParam(keyCtx1);
    
    ASSERTERR(keyCtx->type != keyCtx1->type,  kC4Err_SelfTestFailed);
    
    switch (keyCtx->type) {
        case kC4KeyType_Symmetric:
            ASSERTERR(keyCtx->sym.symAlgor != keyCtx1->sym.symAlgor,  kC4Err_SelfTestFailed);
            ASSERTERR(keyCtx->sym.keylen != keyCtx1->sym.keylen,  kC4Err_SelfTestFailed);
            err = compareResults( keyCtx->sym.symKey, keyCtx1->sym.symKey, keyCtx->sym.keylen,
                                 kResultFormat_Byte, "Symmetric key"); CKERR;
            
            break;
            
        case kC4KeyType_Tweekable:
            ASSERTERR(keyCtx->tbc.tbcAlgor != keyCtx1->tbc.tbcAlgor,  kC4Err_SelfTestFailed);
            ASSERTERR(keyCtx->tbc.keybits != keyCtx1->tbc.keybits,  kC4Err_SelfTestFailed);
            err = compareResults( keyCtx->tbc.key, keyCtx1->tbc.key, keyCtx->tbc.keybits >>3,
                                 kResultFormat_Long, "TBC key"); CKERR;
            
            break;
            
        case kC4KeyType_PBKDF2:
            switch (keyCtx->pbkdf2.keyAlgorithmType)
        {
            case kC4KeyType_Symmetric:
                 break;
                
            case kC4KeyType_Tweekable:
                 break;
                
            default:;
                
        };
            break;
            
        default:
            err = kC4Err_UnknownError;
            break;
    }

    

done:
    return err;
}


static C4Err sRunCipherImportExportKAT(  cipherKATvector *kat)
{
    C4Err err = kC4Err_NoErr;
    C4KeyContextRef keyCtx =  kInvalidC4KeyContextRef;
    C4KeyContextRef keyCtx1 =  kInvalidC4KeyContextRef;
    C4KeyContextRef passCtx =  kInvalidC4KeyContextRef;
    char* name = NULL;
    
    uint8_t     *data = NULL;
    size_t      dataLen = 0;
    
    
    name = cipher_algor_table(kat->algor);
    
    OPTESTLogInfo("\t%-14s ", name);
    OPTESTLogInfo("%8s", "Export");
    
    err = C4Key_NewSymmetric(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = C4Key_SerializeToPassPhrase(keyCtx, kat->passPhrase, strlen(kat->passPhrase), &data, &dataLen); CKERR;
    
      OPTESTLogDebug("\n------\n%s------\n",data);
    
    OPTESTLogInfo("%8s", "Import");
    err = C4Key_Deserialize(data, dataLen,&passCtx ); CKERR;
    
 //   sDumpC4Key(OPTESTLOG_LEVEL_DEBUG, passCtx);
    
    OPTESTLogInfo("%8s", "Verify");
    err = C4Key_VerifyPassPhrase(passCtx, kat->passPhrase, strlen(kat->passPhrase)); CKERR;

//    asprintf(&new_str,"%s %s %s", new_str,strlen(new_str) > 1?",":"", data );

   err = C4Key_DecryptFromPassPhrase(passCtx,kat->passPhrase, strlen(kat->passPhrase), &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;
    
done:
    if(data)
        XFREE(data);
 
    if(C4KeyContextRefIsValid(keyCtx))
    {
        C4Key_Free(keyCtx);
    }
    if(C4KeyContextRefIsValid(passCtx))
    {
        C4Key_Free(passCtx);
    }
    if(C4KeyContextRefIsValid(keyCtx1))
    {
        C4Key_Free(keyCtx1);
    }
  
    OPTESTLogInfo("\n");

    return err;
}


static C4Err  sTestSymmetricKeys()
{
    C4Err     err = kC4Err_NoErr;
    int i;
    
    char* passPhrase1 = "Tant las fotei com auziretz";
   
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
        {	kCipher_Algorithm_AES128, 128,	K1, passPhrase1},
        {	kCipher_Algorithm_AES192, 192,	K2, passPhrase1},
        {	kCipher_Algorithm_AES256, 256,   K3, passPhrase1},
        {	kCipher_Algorithm_2FISH256, 256,   K3, passPhrase1},
    };
    
    OPTESTLogInfo("\nTesting C4 PBKDF2 Symmetric Key Encoding\n");

    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunCipherImportExportKAT( &kat_vector_array[i] ); CKERR;
      }
    
  
done:
     return err;
}


typedef struct  {
    TBC_Algorithm   algor;
    int            keysize;
    uint64_t*        key;
    uint64_t*        tweek;		/* tweek	*/
    char                *passPhrase;

 } tbcKATvector;



static C4Err sRunTBCImportExportKAT(  tbcKATvector *kat)
{
    C4Err err = kC4Err_NoErr;
    C4KeyContextRef keyCtx =  kInvalidC4KeyContextRef;
    C4KeyContextRef keyCtx1=  kInvalidC4KeyContextRef;
    C4KeyContextRef passCtx =  kInvalidC4KeyContextRef;
   char* name = NULL;
    
    uint8_t     *data = NULL;
    size_t      dataLen = 0;
     
    name = tbc_algor_table(kat->algor);
    
    OPTESTLogInfo("\t%-14s ", name);
    
    OPTESTLogInfo("%8s", "Export");
    
    err = C4Key_NewTBC(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = C4Key_SerializeToPassPhrase(keyCtx, kat->passPhrase, strlen(kat->passPhrase), &data, &dataLen); CKERR;
   
    OPTESTLogDebug("\n------\n%s------\n",data);

    OPTESTLogInfo("%8s", "Import");
    err = C4Key_Deserialize(data, dataLen,&passCtx ); CKERR;

  //  sDumpC4Key(OPTESTLOG_LEVEL_DEBUG, passCtx);

    OPTESTLogInfo("%8s", "Verify");
    err = C4Key_VerifyPassPhrase(passCtx, kat->passPhrase, strlen(kat->passPhrase)); CKERR;
    
    err = C4Key_DecryptFromPassPhrase(passCtx,kat->passPhrase, strlen(kat->passPhrase), &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;
    
done:
    
    if(data)
        XFREE(data);

    if(C4KeyContextRefIsValid(keyCtx))
    {
        C4Key_Free(keyCtx);
    }
    if(C4KeyContextRefIsValid(passCtx))
    {
        C4Key_Free(passCtx);
    }
    if(C4KeyContextRefIsValid(keyCtx1))
    {
        C4Key_Free(keyCtx1);
    }

    
    OPTESTLogInfo("\n");
    
    return err;
}


static C4Err  sTestTBCKeys()
{
    C4Err     err = kC4Err_NoErr;
    int i;
    
    
    char* passPhrase1 = "Tant las fotei com auziretz";
    
    uint64_t three_256_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
 
    /* ThreeFish 256 bit key */
    uint64_t three_256_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L
    };
 
    
    uint64_t three_512_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L
    };
    
    uint64_t three_512_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
    

    uint64_t three_1024_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L,
        0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L,
        0x6F6E6D6C6B6A6968L, 0x7776757473727170L, 0x7F7E7D7C7B7A7978L,
        0x8786858483828180L, 0x8F8E8D8C8B8A8988L
    };
    uint64_t three_1024_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
    
    
    tbcKATvector kat_vector_array[] =
    {
        {	kTBC_Algorithm_3FISH256,   256,     three_256_key, three_256_tweak, passPhrase1 },
        {	kTBC_Algorithm_3FISH512,   512,     three_512_key, three_512_tweak , passPhrase1 },
         {	kTBC_Algorithm_3FISH1024,  1024,  three_1024_key, three_1024_tweak, passPhrase1  },
    };
    
    OPTESTLogInfo("\nTesting C4 TBC PBKDF2 Key Import / Export\n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(tbcKATvector) ; i++)
    {
        err = sRunTBCImportExportKAT( &kat_vector_array[i] ); CKERR;
    }
    
    
done:
    return err;
}




static C4Err sRunCipherECCImportExportKAT(  cipherKATvector *kat)
{
    C4Err     err = kC4Err_NoErr;
    ECC_ContextRef eccPub = kInvalidECC_ContextRef;
    ECC_ContextRef eccPriv = kInvalidECC_ContextRef;
    
    C4KeyContextRef keyCtx =  kInvalidC4KeyContextRef;
    C4KeyContextRef keyCtx1=  kInvalidC4KeyContextRef;
    C4KeyContextRef encodedCtx =  kInvalidC4KeyContextRef;
    
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
  
    err = ECC_Init(&eccPriv);
    err = ECC_Import(eccPriv, ecc414_privkey, sizeof(ecc414_privkey));CKERR;

    OPTESTLogInfo("\t%-14s ", name);
    OPTESTLogInfo("%8s", "Export");

    err = C4Key_NewSymmetric(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = C4Key_SerializeToPubKey(keyCtx, eccPub, &data, &dataLen); CKERR;
    
    OPTESTLogDebug("\n------\n%s------\n",data);
    
    OPTESTLogInfo("%8s", "Import");
    err = C4Key_Deserialize(data, dataLen,&encodedCtx ); CKERR;
    
    OPTESTLogInfo("%8s", "Verify");
    err = C4Key_DecryptFromPubKey(encodedCtx, eccPriv, &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;

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
        C4Key_Free(keyCtx);
    }
    if(keyCtx1)
    {
        C4Key_Free(keyCtx1);
    }
    if(encodedCtx)
    {
        C4Key_Free(encodedCtx);
    }
    
    OPTESTLogInfo("\n");

    return err;
}


static C4Err  sTestECC_SymmetricKeys()
{
    C4Err     err = kC4Err_NoErr;
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
        {	kCipher_Algorithm_AES128, 128,	K1, NULL},
        {	kCipher_Algorithm_AES192, 192,	K2, NULL},
        {	kCipher_Algorithm_AES256, 256,   K3, NULL},
        {	kCipher_Algorithm_2FISH256, 256,   K3, NULL},
    };
    
    OPTESTLogInfo("\nTesting C4 ECC Symmetric Key Encoding \n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(cipherKATvector) ; i++)
    {
        err = sRunCipherECCImportExportKAT( &kat_vector_array[i] ); CKERR;
    }
    
    
done:
    return err;
}


static C4Err sRunTBC_ECCImportExportKAT(  tbcKATvector *kat)
{
    C4Err     err = kC4Err_NoErr;
    ECC_ContextRef eccPub = kInvalidECC_ContextRef;
    ECC_ContextRef eccPriv = kInvalidECC_ContextRef;
    
    C4KeyContextRef keyCtx =  kInvalidC4KeyContextRef;
    C4KeyContextRef keyCtx1=  kInvalidC4KeyContextRef;
    C4KeyContextRef encodedCtx =  kInvalidC4KeyContextRef;
    
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
    
    
    name = tbc_algor_table(kat->algor);
    
    err = ECC_Init(&eccPub);
    err = ECC_Import_ANSI_X963( eccPub, ecc414_pubkey, sizeof(ecc414_pubkey));CKERR;
    
    err = ECC_Init(&eccPriv);
    err = ECC_Import(eccPriv, ecc414_privkey, sizeof(ecc414_privkey));CKERR;
    
    OPTESTLogInfo("\t%-14s ", name);
    OPTESTLogInfo("%8s", "Export");
    
    err = C4Key_NewTBC(kat->algor, kat->key, &keyCtx  ); CKERR;
   
    err = C4Key_SerializeToPubKey(keyCtx, eccPub, &data, &dataLen); CKERR;
    
    OPTESTLogDebug("\n------\n%s------\n",data);
    
    OPTESTLogInfo("%8s", "Import");
    err = C4Key_Deserialize(data, dataLen,&encodedCtx ); CKERR;
    
    OPTESTLogInfo("%8s", "Verify");
    err = C4Key_DecryptFromPubKey(encodedCtx, eccPriv, &keyCtx1); CKERR;
    
    err = sCompareKeys(keyCtx, keyCtx1); CKERR;

    
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
        C4Key_Free(keyCtx);
    }
    if(keyCtx1)
    {
        C4Key_Free(keyCtx1);
    }
    if(encodedCtx)
    {
        C4Key_Free(encodedCtx);
    }
    
    OPTESTLogInfo("\n");
    
    return err;
}



static C4Err  sTestECC_TBCKeys()
{
    C4Err     err = kC4Err_NoErr;
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
    
    tbcKATvector kat_vector_array[] =
    {
        {	kTBC_Algorithm_3FISH256,   256,     three_256_key, NULL, NULL },
        {	kTBC_Algorithm_3FISH512,   512,     three_512_key, NULL , NULL },
        
// we dont support ECC encytion of the kTBC_Algorithm_3FISH1024 keys, Too big!
        
//         {	kTBC_Algorithm_3FISH1024,  1024,  three_1024_key, NULL, NULL  },
    };
    
    OPTESTLogInfo("\nTesting C4 TBC ECC Key Import / Export\n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(tbcKATvector) ; i++)
    {
        err = sRunTBC_ECCImportExportKAT( &kat_vector_array[i] ); CKERR;
    }
    
done:
    return err;

}

C4Err  TestKeys()
{
    C4Err     err = kC4Err_NoErr;
  
    
 //   asprintf(&new_str,"[" );

    err = sTestSymmetricKeys(); CKERR;
    err = sTestECC_SymmetricKeys(); CKERR;
    err = sTestTBCKeys(); CKERR;
    err = sTestECC_TBCKeys(); CKERR;
 
//    asprintf(&new_str,"%s ]", new_str );

   
//    C4KeyContextRef keyCtx2 =  kInvalidC4KeyContextRef;
//    
//    err = C4Key_Deserialize(new_str, strlen(new_str),&keyCtx2 ); CKERR;

done:
        
 
//    if(new_str)
//        free(new_str);
//    
    return err;
    
}