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


static C4Err sRunCipherImportExportKAT(  cipherKATvector *kat)
{
    C4Err err = kC4Err_NoErr;
    C4KeyContextRef keyCtx =  kInvalidC4KeyContextRef;
    char* name = NULL;
    
    uint8_t     *data = NULL;
    size_t      dataLen = 0;
    
    
    name = cipher_algor_table(kat->algor);
    
    OPTESTLogInfo("\t%-14s ", name);
    
    OPTESTLogInfo("%4s", "Import");
    
    err = C4Key_NewSymmetric(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = C4Key_EncryptToPassPhrase(keyCtx, kat->passPhrase, strlen(kat->passPhrase), &data, &dataLen); CKERR;
    
    
done:
    
    if(data)
        XFREE(data);
    
    if(C4KeyContextRefIsValid(keyCtx))
    {
        C4Key_Free(keyCtx);
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
    
    OPTESTLogInfo("\nTesting C4 Symmetric Key Import / Export\n");

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
    char* name = NULL;
    
    uint8_t     *data = NULL;
    size_t      dataLen = 0;
     
    name = tbc_algor_table(kat->algor);
    
    OPTESTLogInfo("\t%-14s ", name);
    
    OPTESTLogInfo("%4s", "Import");
    
    err = C4Key_NewTBC(kat->algor, kat->key, &keyCtx  ); CKERR;
    
    err = C4Key_EncryptToPassPhrase(keyCtx, kat->passPhrase, strlen(kat->passPhrase), &data, &dataLen); CKERR;

    
done:
    
    if(C4KeyContextRefIsValid(keyCtx))
    {
        C4Key_Free(keyCtx);
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
    
//
//    uint64_t three_1024_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
//        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
//        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L,
//        0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L,
//        0x6F6E6D6C6B6A6968L, 0x7776757473727170L, 0x7F7E7D7C7B7A7978L,
//        0x8786858483828180L, 0x8F8E8D8C8B8A8988L
//    };
//    uint64_t three_1024_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
//    
    
    tbcKATvector kat_vector_array[] =
    {
        {	kTBC_Algorithm_3FISH256,   256,     three_256_key, three_256_tweak, passPhrase1 },
        {	kTBC_Algorithm_3FISH512,   512,     three_512_key, three_512_tweak , passPhrase1 },
 //        {	kTBC_Algorithm_3FISH1024,  1024,  three_1024_key, three_1024_tweak, passPhrase1  },
    };
    
    OPTESTLogInfo("\nTesting C4 TBC Key Import / Export\n");
    
    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(tbcKATvector) ; i++)
    {
        err = sRunTBCImportExportKAT( &kat_vector_array[i] ); CKERR;
    }
    
    
done:
    return err;
}


C4Err  TestKeys()
{
    C4Err     err = kC4Err_NoErr;
  
    err = sTestSymmetricKeys(); CKERR;
    
    err = sTestTBCKeys(); CKERR;
    
done:
        
    
    return err;
    
}