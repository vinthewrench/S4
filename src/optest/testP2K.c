//
//  testP2K.c
//  S4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//
 
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "s4.h"
#include "optest.h"



#define MSG_KEY_BYTES 32

typedef struct  {
    uint8_t *  passphrase;
    uint8_t     salt[64];
    size_t      saltLen;
    uint32_t    rounds;
    
    uint8_t     key[64];
    size_t		 keyLen;
}  p2k_kat_vector;



static S4Err RunP2K_KAT( p2k_kat_vector *kat)
{
    S4Err err = kS4Err_NoErr;
    
    uint8_t     key[128];
    
    
    err = PASS_TO_KEY(kat->passphrase, strlen((char*)kat->passphrase),
                      kat->salt, kat->saltLen ,
                      kat->rounds,
                      key, kat->keyLen); CKERR;
    
    err = compareResults( kat->key, key, kat->keyLen , kResultFormat_Byte, "PASS_TO_KEY"); CKERR;
    
done:
    return err;
    
};


static S4Err runP2K_Pairwise()
{
    S4Err err = kS4Err_NoErr;
    clock_t		start	= 0;
    double		elapsed	= 0;
    uint8_t     key[MSG_KEY_BYTES];
    
    p2k_kat_vector kat;
    uint8_t*    passphrase = NULL;
    
    
    kat.saltLen = 8;
    err = RNG_GetBytes(kat.salt, kat.saltLen); CKERR;
    
    
    err = RNG_GetPassPhrase(128, (char**) &passphrase); CKERR;
    
    kat.passphrase = passphrase;

    // calculate how many rounds we need on this machine for passphrase hashing
    err = PASS_TO_KEY_SETUP(strlen((char*)kat.passphrase),
                            MSG_KEY_BYTES, kat.salt, kat.saltLen, &kat.rounds); CKERR;
    OPTESTLogInfo("\t%d rounds on this device for 0.1s\n", kat.rounds);
    
    start = clock();
    err = PASS_TO_KEY(kat.passphrase, strlen((char*)kat.passphrase),
                      kat.salt, sizeof(kat.salt), kat.rounds,
                      key, sizeof(key)); CKERR;

    elapsed = ((double) (clock() - start)) / CLOCKS_PER_SEC;
    OPTESTLogInfo("\tPASS_TO_KEY elapsed time %0.4f sec\n", elapsed);
    
    OPTESTLogInfo("\n");

done:
    
    if(passphrase)
        XFREE(passphrase) ;
    
    return err;

}


S4Err  TestP2K()
{
    S4Err     err = kS4Err_NoErr;
    
    
    p2k_kat_vector p2K_kat_vector_array[] =
    {
        {
            (uint8_t*)"Tant las fotei com auziretz",
            { 	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, },
            8,
            1024,
            {
                0x66, 0xA4, 0x59, 0x7C, 0x73, 0x58, 0xFE, 0x57, 0xAE, 0xCE, 0x88, 0x68, 0x67, 0x58, 0xF6, 0x83
            },
            16
        },
        
        {
            (uint8_t*)"Hello. My name is Inigo Montoya. You killed my father. Prepare to die.",
            { 	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, },
            8,
            1024,
            {
                0x26, 0xF5, 0x27, 0xAA, 0x36, 0xD0, 0xE9, 0xF8, 0x10, 0xA0, 0x27, 0xD7, 0x7C, 0xB4, 0xEC, 0x58
            },
            16
        }
        
    };
    
    OPTESTLogInfo("\nTesting PBKD2 KAT\n");
    
    for (int i = 0; i < sizeof(p2K_kat_vector_array)/ sizeof(p2k_kat_vector) ; i++)
    {
          err = RunP2K_KAT( &p2K_kat_vector_array[i]); CKERR;
        
    }
    
    
    OPTESTLogInfo("\nTesting PBKD2 Generation\n");
    err = runP2K_Pairwise( ); CKERR;
    
done:
    return err;
    
}
