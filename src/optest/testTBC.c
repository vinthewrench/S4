//
//  testTBC.c
//  C4
//
//  Created by vincent Moscaritolo on 11/3/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "c4.h"
#include "optest.h"



typedef struct  {
    TBC_Algorithm   algor;
    int            keysize;
    
    uint64_t*        key;
    uint64_t*        PT;			/* Plaintext			*/
    uint64_t*        tweek;		/* tweek	*/
    uint64_t*        TBC;         /* TBC	Known Answer	*/
} katvector;



/* these test vectors come from https://github.com/wernerd/Skein3Fish/blob/master/c/test/threefishTest.c 
  and have have to massage the test vectors a bit for them to compare.  I am not sure why werner didnt
 just use regular test vectors.  
 */


static C4Err RunCipherKAT(  katvector *kat)

{
    C4Err err = kC4Err_NoErr;
    TBC_ContextRef TBC = kInvalidTBC_ContextRef;
    
    uint8_t IN[1024];
    uint8_t CT[1024];
    uint8_t PT[1024];
    char* name = NULL;
 
    name = tbc_algor_table(kat->algor);
    
    OPTESTLogInfo("\t%-14s %016llX %016llX ", name, kat->tweek[0],kat->tweek[1] );
    
    // save a copy of plaintext
    memcpy(IN,kat->PT,kat->keysize >> 3);
    
    err = TBC_Init(kat->algor, kat->key, &TBC); CKERR;
    
    err = TBC_SetTweek(TBC, kat->tweek); CKERR;
    
    err = TBC_Encrypt(TBC, IN, CT); CKERR;
    
    /* check against know-answer */
    err = compareResults( kat->TBC, CT, kat->keysize >>3, kResultFormat_Long, "TBC Encrypt"); CKERR;
    
    err = TBC_Decrypt(TBC, CT, PT); CKERR;
    
    /* check against orginal plain-text  */
    err = compareResults( IN, PT, kat->keysize >>3  , kResultFormat_Long, "TBC Decrypt"); CKERR;

done:
    
    if(TBC_ContextRefIsValid(TBC))
        TBC_Free(TBC);
    
    
    OPTESTLogInfo("\n");
    return err;
 
}


C4Err TestTBCiphers()
{
    C4Err err = kC4Err_NoErr;
    
    unsigned int		i;
    
    /* Test vectors for RBC known answer test */
    /* ThreeFish 256 bit key */
    uint64_t three_256_00_key[] = { 0L, 0L, 0L, 0L };
    
    uint64_t three_256_00_input[] = { 0L, 0L, 0L, 0L };
    
    uint64_t three_256_00_tweak[] = { 0L, 0L };
    
    uint64_t three_256_00_result[] = { 0x94EEEA8B1F2ADA84L, 0xADF103313EAE6670L,
        0x952419A1F4B16D53L, 0xD83F13E63C9F6B11L
    };
    
    uint64_t three_256_01_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L
    };
    
    uint64_t three_256_01_input[] = { 0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L,
        0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L
    };
    
    uint64_t three_256_01_result[] = {
        0xDF8FEA0EFF91D0E0L, 0xD50AD82EE69281C9L, 0x76F48D58085D869DL, 0xDF975E95B5567065L
    };
    
    uint64_t three_256_01_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
    
    uint64_t three_512_00_key[] = { 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
        0L, 0L, 0L, 0L
    };
    
    uint64_t three_512_00_input[] = { 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
        0L, 0L, 0L, 0L, 0L
    };
    
    uint64_t three_512_00_tweak[] = { 0L, 0L };
    
    uint64_t three_512_00_result[] = { 0xBC2560EFC6BBA2B1L, 0xE3361F162238EB40L,
        0xFB8631EE0ABBD175L, 0x7B9479D4C5479ED1L, 0xCFF0356E58F8C27BL,
        0xB1B7B08430F0E7F7L, 0xE9A380A56139ABF1L, 0xBE7B6D4AA11EB47EL
    };
    
    uint64_t three_512_01_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L
    };
    
    uint64_t three_512_01_input[] = { 0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L,
        0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L, 0xD8D9DADBDCDDDEDFL,
        0xD0D1D2D3D4D5D6D7L, 0xC8C9CACBCCCDCECFL, 0xC0C1C2C3C4C5C6C7L
    };
    
    uint64_t three_512_01_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
    
    uint64_t three_512_01_result[] = {
        0x2C5AD426964304E3L, 0x9A2436D6D8CA01B4L, 0xDD456DB00E333863L, 0x794725970EB9368BL,
        0x043546998D0A2A27L, 0x25A7C918EA204478L, 0x346201A1FEDF11AFL, 0x3DAF1C5C3D672789L
    };
    
    uint64_t three_1024_00_key[] = { 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
        0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
        0L, 0L, 0L, 0L
    };
    
    uint64_t three_1024_00_input[] = { 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
        0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
        0L, 0L, 0L, 0L
    };
    
    uint64_t three_1024_00_tweak[] = { 0L, 0L };
    
    uint64_t three_1024_00_result[] = { 0x04B3053D0A3D5CF0L, 0x0136E0D1C7DD85F7L,
        0x067B212F6EA78A5CL, 0x0DA9C10B4C54E1C6L, 0x0F4EC27394CBACF0L,
        0x32437F0568EA4FD5L, 0xCFF56D1D7654B49CL, 0xA2D5FB14369B2E7BL,
        0x540306B460472E0BL, 0x71C18254BCEA820DL, 0xC36B4068BEAF32C8L,
        0xFA4329597A360095L, 0xC4A36C28434A5B9AL, 0xD54331444B1046CFL,
        0xDF11834830B2A460L, 0x1E39E8DFE1F7EE4FL
    };
    
    uint64_t three_1024_01_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
        0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
        0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L,
        0x5756555453525150L, 0x5F5E5D5C5B5A5958L, 0x6766656463626160L,
        0x6F6E6D6C6B6A6968L, 0x7776757473727170L, 0x7F7E7D7C7B7A7978L,
        0x8786858483828180L, 0x8F8E8D8C8B8A8988L
    };
    
    uint64_t three_1024_01_input[] = {
        0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L, 0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L,
        0xD8D9DADBDCDDDEDFL, 0xD0D1D2D3D4D5D6D7L, 0xC8C9CACBCCCDCECFL, 0xC0C1C2C3C4C5C6C7L,
        0xB8B9BABBBCBDBEBFL, 0xB0B1B2B3B4B5B6B7L, 0xA8A9AAABACADAEAFL,  0xA0A1A2A3A4A5A6A7L,
        0x98999A9B9C9D9E9FL, 0x9091929394959697L, 0x88898A8B8C8D8E8FL, 0x8081828384858687L
    };
    
    uint64_t three_1024_01_tweak[] = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };
    
    uint64_t three_1024_01_result[] = {
        0xB0C33CD7DB4D65A6L, 0xBC49A85A1077D75DL, 0x6855FCAFEA7293E4L, 0x1C5385AB1B7754D2L,
        0x30E4AAFFE780F794L, 0xE1BBEE708CAFD8D5L, 0x9CA837B7423B0F76L, 0xBD1403670D4963B3L,
        0x451F2E3CE61EA48AL, 0xB360832F9277D4FBL, 0x0AAFC7A65E12D688L, 0xC8906E79016D05D7L,
        0xB316570A15F41333L, 0x74E98A2869F5D50EL, 0x57CE6F9247432BCEL, 0xDE7CDD77215144DEL,

    };

       katvector kat_vector_array[] =
    {
        {	kTBC_Algorithm_3FISH256,   256,  three_256_00_key,  three_256_00_input,  three_256_00_tweak, three_256_00_result  },
        {	kTBC_Algorithm_3FISH256,   256,  three_256_01_key,  three_256_01_input,  three_256_01_tweak, three_256_01_result  },

        {	kTBC_Algorithm_3FISH512,   512,  three_512_00_key,  three_512_00_input,  three_512_00_tweak, three_512_00_result  },
        {	kTBC_Algorithm_3FISH512,   512,  three_512_01_key,  three_512_01_input,  three_512_01_tweak, three_512_01_result  },
    
        {	kTBC_Algorithm_3FISH1024,   1024,  three_1024_00_key,  three_1024_00_input,  three_1024_00_tweak, three_1024_00_result  },
        {	kTBC_Algorithm_3FISH1024,   1024,  three_1024_01_key,  three_1024_01_input,  three_1024_01_tweak, three_1024_01_result  },
        
     };
    

    /* run  known answer tests (KAT) */
    for (i = 0; i < sizeof(kat_vector_array)/ sizeof(katvector) ; i++)
    {
        err = RunCipherKAT( &kat_vector_array[i] ); CKERR;
        
    }
    
      OPTESTLogInfo("\n");
    
done:
    return err;
}
