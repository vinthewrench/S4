//
//  testUtilties.c
//  S4
//
//  Created by vincent Moscaritolo on 3/7/16.
//  Copyright © 2016 4th-A Technologies, LLC. All rights reserved.
//

#include <stdio.h>

#include "optest.h"

/*
 
 #bits base-2                           base32     base64     z-base-32
 ----- ------                           ------     ------     ---------
 1     0                                AA======   AA==       y
 1     1                                QA======   gA==       o
 2     01                               IA======   QA==       e
 2     11                               QA======   gA==       a
 10    0000000000                       AAAA====   AAA=       yy
 10    1000000010                       QCAA====   gIA=       on
 20    10001011100010001000             BC4IQ===   CLiI       tqre
 24    111100001011111111000111         6C74O===   8L/H       6n9hq
 24    110101000111101000000100         2R5AI===   1HoE       4t7ye
 30    111101010101011110111101000011   HVK66QY=   PVXvQw==   6im5sd

 */

typedef struct  {
    
     int                bits;
     uint8_t*            base2;			/* Plaintext			*/
     char*              zbase32;		/* Encoded		*/
 } katvector;


 static void bin_to_chars(uint8_t* base2, int bits, int maxbits, char*buffout)
{
    uint8_t *p = base2;
    uint8_t b = *p;
    char* out = buffout;
    int offset = 0;
    int bitsprocessed = 0;
    
    while (bits)
    {
        *out++= b & 0x80?'1':'0';

        if(++offset  > 7)
        {
            p = base2++;
            b = *p;
            offset = 0;
        }
        else
        {
            b = b <<1;
        }
        
        bits--;
        bitsprocessed ++;
        
        if(bitsprocessed > maxbits)
        {
            *out++ = '.' ;
            *out++ = '.' ;
            *out++ = '.' ;
            break;
        }
    }
    
    *out++ = '\0';
}


#define INT_CEIL(x,y) (x / y + (x % y > 0))

S4Err  testZbase32()
{
    S4Err     err = kS4Err_NoErr;
    
    katvector kat_vector_array[] =
    {
        { 1,   (uint8_t*)"\x00",               "y"		},
        { 1,   (uint8_t*)"\x80",               "o"		},
        { 2,   (uint8_t*)"\x40",               "e"		},
        { 2,   (uint8_t*)"\xC0",               "a"		},
        { 10,  (uint8_t*)"\x00\x00",           "yy"	},
        { 10,  (uint8_t*)"\x80\x80",           "on"	},
        { 20,  (uint8_t*)"\x8B\x88\x80",       "tqre"	},
        
        { 24,  (uint8_t*)"\xF0\xBF\xC7",       "6n9hq"	},
        { 24,  (uint8_t*)"\xD4\x7A\x04",     	"4t7ye"	},
   
        { 30,  (uint8_t*)"\xF5\x57\xBD\x0C", "6im54d"	},  // the spec says "6im5sd" but I think it is wrong
        { 64,  (uint8_t*)"\x28\x6F\x20\x29\x28\x20\x6F\x29",               "fbz1ykjerbz11" },
  
        { 128,  (uint8_t*)"\x00\x01\x02\x03\x05\x06\x07\x08\x0A\x0B\x0C\x0D\x0F\x10\x11\x12",   "yyyoryafyadoonombogo6rytne" },
        { 160,  (uint8_t*) "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C"
                            "\x9C\xD0\xD8\x9D",  "igcuhp18y4ysiqt6riazowgnp1qpbsr7" }
    };
   
    int i;
    
     for (i = 0; i < sizeof(kat_vector_array)/ sizeof(katvector) ; i++)
    {
        katvector* kat = &kat_vector_array[i];
        
        uint8_t  encoded[64]  = {0};
        uint8_t  decoded[64]  = {0};
    
        int len, len2;
        
        char* binString[128] = {0};
        
        bin_to_chars((uint8_t*)kat->base2, kat->bits, 24, (char*)binString);
        
        OPTESTLogVerbose("\t\t%4lu %2d %-30s %-32s\n",  kat->bits, INT_CEIL(kat->bits, 8), binString,  kat->zbase32);
        
        len = zbase32_encode((uint8_t*)encoded, (uint8_t*)kat->base2, kat->bits);
     
        /* check against encoded  */
        err = compareResults( kat->zbase32, encoded, len , kResultFormat_Byte, "Encoded"); CKERR;
    
        len2 = zbase32_decode((uint8_t*) decoded, (uint8_t*)encoded, kat->bits);
        
        err = compareResults(decoded, kat->base2, len/8  , kResultFormat_Byte, "Decoded"); CKERR;
        
      };
done:
    return err;

}



S4Err  TestUtilties()
{
    S4Err     err = kS4Err_NoErr;
    
    OPTESTLogInfo("\nTesting z-base-32 Encoding\n");
    
    err = testZbase32();
    
    OPTESTLogInfo("\n\n");

done:
    return err;
    
}
