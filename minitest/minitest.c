//
//  main.m
//  miniTest
//
//  Created by vinnie on 9/14/18.
//  Copyright © 2018 4th-a. All rights reserved.
//

//#import <Foundation/Foundation.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#include <tommath/tommath.h>
#include <tomcrypt.h>
#include <threefishApi.h>

#define CMP(b1, b2, length)							\
(memcmp((void *)(b1), (void *)(b2), (length)) == 0)

void dumpHex(uint8_t* buffer, int length, int offset)
{
	char hexDigit[] = "0123456789ABCDEF";
	register int			i;
	int						lineStart;
	int						lineLength;
	short					c;
	const unsigned char	  *bufferPtr = buffer;

	char                    lineBuf[80];
	char                    *p;


#define kLineSize	8
	for (lineStart = 0, p = lineBuf; lineStart < length; lineStart += lineLength,  p = lineBuf )
	{
		lineLength = kLineSize;
		if (lineStart + lineLength > length)
			lineLength = length - lineStart;

		p += sprintf(p, "%6d: ", lineStart+offset);
		for (i = 0; i < lineLength; i++){
			*p++ = hexDigit[ bufferPtr[lineStart+i] >>4];
			*p++ = hexDigit[ bufferPtr[lineStart+i] &0xF];
			if((lineStart+i) &0x01)  *p++ = ' ';  ;
		}
		for (; i < kLineSize; i++)
			p += sprintf(p, "   ");

		p += sprintf(p,"  ");
		for (i = 0; i < lineLength; i++) {
			c = bufferPtr[lineStart + i] & 0xFF;
			if (c > ' ' && c < '~')
				*p++ = c ;
			else {
				*p++ = '.';
			}
		}
		*p++ = 0;

		printf( "%s\n",lineBuf);
	}
#undef kLineSize
}


int compareResults(const void* expected, const void* calculated, size_t len,  char* comment  )
{
	int err = 0;

	err = CMP(expected, calculated, len) ? 0 : 1;

	if( (err) )
	{
		printf( "\n\t\tFAILED %s\n",comment );

		printf( "\t\texpected:\n");
		dumpHex(( uint8_t*) expected, (int)len, 0);
		printf( "\t\tcalulated:\n");
		dumpHex(( uint8_t*) calculated, (int)len, 0);
		printf( "\n");

	}

	return err;
}


void testecc()
{

	uint8_t pubkey[105] = {
		0x04,0x00,0xca,0x7d,0xe8,0xad,0x11,0x11,
		0xb9,0x3c,0x79,0x8e,0x64,0x28,0xc8,0xeb,
		0x64,0xd9,0xb0,0x3b,0xa2,0x12,0x8a,0x49,
		0x1a,0x14,0x64,0xd4,0xa7,0x64,0x12,0x15,
		0xc7,0xd3,0xc2,0x24,0xa6,0xed,0x7f,0xa8,
		0x6a,0x28,0x57,0xf7,0x4d,0x5a,0x1a,0x89,
		0xc4,0xa8,0xd9,0xac,0xdb,0x2a,0x1b,0x19,
		0xb7,0x0d,0x65,0xd7,0x97,0xf2,0xb7,0x9e,
		0xc9,0xef,0x7c,0xf5,0xb9,0x42,0x6f,0x16,
		0xd0,0xba,0xed,0x8c,0x60,0xa9,0x9c,0xa7,
		0x01,0x1b,0xa6,0x8b,0x09,0x61,0xc7,0xc9,
		0xa4,0xde,0x77,0x29,0xbe,0xff,0x34,0x5a,
		0x73,0x68,0x02,0x29,0xe1,0x81,0xe7,0xf8,
		0x23};

	uint64_t three_512_01_key[] = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
		0x2726252423222120L, 0x2F2E2D2C2B2A2928L, 0x3736353433323130L,
		0x3F3E3D3C3B3A3938L, 0x4746454443424140L, 0x4F4E4D4C4B4A4948L
	};

#define PTsize sizeof(three_512_01_key)

	ecc_key eccPub;;
	uint8_t        PT[PTsize];

	uint8_t        CT[256];
	size_t         CTlen = sizeof(CT);


	// fill PT
//	for(int i = 0; i< PTsize; i++) PT[i]= i;
	memcpy(PT, &three_512_01_key, sizeof(three_512_01_key));

	printf("ecc_bl_import ");

 	int status = ecc_bl_ansi_x963_import(pubkey, sizeof(pubkey), &eccPub);

	if(status != CRYPT_OK)
	{
		printf(" -- ecc_bl_import FAIL");
		return;
	}
	{
		printf("OK \n");
	}

	printf("ecc_bl_encrypt_key(%ld bits) ", PTsize * 8 );
	status = ecc_bl_encrypt_key(PT, PTsize, CT,  &CTlen,
								NULL,
								find_prng("sprng"),
								find_hash("sha512"),
								&eccPub);

	if(status != CRYPT_OK)
	{
		printf("FAIL");
		return;
	}
	else
	{
		printf("-> %ld bytes\n",CTlen);
		dumpHex(CT, (int)CTlen, 0);

	}


done:;

}

 
void test3fish()
{

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

	uint8_t CT[1024];
	uint8_t PT[1024];

	ThreefishKey_t       state;


	printf("test3fish  encrypt\n");

 	threefishSetKey(&state, Threefish512, three_512_01_key, three_512_01_tweak);
 	threefishEncryptBlockBytes(&state,(uint8_t*) three_512_01_input, CT);

	int status = compareResults(CT,three_512_01_result, sizeof(three_512_01_result), "theefish encrypt");
	if(status)
	{
		printf("test3fish  encrypt FAIL");
	}

	printf("test3fish  decrypt\n");

 	threefishDecryptBlockBytes(&state,(uint8_t*) CT, PT);

	status = compareResults(PT,three_512_01_input, sizeof(three_512_01_input), "theefish decrypt");
	if(status)
	{
		printf("test3fish  decrypt FAIL");
	}


done:;

}

int main(int argc, const char * argv[]) {
//	@autoreleasepool {

  		ltc_mp = ltm_desc;
 		register_prng (&sprng_desc);
 		register_hash (&sha512_desc);

 		testecc();
 		test3fish();

//	}
	return 0;
}
