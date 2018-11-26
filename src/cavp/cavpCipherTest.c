//
//  cavpCipherTest.c
//  S4-cavp
//
//  Created by vinnie on 9/25/18.
//  Copyright © 2018 4th-A Technologies, LLC. All rights reserved.
//

#include "cavpCipherTest.h"

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <ctype.h>

#include "cavputilities.h"

#include   <s4/s4.h>

enum  CAVPTest_
{
	kCAVPTest_Invalid		= 0,
	kCAVPTest_Encrypt,
	kCAVPTest_Decrypt,
	kCAVPTest_EncryptMCT,

	ENUM_FORCE( CAVPTest_ )
};
ENUM_TYPEDEF( CAVPTest_, CAVPTest   );

enum  CipherMode_
{
	kCipherMode_Invalid		= 0,
	kCipherMode_ECB,
	kCipherMode_CBC,

	ENUM_FORCE( CipherMode_ )
};
ENUM_TYPEDEF( CipherMode_, CipherMode   );



static Cipher_Algorithm algorForFileName(char* fileName)
{
	Cipher_Algorithm algor = kCipher_Algorithm_Invalid;

	if(containsString("128.", fileName))
		algor = kCipher_Algorithm_AES128;
	else if(containsString("192.", fileName))
		algor = kCipher_Algorithm_AES192;
	else if(containsString("256.", fileName))
		algor = kCipher_Algorithm_AES256;

	return algor;
}



S4Err encryptMCT(Cipher_Algorithm algor,
				 CipherMode mode,
				 	uint8_t*  KEY,
				 	uint8_t*  IV,
					uint8_t*  IN,  size_t INlen,
					uint8_t*  OUT)
{
	S4Err 				err = kS4Err_NoErr;

	uint8_t			KEYMASK[24];
	uint8_t			OUTVAL[8];
	uint8_t			LAST[8];

	for(int i = 0; i< 400; i++)
	{
		uint8_t *buf;
		uint8_t *buf1;

		if(mode == kCipherMode_ECB)
		{
			for(int j = 0; j< 10000; j++)
			{
				buf  = j&1?LAST:OUTVAL;
				buf1  = j&1?OUTVAL:LAST;

				err = ECB_Encrypt(algor, KEY, buf,  INlen, buf1); CKERR;

				if( j == 9997) COPY(OUTVAL,  &KEYMASK[16], 8);
				if( j == 9998) COPY(LAST, 	 &KEYMASK[8],  8);
				if( j == 9999) COPY(OUTVAL,  &KEYMASK[0],  8);

			}

		}
		else  if(mode == kCipherMode_CBC)
		{
		}
		else
			FLAG_ERR(kS4Err_FeatureNotAvailable);


		for(int k = 0; k < 8; k++)
			KEY[k] ^= KEYMASK[k];

	}

done:
	return err;
}

S4Err processCipher(Cipher_Algorithm algor,
					CipherMode mode,
					CAVPTest op,
					uint8_t*  KEY,
					uint8_t*  IV,
					uint8_t*  IN,  size_t INlen,
					uint8_t**  OUT)
{
	S4Err 				err = kS4Err_NoErr;
	CBC_ContextRef		cbcCtx = kInvalidCBC_ContextRef;

	uint8_t* 		CAL = NULL;

	if(mode == kCipherMode_ECB)
	{
		CAL = XMALLOC(INlen);

		switch (op)
		{
			case kCAVPTest_EncryptMCT:
				err = encryptMCT(algor, mode, KEY, IV,  IN, INlen, CAL); CKERR;
				break;

			case kCAVPTest_Encrypt:
				err = ECB_Encrypt(algor, KEY, IN, INlen, CAL); CKERR;
				break;

			case kCAVPTest_Decrypt:
				err = ECB_Decrypt(algor, KEY, IN, INlen, CAL);CKERR;
			break;

			default:
				break;
		}
	}
	else  if(mode == kCipherMode_CBC)
	{
		CAL = XMALLOC(INlen);
		switch (op)
		{
			case kCAVPTest_EncryptMCT:
				err = encryptMCT(algor, mode, KEY, IV,  IN, INlen, CAL); CKERR;
				break;

			case kCAVPTest_Encrypt:
				err = CBC_Init(algor,KEY,IV, &cbcCtx); CKERR;
				err = CBC_Encrypt(cbcCtx, IN, INlen, CAL); CKERR;
				break;

			case kCAVPTest_Decrypt:
				err = CBC_Init(algor,KEY,IV, &cbcCtx); CKERR;
				err = CBC_Decrypt(cbcCtx, IN, INlen, CAL); CKERR;
				break;

			default:
				break;
		}


	}
	else
		err = kS4Err_FeatureNotAvailable;

done:

	if(IsS4Err(err))
	{
		if(CAL) XFREE(CAL);
 	}

	if(CBC_ContextRefIsValid(cbcCtx))
		CBC_Free(cbcCtx);

	*OUT = CAL;

	return err;
}


S4Err cavpCipherTestFile(char* path)
{
	S4Err 				err = kS4Err_NoErr;
	bool 				PASSED = false;
	int					testcount = 0;
	int					lineNumber = 0;
	size_t				keySize = 0;
	bool 				mctMode = false;
	CipherMode			cipherMode = kCipherMode_Invalid;
	Cipher_Algorithm 	algor 		= kCipher_Algorithm_Invalid;

	uint8_t*  CT = NULL;
	uint8_t*  PT = NULL;
	size_t	  PTlen = 0;
	size_t	  CTlen = 0;

	uint8_t*  CAL = NULL;

	char *base = basename((char *)path);

	// determine test type
	mctMode = containsString("MCT", base);
	if(hasPrefix("ECB", base))
	{
		cipherMode = kCipherMode_ECB;
	}
	else if(hasPrefix("CBC", base))
	{
		cipherMode = kCipherMode_CBC;
	}
	else
	{
		FLAG_ERR(kS4Err_FeatureNotAvailable);
	}

	algor = algorForFileName(base);
	if(algor == kCipher_Algorithm_Invalid)
	{
		FLAG_ERR(kS4Err_FeatureNotAvailable);
	}

// skip this test for now
	if(mctMode)
		return kS4Err_NoErr;


	char line [ 32767 ]; /* or other suitable maximum line size */

	err =  Cipher_GetKeySize(algor, &keySize); CKERR;

	FILE *file = fopen ( path, "r" );
	if ( file != NULL )
	{
		CAVPTest cavpTest	= kCAVPTest_Invalid;

		uint8_t KEY[32]  = {0};
		uint8_t IV[16]  	= {0};

		while ( fgets ( line, sizeof line, file ) != NULL ) /* read a line */
		{
			lineNumber++;
			char *p;

			// skip ws
			for (p = line; isspace(*p); p++) ;

			if(hasPrefix("#", p))
			{
				//				   fputs ( line, stdout ); /* commne the line */
				continue;
			}

			if(hasPrefix("KEY", p))
			{
				char *p1 = NULL;
				int len = nextHexToken(p, &p1);

				if((len/2 != (keySize >>3))
				  || (sgetHexString(p1,(uint8_t*) KEY) != (keySize >>3)))
				{
					FLAG_ERR(kS4Err_CorruptData);
				}
			}
			else if(hasPrefix("IV", p))
			{
					char *p1 = NULL;
					int len = nextHexToken(p, &p1);

				if((len/2 > sizeof(IV))
				   || (sgetHexString(p1,(uint8_t*) IV) > sizeof(IV)))
				{
						FLAG_ERR(kS4Err_CorruptData);
				}
			}
			else if(hasPrefix("[DECRYPT]", p))
			{
				// we dont decrypt monte tests
				if(mctMode)
					FLAG_ERR(kS4Err_FeatureNotAvailable);

				cavpTest = kCAVPTest_Decrypt;
			}
			else if(hasPrefix("[ENCRYPT]", p))
			{
				cavpTest = mctMode?kCAVPTest_EncryptMCT:kCAVPTest_Encrypt;
			}
			else if(hasPrefix("PLAINTEXT", p))
			{
				char *p1 = NULL;
				int len = nextHexToken(p, &p1);
				FREE_AND_NULL(CT);
				FREE_AND_NULL(CAL);

				PT = XMALLOC(len/2);
				PTlen = sgetHexString(p1,(uint8_t*) PT);

				switch (cavpTest)
				{
					case kCAVPTest_Encrypt:
					case kCAVPTest_EncryptMCT:
						err = processCipher(algor, cipherMode, cavpTest,
											 	(uint8_t*)KEY, (uint8_t*)IV,
												PT, PTlen,
												&CAL); CKERR;
						break;

					case kCAVPTest_Decrypt:
						// check result
						if(CAL)
						{
						err =  compareResults(PT, CAL, PTlen, "[DECRYPT]"); CKERR;
						testcount++;
						}
						break;

					default:
						break;
				}

			}
			else if(hasPrefix("CIPHERTEXT", p))
			{
				char *p1 = NULL;
				int len = nextHexToken(p, &p1);
				FREE_AND_NULL(PT);
				CT = XMALLOC(len/2);
				CTlen = sgetHexString(p1,(uint8_t*) CT);

				switch (cavpTest)
				{
					case kCAVPTest_Decrypt:
						err = processCipher(algor, cipherMode, cavpTest,
											(uint8_t*)KEY, (uint8_t*)IV,
											CT,CTlen,
											&CAL); CKERR;
						break;

					case kCAVPTest_Encrypt:
	 				case kCAVPTest_EncryptMCT:
						// check result
						if(CAL)
						{
						err =  compareResults(CT, CAL, PTlen, "[ENCRYPT]"); CKERR;
						testcount++;
						}
						break;

					default:
						break;
				}

			}

		}
		fclose ( file );
		PASSED = true;

	}

done:

	FREE_AND_NULL(PT);
	FREE_AND_NULL(CT);
	FREE_AND_NULL(CAL);

	if(IsS4Err(err))
	{
		char str[256];

		printf("𐄂 %-25s %5d FAIL\n", base, lineNumber);

		if(IsntS4Err( S4_GetErrorString(err, str)))
		{
			printf("\n Error %d:  %s\n", err, str);
		}
		else
		{
			printf("\nError %d\n", err);
		}
	}
	else
	{
		printf("✓ %-25s %3d\n", base, testcount);
	}

	return err;

}
