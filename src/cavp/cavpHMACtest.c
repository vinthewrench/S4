//
//  cavpHMACtest.c
//  S4-cavp
//
//  Created by vinnie on 9/27/18.
//  Copyright © 2018 4th-A Technologies, LLC. All rights reserved.
//

#include "cavpHMACtest.h"

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <ctype.h>

#include "cavputilities.h"

#include   <S4Crypto/S4Crypto.h>



S4Err cavpHMACTestFile(char* path)
{
	S4Err 				err = kS4Err_NoErr;
	bool 				PASSED = false;
	int					testcount = 0;
	int					lineNumber = 0;
	size_t				hashSize = 0;

	size_t		Klen = 0;
	size_t 		Tlen = 0;
	uint8_t*  	KEY = NULL;
	uint8_t*  	Msg = NULL;
	size_t 		Msglen = 0;

	uint8_t*  	Mac = NULL;
	size_t 		Maclen = 0;

	uint8_t*  CAL = NULL;


	HASH_Algorithm hashAlgor = kHASH_Algorithm_Invalid;
	MAC_ContextRef	hmac =  kInvalidMAC_ContextRef;

	char *base = basename((char *)path);

	char line [ 32767 ]; /* or other suitable maximum line size */
	FILE *file = fopen ( path, "r" );
	if ( file != NULL )
	{
		//		printf(" %s ", base);

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
			else if(hasPrefix("[L", p))
			{
				int HASH_BYTES = 0;
				while (!(*p >= '0' && *p <= '9')) p++;
				if( sscanf(p, "%d",   &HASH_BYTES)  != 1)
					FLAG_ERR(kS4Err_CorruptData);

				switch(HASH_BYTES)
				{
					case 20: hashAlgor = kHASH_Algorithm_SHA1; break;
					case 28: hashAlgor = kHASH_Algorithm_SHA224; break;
					case 32: hashAlgor = kHASH_Algorithm_SHA256; break;
					case 48: hashAlgor = kHASH_Algorithm_SHA384; break;
					case 64: hashAlgor = kHASH_Algorithm_SHA512; break;
					default:  FLAG_ERR(kS4Err_CorruptData);
				}
			}
			else if(hasPrefix("Klen", p))
			{
				while (!(*p >= '0' && *p <= '9')) p++;
				if( sscanf(p, "%ld",   &Klen)  != 1)
					FLAG_ERR(kS4Err_CorruptData);
			}
			else if(hasPrefix("Tlen", p))
			{
				while (!(*p >= '0' && *p <= '9')) p++;
				if( sscanf(p, "%ld",   &Tlen)  != 1)
					FLAG_ERR(kS4Err_CorruptData);
			}
			else if(hasPrefix("Key", p))
			{
				p+= 3;
				char *p1 = NULL;
				int len = nextHexToken(p, &p1);
				FREE_AND_NULL(KEY);

				KEY = XMALLOC(len/2);
				if( sgetHexString(p1,(uint8_t*) KEY) != Klen)
					FLAG_ERR(kS4Err_CorruptData);
			}
			else if(hasPrefix("Msg", p))
			{
				p+= 3;
 				char *p1 = NULL;

				size_t	resultLen;

				int len = nextHexToken(p, &p1);
				FREE_AND_NULL(Msg);

				Msg = XMALLOC(len/2);
				Msglen = sgetHexString(p1,(uint8_t*) Msg);

				if(MAC_ContextRefIsValid(hmac)) MAC_Free(hmac);
				hmac =  kInvalidMAC_ContextRef;

				err = MAC_Init(kMAC_Algorithm_HMAC,
							   hashAlgor,  KEY,Klen, &hmac ); CKERR;

				err = MAC_HashSize(hmac, &hashSize); CKERR;

				err = MAC_Update(hmac, Msg, Msglen); CKERR;

				CAL = XMALLOC(hashSize);
				resultLen = hashSize;
				err = MAC_Final(hmac, CAL, &resultLen); CKERR;

				MAC_Free(hmac);
				hmac = NULL;

			}
			else if(hasPrefix("Mac", p))
			{
				p+= 3;
				char *p1 = NULL;
				int len = nextHexToken(p, &p1);
				FREE_AND_NULL(Mac);

				Mac = XMALLOC(len/2);
				Maclen = sgetHexString(p1,(uint8_t*) Mac);

				err =  compareResults(Mac, CAL, Maclen, "Hmac"); CKERR;

				testcount++;

			}
		
		}
		fclose ( file );
		PASSED = true;
	}

done:

	FREE_AND_NULL(Mac);
	FREE_AND_NULL(Msg);
	FREE_AND_NULL(CAL);

	if(MAC_ContextRefIsValid(hmac))
		MAC_Free(hmac);

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
