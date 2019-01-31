//
//  cavpTest.h
//  cryptotest
//
//  Created by vinnie on 9/13/18.
//  Copyright © 2018 4th-a. All rights reserved.
//

#include "cavpHashTest.h"

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


static HASH_Algorithm algorForFileName(char* fileName)
{
	HASH_Algorithm algor = kHASH_Algorithm_Invalid;

	if(hasPrefix("SHA1", fileName))
		algor = kHASH_Algorithm_SHA1;
	else if(hasPrefix("SHA224", fileName))
		algor = kHASH_Algorithm_SHA224;
	else if(hasPrefix("SHA256", fileName))
		algor = kHASH_Algorithm_SHA256;
	else if(hasPrefix("SHA384", fileName))
		algor = kHASH_Algorithm_SHA384;
	else if(hasPrefix("SHA512_256", fileName))
		algor = kHASH_Algorithm_SHA512_256;
	else if(hasPrefix("SHA512_", fileName))
		algor = kHASH_Algorithm_Invalid;
	else if(hasPrefix("SHA512", fileName))
		algor = kHASH_Algorithm_SHA512;
	else if(hasPrefix("SHA3_224", fileName))
		algor = kHASH_Algorithm_SHA3_224;
	else if(hasPrefix("SHA3_256", fileName))
		algor = kHASH_Algorithm_SHA3_256;
	else if(hasPrefix("SHA3_384", fileName))
		algor = kHASH_Algorithm_SHA3_384;
	else if(hasPrefix("SHA3_512", fileName))
		algor = kHASH_Algorithm_SHA3_512;

	return algor;

}


S4Err cavpHashTestFile(char* path)
{
	bool PASSED = false;
	S4Err err = kS4Err_NoErr;
	HASH_ContextRef  	hash = kInvalidHASH_ContextRef;
	size_t				hashSize = 0;
	int					 testcount = 0;
	int					lineNumber = 0;

	int					LEN = 0;

	uint8_t*	msgBuf		= NULL;
	size_t		msgBufLen	= 0;
	size_t		msgLen		= 0;

	msgBuf		= malloc(1024);
	msgBufLen   = 1024;

	uint8_t*	katBuf		= NULL;
	size_t		katBufLen	= 0;
	size_t		katLen		= 0;

	katBuf		= malloc(1024);
	katBufLen   = 1024;

	char *base = basename((char *)path);

	HASH_Algorithm algor = algorForFileName(base);

	if(algor == kHASH_Algorithm_Invalid)
	{
		PASSED = false;
		err = kS4Err_FeatureNotAvailable;
	}
	else
	{
		char line [ 32767 ]; /* or other suitable maximum line size */

		FILE *file = fopen ( path, "r" );
		if ( file != NULL )
		{
			err = HASH_Init(algor, &hash); CKERR;
			err = HASH_GetSize(hash, &hashSize); CKERR;

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

				if(hasPrefix("Msg", p))
			   	{
					char *p1 = NULL;
					int len = nextHexToken(p, &p1);

					if(len)
					{
						if(msgBufLen < len)
						{
							if((msgBuf = realloc(msgBuf, LEN)) == 0 )
								FLAG_ERR(kS4Err_OutOfMemory);
							msgBufLen = LEN;
						}
						msgLen = sgetHexString(p1, msgBuf);
//						if(LEN > 0 && (msgLen != LEN)) FLAG_ERR(kS4Err_CorruptData);

					}

			   	}
				else if(hasPrefix("Len", p))
				{
					int bitLen = 0;
					while (!(*p >= '0' && *p <= '9')) p++;
					if( sscanf(p, "%d",   &bitLen)  != 1)
						FLAG_ERR(kS4Err_CorruptData);
					LEN = bitLen/8;

 				}
				else if(hasPrefix("MD", p))
				{
					char *p1 = NULL;
					int len = nextHexToken(p, &p1);

					uint8_t hashBuf[128] =  {0};

					if(len)
					{
						if(katBufLen < len)
						{
							if((katBuf = realloc(katBuf, LEN)) == 0 )
								FLAG_ERR(kS4Err_OutOfMemory);
							katBufLen = len;
						}
						katLen	 = sgetHexString(p1, katBuf);
 						if(hashSize > 0 && (katLen != hashSize))
							FLAG_ERR(kS4Err_CorruptData);
					}

					err = HASH_Reset(hash); CKERR;
					err = HASH_Update(hash, msgBuf, LEN); CKERR;
					err = HASH_Final(hash, (void*) hashBuf);CKERR;

					err = compareResults(katBuf, hashBuf, katLen, base); CKERR;
					testcount++;
				}
			}
			fclose ( file );
			PASSED = true;
		}
		else
		{
			err = kS4Err_FeatureNotAvailable;

		}
		

	}

done:
	if( HASH_ContextRefIsValid(hash))
		HASH_Free(hash);

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

S4Err cavpHashMonteTestFile(char* path)
{
	bool PASSED = false;
	S4Err err = kS4Err_NoErr;
	HASH_ContextRef  	hash = kInvalidHASH_ContextRef;
	size_t				hashSize = 0;
	int					 testcount = 0;
	int					lineNumber = 0;

	uint8_t*  MD[4] = {NULL};

	char *base = basename((char *)path);

	HASH_Algorithm algor = algorForFileName(base);

	if(algor == kHASH_Algorithm_Invalid)
	{
		PASSED = false;
		err = kS4Err_FeatureNotAvailable;
	}
	else
	{
		char line [ 32767 ]; /* or other suitable maximum line size */

		FILE *file = fopen ( path, "r" );
		if ( file != NULL )
		{
			err = HASH_Init(algor, &hash); CKERR;
			err = HASH_GetSize(hash, &hashSize); CKERR;

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

				if(hasPrefix("Seed", p))
				{
					uint8_t seedBuf[64] =  {0};

					p+=4;
					char *p1 = NULL;
					int len = nextHexToken(p, &p1);

					if(len/2 != hashSize)
							FLAG_ERR(kS4Err_CorruptData);

					size_t seedLen = sgetHexString(p1, seedBuf);
					if(seedLen != hashSize)
						FLAG_ERR(kS4Err_CorruptData);

					// copy the Seed to the MD buffers
					for(int i = 0; i< 4; i++)
					{
						MD[i] = XMALLOC(hashSize);
						COPY(seedBuf, MD[i], hashSize);
					}

			
				}
				else if(hasPrefix("[L", p))
				{
					int byteLen = 0;
					while (!(*p >= '0' && *p <= '9')) p++;
 					if( sscanf(p, "%d",   &byteLen)  != 1)
 						FLAG_ERR(kS4Err_CorruptData);

//					LEN = byteLen;

				}
				else if(hasPrefix("MD", p))
				{
					p+=2;
					char *p1 = NULL;
					int len = nextHexToken(p, &p1);

					uint8_t mdBuf[128] =  {0};

					if(len/2 != hashSize)
						FLAG_ERR(kS4Err_CorruptData);

					size_t mdLen = sgetHexString(p1, mdBuf);
					if(mdLen != hashSize)
						FLAG_ERR(kS4Err_CorruptData);

					for(int i = 0; i<1000; i++)
					{
						err = HASH_Reset(hash); CKERR;
						err = HASH_Update(hash, MD[(i)%4], hashSize); CKERR;
						err = HASH_Update(hash, MD[(i+1)%4], hashSize); CKERR;
						err = HASH_Update(hash, MD[(i+2)%4], hashSize); CKERR;
						err = HASH_Final(hash,  MD[(i+3)%4]); CKERR;
					}

					err = compareResults(mdBuf, MD[2], hashSize, base); CKERR;

					COPY( MD[2], MD[0], hashSize);
					COPY( MD[2], MD[1], hashSize);
					COPY( MD[2], MD[3], hashSize);

					testcount++;
				}
			}
			fclose ( file );
			PASSED = true;
		}
		else
		{
			err = kS4Err_FeatureNotAvailable;

		}


	}

done:
	if( HASH_ContextRefIsValid(hash))
		HASH_Free(hash);

	for(int i = 0; i< 4; i++)
	{
		if(MD[i] ) XFREE( MD[i] );
	}

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



