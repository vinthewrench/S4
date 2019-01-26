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



typedef struct  {
	ARGON2_Algorithm	algorithm;
	uint8_t  	passphrase [256];
	size_t 	  	passphraseLen;
	uint8_t     salt[256];
	size_t      saltLen;

	uint32_t	 t_cost;
	uint32_t	 m_cost;
	uint32_t 	 parallelism;

	uint8_t     key[64];
	size_t	 	keyLen;
}  argon2_kat_vector;


static S4Err RunArgon2_KAT( argon2_kat_vector *kat)
{
	S4Err err = kS4Err_NoErr;

	uint8_t     key[128];

	err = PASS_TO_KEY_ARGON2(kat->algorithm,
							 kat->passphrase, strlen((char*)kat->passphrase),
							 kat->salt, kat->saltLen ,
							 kat->t_cost, kat->m_cost, kat->parallelism,
							 key, kat->keyLen); CKERR;

	err = compareResults( kat->key, key, kat->keyLen , kResultFormat_Cstr, "ARGON2 PASS_TO_KEY");
	CKERR;


done:
	return err;

};


static S4Err runArgon2_Pairwise()
{
	S4Err err = kS4Err_NoErr;
	clock_t		start	= 0;
	double		elapsed	= 0;
	uint8_t     key[MSG_KEY_BYTES];

	argon2_kat_vector kat;
	uint8_t*    passphrase = NULL;

	kat.t_cost = 8;
	kat.m_cost = 1024;
	kat.parallelism = 2;

	kat.saltLen = 16;		// good saltlen = 16 bytes
	err = RNG_GetBytes(kat.salt, kat.saltLen); CKERR;

	err = RNG_GetPassPhrase(64,  (char **) kat.passphrase); CKERR;
	kat.passphraseLen = 64;

	start = clock();

	err = PASS_TO_KEY_ARGON2(kARGON2_Algorithm_Argon2id,
							 kat.passphrase, kat.passphraseLen,
							 kat.salt, kat.saltLen ,
							 kat.t_cost, kat.m_cost, kat.parallelism,
							 key, sizeof(key)); CKERR;


	elapsed = ((double) (clock() - start)) / CLOCKS_PER_SEC;
	OPTESTLogInfo("\t passes = %ld\n\t memory = %ld\n\t parallelism = %ld\n\t elapsed time %0.4f sec\n",
				  kat.t_cost, kat.m_cost, kat.parallelism,
				  elapsed);

	OPTESTLogInfo("\n");

done:

	if(passphrase)
		XFREE(passphrase) ;

	return err;

}
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


S4Err  TestPBKDF2()
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

S4Err  TestARGON2()
{
	S4Err     err = kS4Err_NoErr;

	argon2_kat_vector argon2_kat_vector_array[] =
	{

		// from phc-winner-argon2/src/test.c
		{
			kARGON2_Algorithm_Argon2i,
			"password", 8,
			"somesalt", 8,
			2,
			(uint32_t) 262144,
			1,
			{
				0x29, 0x6D, 0xBA, 0xE8, 0x0B, 0x80, 0x7C, 0xDC,
				0xEA, 0xAD, 0x44, 0xAE, 0x74, 0x1B, 0x50, 0x6F,
				0x14, 0xDB, 0x09, 0x59, 0x26, 0x7B, 0x18, 0x3B,
				0x11, 0x8F, 0x9B, 0x24, 0x22, 0x9B, 0xC7, 0xCB,
			},
			32
		},

 		{
			kARGON2_Algorithm_Argon2i,
			"password", 8,
			"somesalt", 8,
			2,
			(uint32_t) 256,
			1,
			{
				0x89, 0xE9, 0x02, 0x9F, 0x46, 0x37, 0xB2, 0x95,
				0xBE, 0xB0, 0x27, 0x05, 0x6A, 0x73, 0x36, 0xC4,
				0x14, 0xFA, 0xDD, 0x43, 0xF6, 0xB2, 0x08, 0x64,
				0x52, 0x81, 0xCB, 0x21, 0x4A, 0x56, 0x45, 0x2F,
			},
			32
		},
		{
			kARGON2_Algorithm_Argon2i,
			"password", 8,
			"somesalt", 8,
			2,
			(uint32_t) 256,
			2,
			{
				0x4F, 0xF5, 0xCE, 0x27, 0x69, 0xA1, 0xD7, 0xF4,
				0xC8, 0xA4, 0x91, 0xDF, 0x09, 0xD4, 0x1A, 0x9F,
				0xBE, 0x90, 0xE5, 0xEB, 0x02, 0x15, 0x5A, 0x13,
				0xE4, 0xC0, 0x1E, 0x20, 0xCD, 0x4E, 0xAB, 0x61,
			},
			32
		},
		{
			kARGON2_Algorithm_Argon2i,
			"differentpassword", 17,
			"somesalt", 8,
			2,
			(uint32_t) 65536,
			1,
			{
				0x14, 0xAE, 0x8D, 0xA0, 0x1A, 0xFE, 0xA8, 0x70,
				0x0C, 0x23, 0x58, 0xDC, 0xEF, 0x7C, 0x53, 0x58,
				0xD9, 0x02, 0x12, 0x82, 0xBD, 0x88, 0x66, 0x3A,
				0x45, 0x62, 0xF5, 0x9F, 0xB7, 0x4D, 0x22, 0xEE,
			},
			32
		},
		{
			kARGON2_Algorithm_Argon2i,
			"password", 8,
			"diffsalt", 8,
			2,
			(uint32_t) 65536,
			1,
			{
				0xB0, 0x35, 0x7C, 0xCC, 0xFB, 0xEF, 0x91, 0xF3,
				0x86, 0x0B, 0x0D, 0xBA, 0x44, 0x7B, 0x23, 0x48,
				0xCB, 0xEF, 0xEC, 0xAD, 0xAF, 0x99, 0x0A, 0xBF,
				0xE9, 0xCC, 0x40, 0x72, 0x6C, 0x52, 0x12, 0x71,
			},
			32
		},

		// compatibility tests
		{
			kARGON2_Algorithm_Argon2d,
			"password", 8,
			"somesalt", 8,
			2,
			(uint32_t) 4096,
			1,
			{
				0xDD, 0xF9, 0x48, 0x31, 0xB0, 0x65, 0xCE, 0x9E,
				0xC6, 0x72, 0xC2, 0x5B, 0xED, 0xE9, 0x92, 0x98,
				0x62, 0x8D, 0xDF, 0xB4, 0x17, 0xBA, 0xA7, 0x80,
				0x96, 0x80, 0x65, 0x8E, 0xAA, 0x3F, 0x56, 0xE0,
			},
			32
		},

		{
			kARGON2_Algorithm_Argon2d,
			"password", 8,
			"somesalt", 8,
			2,
			(uint32_t) 65536,
			1,
			{
				0x95, 0x5E, 0x5D, 0x5B, 0x16, 0x3A, 0x1B, 0x60,
				0xBB, 0xA3, 0x5F, 0xC3, 0x6D, 0x04, 0x96, 0x47,
				0x4F, 0xBA, 0x4F, 0x6B, 0x59, 0xAD, 0x53, 0x62,
				0x86, 0x66, 0xF0, 0x7F, 0xB2, 0xF9, 0x3E, 0xAF,
			},
			32
		},

		{
			kARGON2_Algorithm_Argon2id,
			"Some stupid password!", 21,
			"some stupid salt", 16,
			3,
			(uint32_t) 4096,
			1,
			{
				0xF1, 0x8D, 0x7F, 0xF0, 0x9E, 0xAC, 0x50, 0xD4,
				0x0C, 0xC4, 0x6F, 0x84, 0xE8, 0xCB, 0x1D, 0x28,
				0x15, 0xF1, 0x8B, 0xE4, 0x43, 0x3E, 0x4E, 0x10,
				0x20, 0x1A, 0xB0, 0x6B, 0xC0, 0x90, 0xE7, 0xC3,
			},
			32
		},

		{
			kARGON2_Algorithm_Argon2id,
			"Tant las fotei com auziretz", 27,
			{ 	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, },
			8,
			3,
			(uint32_t) 4096,
			1,
			{
				0xE8, 0x09, 0x44, 0x50, 0xD4, 0xA2, 0xF1, 0x38,
				0x71, 0x61, 0xAB, 0xDC, 0x7E, 0xB8, 0x3A, 0x77,
			},
			16
		},

		{
			kARGON2_Algorithm_Argon2id,
			"Hello. My name is Inigo Montoya. You killed my father. Prepare to die.",
			70,
			{ 	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, },
			8,
			3,
			(uint32_t) 4096,
			1,
			{
				0x74, 0x60, 0x2F, 0x5F, 0x5F, 0x80, 0x95, 0x7A,
				0x4F, 0xB4, 0x52, 0xA6, 0xE1, 0x01, 0x38, 0x3D,
			},
			16
		}
 
	};

	OPTESTLogInfo("\nTesting Argon2 KAT\n");

	for (int i = 0; i < sizeof(argon2_kat_vector_array)/ sizeof(argon2_kat_vector) ; i++)
	{
		err = RunArgon2_KAT( &argon2_kat_vector_array[i]); CKERR;
	}


	OPTESTLogInfo("\nTesting Argon2 Generation\n");
	err = runArgon2_Pairwise( ); CKERR;

done:
	return err;

}

S4Err  TestP2KAPI()
{
	S4Err     err = kS4Err_NoErr;
	P2K_Algorithm* algorithms;
	size_t algorCount = 0;

	P2K_ContextRef p2K = kInvalidP2K_ContextRef;

 	OPTESTLogInfo("\nTesting P2K API\n");

 	err = P2K_GetAvailableAlgorithms(&algorithms, &algorCount); CKERR;

	for(int i = 0; i < algorCount; i++)
	{
		P2K_Algorithm algor = algorithms[i];
		const char* name = "Invalid";

		uint8_t  	passphrase [256];
		size_t 	  	passphraseLen;
		size_t      saltLen;

		size_t      keyLen;
		uint8_t  	key[64];

		char* paramStr = NULL;;

		size_t      key1Len;
		uint8_t  	key1[64];

		err = P2K_GetName(algor, &name); CKERR;
		OPTESTLogInfo("%10s\t", name );

		err = P2K_Init(algor, &p2K); CKERR;

		saltLen = 8;		// good saltlen = 16 bytes
		passphraseLen = sizeof(passphrase) -1;

		keyLen = 32;

 		err = RNG_GetPassPhrase(passphraseLen,  (char **) passphrase); CKERR;

		err = P2K_EncodePassword(p2K, passphrase, passphraseLen, saltLen, keyLen, key, &paramStr); CKERR;

		OPTESTLogDebug(" %s \n", paramStr );
		dumpHex(IF_LOG_DEBUG, key,  (int)keyLen, 0);

 		P2K_Free(p2K);
		p2K = kInvalidP2K_ContextRef;

		err = P2K_DecodePassword(passphrase, passphraseLen, paramStr, key1, sizeof(key1), &key1Len); CKERR;

		// compare key and key1
 		err = compare2Results( key, keyLen, key1, key1Len , kResultFormat_Byte, "P2K_DecodePassword"); CKERR;

		OPTESTLogDebug("\t" );

		OPTESTLogInfo("✓\n");
	}


done:
	if( P2K_ContextRefIsValid(p2K))
		P2K_Free(p2K);

	if(algorithms)
		XFREE(algorithms);

	return err;

}

S4Err  TestKeysToPassPhrase()
{
	Cipher_Algorithm cipherAlgorithms[] =
	{
		kCipher_Algorithm_AES128,
/*		kCipher_Algorithm_AES192,   not supported  */
		kCipher_Algorithm_AES256,
		kCipher_Algorithm_2FISH256
	};

	S4Err     err = kS4Err_NoErr;
	P2K_Algorithm* passPhraseAlgorithms;
	size_t algorCount = 0;

	uint8_t    *eskData = NULL;
	size_t     eskDataLen = 0;

	uint8_t*  	key1 	= NULL;
	size_t      key1Len  = 0;

	uint8_t    *passCode = NULL;
	size_t     passCodeLen = 0;


	S4KeyContextRef     *importCtx = NULL;  // typically an array of contexts
	size_t      keyCount = 0;

 	OPTESTLogInfo("\nTesting Keys to PassPhrase\n");

	err = P2K_GetAvailableAlgorithms(&passPhraseAlgorithms, &algorCount); CKERR;

	for(int i = 0; i < algorCount; i++)
	{
		P2K_Algorithm passPhraseAlgorithm = passPhraseAlgorithms[i];
		const char* p2KName = "Invalid";
		const char* saltString = "Some Salt";

		uint8_t  	passphrase [256];
		const size_t  passphraseLen = sizeof(passphrase) -1;

		err = P2K_GetName(passPhraseAlgorithm, &p2KName); CKERR;
		OPTESTLogInfo("%10s\t", p2KName );

		err = RNG_GetPassPhrase(passphraseLen,  (char **) passphrase); CKERR;

		err = HASH_NormalizePassPhrase(passphrase,passphraseLen,
									   (uint8_t*)saltString, strlen(saltString),
									   &passCode, &passCodeLen); CKERR;

		for (int j = 0; j < sizeof(cipherAlgorithms)/ sizeof(Cipher_Algorithm) ; j++)
		{
			Cipher_Algorithm cipherAlgorithm = cipherAlgorithms[j];
			const char* 		cipherName = "Invalid";
			size_t              cipherSizeInBits = 0;
			size_t              cipherSizeInBytes = 0;
			uint8_t  	  		key[128];

			err = Cipher_GetName(cipherAlgorithm, &cipherName); CKERR;
			OPTESTLogInfo("%10s\t", cipherName );

			err = Cipher_GetKeySize(cipherAlgorithm, &cipherSizeInBits); CKERR;
			cipherSizeInBytes = cipherSizeInBits / 8;

			err = RNG_GetBytes(key,sizeof(key)); CKERR;

			err = P2K_EncryptKeyToPassPhrase( key, sizeof(key), cipherAlgorithm,
											   passCode, passCodeLen, passPhraseAlgorithm,
											   &eskData, &eskDataLen); CKERR;

			OPTESTLogDebug("\n------\n%s------\n",eskData);

			////////
			// the following is not a very useful thing to do in in this case,
			// its icluded for testing only.  the JSON produced above will deserialize into a ESK key
			// but you will not be able to ecode it this way since no object key is specifified.
			// you can verify the passcode but to decrypt the orginal key you need
			// to call P2K_DecryptKeyFromPassPhrase.

			err = S4Key_DeserializeKeys(eskData, eskDataLen, &keyCount, &importCtx ); CKERR;
			ASSERTERR(keyCount == 1,  kS4Err_SelfTestFailed);

			err = S4Key_VerifyPassCode(importCtx[0], passCode, passCodeLen); CKERR;

			///////

			err = P2K_DecryptKeyFromPassPhrase(eskData, eskDataLen,
												 passCode, passCodeLen,
												 &key1, & key1Len); CKERR;

			// compare key and key1
			err = compare2Results( key, sizeof(key), key1, key1Len ,
								  kResultFormat_Byte, "P2K_DecryptKeyFromPassPhrase"); CKERR;


			if(eskData)
			{
				XFREE(eskData);
				eskData = NULL;
			}

			if(key1)
			{
				XFREE(key1);
				key1 = NULL;
			}
		}

			if(passCode)
			{
				XFREE(passCode);
				passCode = NULL;
			}

		OPTESTLogDebug("\t" );

		OPTESTLogInfo("✓\n");
	}


done:

	if(importCtx)
	{
		if(S4KeyContextRefIsValid(importCtx[0]))
		{
			S4Key_Free(importCtx[0]);
		}
		XFREE(importCtx);
	}


	if(eskData)
		XFREE(eskData);

	if(passCode)
		XFREE(passCode);

	if(passPhraseAlgorithms)
		XFREE(passPhraseAlgorithms);

	return err;

}

S4Err  TestP2K()
{
	S4Err     err = kS4Err_NoErr;

   	err = TestP2KAPI(); CKERR;
	err = TestKeysToPassPhrase(); CKERR;
	err = TestARGON2(); CKERR;
	err = TestPBKDF2(); CKERR;

done:
	return err;

}

