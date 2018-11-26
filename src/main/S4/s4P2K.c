//
//  s4P2K.c
//  S4
//
//  Created by vinnie on 10/3/18.
//  Copyright © 2018 4th-A Technologies, LLC. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <argon2.h>

#include "s4internal.h"

#ifdef __clang__
#pragma mark - P2K
#endif



typedef struct p2kArgonParams_
{
	uint32_t t_cost;
	uint32_t m_cost;
	uint32_t threads;
}p2kArgonParams;

typedef struct p2PBKDF2Params_
{
	uint32_t rounds;
 }p2PBKDF2Params ;


typedef struct P2K_Context    P2K_Context;

struct P2K_Context
{
#define kP2K_ContextMagic		0x7350324B
	uint32_t       		magic;
	P2K_Algorithm		algor;

	uint8_t*   			salt;
	size_t      		saltLen;

	size_t      		keyLen;

	union {
		p2kArgonParams argon2;
		p2PBKDF2Params pbkdf2;
	};
};


argon2_type argonTypeFromAlgorithm(P2K_Algorithm algor)
{
	switch(algor)
	{
		case kP2K_Algorithm_Argon2d: return Argon2_d;
		case kP2K_Algorithm_Argon2i: return Argon2_i;
		case kP2K_Algorithm_Argon2id: return Argon2_id;
		default: return -1;
	}
 }

static bool
sP2K_ContextIsValid( const P2K_ContextRef  ref)
{
	bool	valid	= false;

	valid	= IsntNull( ref ) && ref->magic	 == kP2K_ContextMagic;

	return( valid );
}

#define validateP2KContext( s )		\
ValidateParam( sP2K_ContextIsValid( s ) )


typedef struct S4P2KInfo_
{
	char      *const name;
	P2K_Algorithm algorithm;
	bool			available;
} S4P2KInfo;

static S4P2KInfo sP2KInfoTable[] = {

	{ "PBKDF2",    		kP2K_Algorithm_PBKDF2,	 	true},
	{ "Argon2d",   		kP2K_Algorithm_Argon2d,	 	true},
	{ "Argon2i",    	kP2K_Algorithm_Argon2i,	 	true},
	{ "Argon2id",    	kP2K_Algorithm_Argon2id,	true},

	{ NULL,    		kP2K_Algorithm_Invalid, 	 	false},
};


S4P2KInfo* sP2KInfoForAlgorithm(P2K_Algorithm algorithm)
{
	S4P2KInfo* info = NULL;

	for(S4P2KInfo* p2KInfo = sP2KInfoTable; p2KInfo->name; p2KInfo++)
	{
		if(algorithm == p2KInfo->algorithm)
		{
			info = p2KInfo;
			break;
		}
	}

	return info;
}


EXPORT_FUNCTION bool P2K_AlgorithmIsAvailable(P2K_Algorithm algorithm)
{
	bool isAvailable = false;

	S4P2KInfo* p2KInfo = sP2KInfoForAlgorithm(algorithm);
	if(p2KInfo)
	{
		isAvailable = p2KInfo->available;
	}
	return isAvailable;
}

EXPORT_FUNCTION  S4Err P2K_GetName(P2K_Algorithm algorithm, const char **p2kName)
{
	S4Err err = kS4Err_FeatureNotAvailable;

	S4P2KInfo* p2KInfo = sP2KInfoForAlgorithm(algorithm);
	if(p2KInfo)
	{
		if(p2kName)
			*p2kName = p2KInfo->name;
		err = kS4Err_NoErr;
	}

	return err;
}

EXPORT_FUNCTION S4Err P2K_GetAvailableAlgorithms(P2K_Algorithm **outAlgorithms, size_t *outCount)
{
	S4Err err = kS4Err_NoErr;

	size_t 			algorCount = 0;
	P2K_Algorithm  *p2kTable  =  NULL;

	for(S4P2KInfo* p2KInfo = sP2KInfoTable; p2KInfo->name; p2KInfo++)
		if(p2KInfo->name && p2KInfo->available)
			algorCount ++;

	if(algorCount)
		p2kTable = XMALLOC(algorCount * sizeof(P2K_Algorithm) );

	int i = 0;
	for(S4P2KInfo* p2KInfo = sP2KInfoTable; p2KInfo->name; p2KInfo++)
		if(p2KInfo->name && p2KInfo->available)
			p2kTable[i++] = p2KInfo->algorithm;

	if(outAlgorithms)
		*outAlgorithms = p2kTable;
	else if(p2kTable) XFREE(p2kTable);

	if(outCount)
		*outCount = algorCount;

	return err;
}




EXPORT_FUNCTION S4Err P2K_Init( P2K_Algorithm algorithm,
							   P2K_ContextRef * ctx)
{
	S4Err       	err = kS4Err_NoErr;
	P2K_Context*    p2kCTX = NULL;

	if(!P2K_AlgorithmIsAvailable(algorithm))
		RETERR(kS4Err_FeatureNotAvailable);

	ValidateParam(ctx);
	*ctx = NULL;

	p2kCTX = XMALLOC(sizeof (P2K_Context)); CKNULL(p2kCTX);

	p2kCTX->magic = kP2K_ContextMagic;
	p2kCTX->algor = algorithm;

	*ctx = p2kCTX;

done:

	if(IsS4Err(err))
	{
		if(IsntNull(p2kCTX))
		{
			XFREE(p2kCTX);
		}
	}

	return err;
}


EXPORT_FUNCTION void P2K_Free(P2K_ContextRef  ctx)
{
	if(sP2K_ContextIsValid(ctx))
	{
		if(ctx->salt)
		{
			if(ctx->saltLen)
				ZERO(ctx->salt, ctx->saltLen);
			XFREE(ctx->salt);
		}
		ZERO(ctx, sizeof(P2K_Context));
		XFREE(ctx);
	}
}

EXPORT_FUNCTION S4Err P2K_GetAlgorithm(P2K_ContextRef ctx, P2K_Algorithm *algorithm)
{
	S4Err             err = kS4Err_NoErr;

	validateP2KContext(ctx);

	if(algorithm)
		*algorithm = ctx->algor;

	return err;
}



/*
 Number of iterations t, affecting the time cost.
 Size of memory used m, affecting the memory cost.
 Number of threads h, affecting the degree of parallelism.

argon2d uses data-dependent accesses for presumably stronger tradeoff resistance,
argon2i eschews them to avoid side channel attacks.  recommended for password-hashing.

 */

static S4Err s4calculateArgonParams( argon2_type argonType,
									 size_t  password_len,
									 size_t  key_len,
									 size_t  salt_len,
									uint32_t	*t_cost_out,
									uint32_t    *m_cost_out,
									uint32_t    *parallelism_out
 									)
{
	S4Err    err         = kS4Err_NoErr;

	uint32_t t_cost = 2;    		 /* one pass */
	uint32_t m_cost = 65536;    /*  bytes */
	uint32_t threads = 1;   	/* one thread version */

	switch (argonType) {
		case Argon2_i:
				break;

		case Argon2_d:

			break;

		case Argon2_id:
			break;

		default:
			err = kS4Err_FeatureNotAvailable;
			break;
	}
done:

	if(t_cost_out)
		*t_cost_out = t_cost;

	if(m_cost_out)
		*m_cost_out = m_cost;

	if(parallelism_out)
		*parallelism_out = threads;

	return err;

}

#define ROUNDMEASURE 10000
#define MIN_ROUNDS 1500

static S4Err s4calculatePBKDF2Params(   size_t  password_len,
										size_t  key_len,
										size_t  salt_len,
										uint32_t *rounds_out)
{
	S4Err    err         = kS4Err_NoErr;
	uint8_t     *password   = NULL;
	uint8_t     *key        = NULL;
	uint8_t     *salt        = NULL;
	uint32_t    rounds = MIN_ROUNDS;

#if _USES_COMMON_CRYPTO_

	rounds = CCCalibratePBKDF(kCCPBKDF2,password_len, salt_len, kCCPRFHmacAlgSHA256, key_len, 100 );

	rounds = rounds > MIN_ROUNDS?rounds:MIN_ROUNDS;

#else

	uint64_t	startTime, endTime, elapsedTime;


	uint64_t    msec = 100;   // 0.1s ?
	int i;

	// random password and salt
	password = XMALLOC(password_len);        CKNULL(password);
	key = XMALLOC(key_len);                  CKNULL(key);
	salt = XMALLOC(salt_len);              	 CKNULL(salt);

	err = RNG_GetBytes( password, password_len ); CKERR;
	err = RNG_GetBytes( salt, salt_len ); CKERR;

	// run and calculate elapsed time.
	for(elapsedTime = 0, i=0; i < 10 && elapsedTime == 0; i++)
	{
		startTime = clock();

		err = PASS_TO_KEY (password, password_len, salt, salt_len, ROUNDMEASURE, key, key_len); CKERR;

		endTime = clock();

		elapsedTime = endTime - startTime;
	}

	if(elapsedTime == 0)
		RETERR(kS4Err_UnknownError);

	// How many rounds to use so that it takes 0.1s ?
	rounds = (uint32_t) ((uint64_t)(msec * ROUNDMEASURE * 1000) / elapsedTime);
	rounds = rounds > MIN_ROUNDS?rounds:MIN_ROUNDS;

#endif

	if(rounds_out)
		*rounds_out = rounds;

done:

	if(password) XFREE(password);
	if(key) XFREE(key);
	if(salt) XFREE(salt);

	return err;

}


static S4Err sCalculateParams(P2K_ContextRef  ctx,
 							   size_t  	password_len,
 							   size_t	salt_len,
							   size_t	key_len)
{
	S4Err             err = kS4Err_NoErr;

	validateP2KContext(ctx);

	switch (ctx->algor)
	{
		case kP2K_Algorithm_PBKDF2:
		{
 			err = s4calculatePBKDF2Params(password_len,salt_len,key_len,
										  &ctx->pbkdf2.rounds); CKERR;
	}
			break;

		case kP2K_Algorithm_Argon2d:
		case kP2K_Algorithm_Argon2i:
		case kP2K_Algorithm_Argon2id:
		{
 			err = s4calculateArgonParams(argonTypeFromAlgorithm(ctx->algor), password_len,salt_len,key_len,
										  	&ctx->argon2.t_cost,
										 	&ctx->argon2.m_cost,
										 	&ctx->argon2.threads); CKERR;
		}
			break;


		default:
			err = kS4Err_FeatureNotAvailable;
			break;
	}

	ctx->keyLen = key_len;

done:
	return err;

}

static S4Err sCalculateKey(P2K_ContextRef	ctx,
						   const uint8_t 	*password,
						   size_t  			password_len,
						   size_t		 	key_len,
						   uint8_t       	*key_buf)
{
	S4Err             err = kS4Err_NoErr;

	validateP2KContext(ctx);

	switch (ctx->algor)
	{
		case kP2K_Algorithm_PBKDF2:
		{
#if _USES_COMMON_CRYPTO_

			if( CCKeyDerivationPBKDF( kCCPBKDF2, (const char*)password,  password_len,
									 salt, salt_len,
									 kCCPRFHmacAlgSHA256, rounds,
									 key_buf,   key_len)
			   != kCCSuccess)
				err = kS4Err_BadParams;


#else
			int         status  = CRYPT_OK;

			status = pkcs_5_alg2(password, password_len,
								 ctx->salt, ctx->saltLen,
								 ctx->pbkdf2.rounds,
								 find_hash("sha256"),
								 key_buf,   &key_len); CKSTAT;
			if(status != CRYPT_OK)
				err = sCrypt2S4Err(status);

#endif

 		}

			break;

		case kP2K_Algorithm_Argon2d:
		case kP2K_Algorithm_Argon2i:
		case kP2K_Algorithm_Argon2id:
		{

			int  status  = ARGON2_OK;

			status = argon2_hash(ctx->argon2.t_cost,
								 ctx->argon2.m_cost,
								 ctx->argon2.threads,
								 password, password_len,
								 ctx->salt, ctx->saltLen,
								 (void*)key_buf, key_len,
								 NULL, 0,
								 (argon2_type) argonTypeFromAlgorithm(ctx->algor),
								 ARGON2_VERSION_NUMBER);

			if(status != ARGON2_OK)
				err = kS4Err_BadParams;

 		}
			break;


		default:
			err = kS4Err_FeatureNotAvailable;
			break;
	}

done:
	return err;

}

static S4Err sEncodeParams(P2K_ContextRef ctx,
						  uint_8t *buffer, size_t bufLen, size_t *bufUsedOut )
{
	S4Err             err = kS4Err_NoErr;

	validateP2KContext(ctx);

	S4P2KInfo* p2KInfo = sP2KInfoForAlgorithm(ctx->algor);
	if(!p2KInfo)
		RETERR(kS4Err_UnknownError);

	size_t used = 0;
	uint_8t *p = buffer;
	*p = '\0';

#define SS(str)           						\
	do {										\
		  size_t pp_len = strlen(str);			\
		  if(bufLen - (p - buffer) < pp_len )		\
			  RETERR(kS4Err_BufferTooSmall);	\
		  memcpy(p, str, pp_len + 1);			\
		  p += pp_len;                    		\
		} while ((void)0, 0)					\

#define SX(x)                              		 	\
    do {                                		 	\
        char tmp[30];                      		 	\
        sprintf(tmp, "%lu", (unsigned long)(x));  	\
        SS(tmp);                     				\
    } while ((void)0, 0)


#define SB(buf, len)                    			\
	do {											\
		size_t tempLen = bufLen - (p - buffer);		\
		if(bufLen - (p - buffer) < len )			\
			RETERR(kS4Err_BufferTooSmall);			\
		base64_encode(buf, len, p, &tempLen);		\
		p+=tempLen;									\
	} while ((void)0, 0);

	SS("$");
	SS(p2KInfo->name);

	switch (ctx->algor)
	{
		case kP2K_Algorithm_PBKDF2:
		{
			SS("$r=");
			SX(ctx->pbkdf2.rounds);
			SS(",k=");
			SX(ctx->keyLen);
		}
			break;
		case kP2K_Algorithm_Argon2d:
		case kP2K_Algorithm_Argon2i:
		case kP2K_Algorithm_Argon2id:
		{
			SS("$m=");
			SX(ctx->argon2.m_cost);
			SS(",t=");
			SX(ctx->argon2.t_cost);
			SS(",p=");
			SX(ctx->argon2.threads);
			SS(",k=");
			SX(ctx->keyLen);
		}
			break;

		default:
			err = kS4Err_FeatureNotAvailable;
			break;

	}


	SS("$");
	SB(ctx->salt, ctx->saltLen );

	used = p-buffer;

	if(bufUsedOut)
		*bufUsedOut = used;

done:
	return err;

#undef SS
#undef SX
#undef SB

}

EXPORT_FUNCTION S4Err P2K_EncodePassword(P2K_ContextRef  ctx,
						 const uint8_t 	 	*password,
						 size_t  			password_len,
						 size_t		 	 	salt_len,
						 size_t		 	 	key_len,
						 uint8_t 			*key_buf,
						 char*				*paramStr
 						 )
{
	S4Err             err = kS4Err_NoErr;
	validateP2KContext(ctx);

	ValidateParam(password);
	ValidateParam(key_buf);

	uint_8t 	paramBuf[128];
	size_t		paramBufLen = 0;

	err = sCalculateParams(ctx, password_len,salt_len, key_len);CKERR;

	ctx->saltLen = salt_len;
	ctx->salt = XMALLOC(salt_len); CKNULL(ctx->salt);
	err = RNG_GetBytes(ctx->salt, ctx->saltLen); CKERR;

	err = sCalculateKey(ctx,password, password_len,key_len, key_buf); CKERR;

	err = sEncodeParams(ctx, paramBuf, sizeof(paramBuf), &paramBufLen );

	if(paramStr)
	{
		*paramStr =  XMALLOC(paramBufLen + 1);
		memcpy((void *)*paramStr, paramBuf, paramBufLen + 1);
	}

done:


	return err;

}


/*
 * Decode decimal integer from 'str'; the value is written in '*v'.
 * Returned value is a pointer to the next non-decimal character in the
 * string. If there is no digit at all, or the value encoding is not
 * minimal (extra leading zeros), or the value does not fit in an
 * 'unsigned long', then NULL is returned.
 */
static const char *decode_decimal(const char *str, unsigned long *v) {
	const char *orig;
	unsigned long acc;

	acc = 0;
	for (orig = str;; str++) {
		int c;

		c = *str;
		if (c < '0' || c > '9') {
			break;
		}
		c -= '0';
		if (acc > (ULONG_MAX / 10)) {
			return NULL;
		}
		acc *= 10;
		if ((unsigned long)c > (ULONG_MAX - acc)) {
			return NULL;
		}
		acc += (unsigned long)c;
	}
	if (str == orig || (*orig == '0' && str != (orig + 1))) {
		return NULL;
	}
	*v = acc;
	return str;
}

static S4Err sDecodeParams(P2K_ContextRef ctx,
						   const char *str )
{
	S4Err             err = kS4Err_NoErr;

	validateP2KContext(ctx);

	char* string = strdup((const char*)str);
	char *tofree = string;
	char *token = NULL;
	size_t tokenLen = 0;

	CKNULL(tofree);
	// code here to decode and fill ctx

	//  $PBKDF2$r=3611,k=32$C0hmMC1wfRc=
	//  $Argon2i$m=65536,t=2,p=1,k=32$hr6+JwvrqbI=
	//  $Argon2d$m=65536,t=2,p=1,k=32$5lcKHbxA140=
	//	$Argon2id$m=65536,t=2,p=1,k=32$vD040j4s764=

	/* check for $ prefix */
 	string = strpbrk(string, "$");
	if(!string)
		RETERR(kS4Err_CorruptData);

	string++;

	//get first Token
	token = strsep(&string, "$");
	tokenLen = strlen(token);

	if(strncmp(token, "PBKDF2", 6) == 0)
	   ctx->algor = kP2K_Algorithm_PBKDF2;
	else if(strncmp(token, "Argon2id", 8)== 0)
		ctx->algor = kP2K_Algorithm_Argon2id;
	else if(strncmp(token, "Argon2i", 7)== 0)
		ctx->algor = kP2K_Algorithm_Argon2i;
	else if(strncmp(token, "Argon2d", 7)== 0)
		ctx->algor = kP2K_Algorithm_Argon2d;
	else
		RETERR(kS4Err_CorruptData);

	// parse options
	token = strsep(&string, "$");
	if(!token )
		RETERR(kS4Err_CorruptData);
	tokenLen = strlen(token);
	if(tokenLen == 0) RETERR(kS4Err_CorruptData);

	if(ctx->algor == kP2K_Algorithm_PBKDF2)
	{
		unsigned long dec_x;                                                   \
		bool foundR = false;
		bool foundK = false;

		const char *p = NULL;

		if((p = strnstr(token, "r=", tokenLen)))
		{
			p+=2;
			p = decode_decimal(p, &dec_x);
			CKNULL(p);
			ctx->pbkdf2.rounds = (uint32_t)dec_x;
			foundR = true;
  		}

		if((p = strnstr(token, "k=", tokenLen)))
		{
			p+=2;
			p = decode_decimal(p, &dec_x);
			CKNULL(p);
			ctx->keyLen = (uint32_t)dec_x;
			foundK = true;
 		}

		if(!(foundR && foundK))
			RETERR(kS4Err_CorruptData);
  	}
	else  if(ctx->algor == kP2K_Algorithm_Argon2id
			 || ctx->algor == kP2K_Algorithm_Argon2i
			 || ctx->algor == kP2K_Algorithm_Argon2d)
	{
		unsigned long dec_x;                                                   \
		bool foundM = false;
		bool foundT = false;
		bool foundP = false;
		bool foundK = false;

		const char *p = NULL;

		if((p = strnstr(token, "m=", tokenLen)))
		{
			p+=2;
			p = decode_decimal(p, &dec_x);
			CKNULL(p);
			ctx->argon2.m_cost = (uint32_t)dec_x;
			foundM = true;
		}

		if((p = strnstr(token, "t=", tokenLen)))
		{
			p+=2;
			p = decode_decimal(p, &dec_x);
			CKNULL(p);
			ctx->argon2.t_cost = (uint32_t)dec_x;
			foundT = true;
		}

		if((p = strnstr(token, "p=", tokenLen)))
		{
			p+=2;
			p = decode_decimal(p, &dec_x);
			CKNULL(p);
			ctx->argon2.threads = (uint32_t)dec_x;
			foundP = true;
		}

		if((p = strnstr(token, "k=", tokenLen)))
		{
			p+=2;
			p = decode_decimal(p, &dec_x);
			CKNULL(p);
			ctx->keyLen = (uint32_t)dec_x;
			foundK = true;
		}

		if(!(foundM && foundT && foundP && foundK))
			RETERR(kS4Err_CorruptData);
	}

	else
		RETERR(kS4Err_UnknownError);

	// parse salt
	token = strsep(&string, "$");
	if(!token )
		RETERR(kS4Err_CorruptData);
	tokenLen = strlen(token);
	if(tokenLen == 0) RETERR(kS4Err_CorruptData);

	{
		uint8_t     saltBuf[128];
		unsigned long saltLen = sizeof(saltBuf);

		if( base64_decode((const unsigned char*)token, strlen(token), saltBuf, &saltLen)  == CRYPT_OK)
		{
			// good salt
			ctx->saltLen = saltLen;
			ctx->salt = XMALLOC(saltLen); CKNULL(ctx->salt);
			COPY(saltBuf, ctx->salt, saltLen);
		}
		else
			RETERR(kS4Err_CorruptData);

	}



done:

	if(tofree)
		XFREE(tofree);

	return err;
}


S4Err P2K_DecodePassword( 	const uint8_t 	 *password,
						 size_t  			password_len,
						 const char			*paramStr,
						 void *outKey, 	size_t bufSize, size_t *keySize
						 )
{
	S4Err             err = kS4Err_NoErr;

	P2K_Context*    ctx = NULL;

	ValidateParam(password);
	ValidateParam(paramStr);

	// parse paramStr  and decode values/


	ctx = XMALLOC(sizeof (P2K_Context)); CKNULL(ctx);
	ctx->magic = kP2K_ContextMagic;

	err = sDecodeParams(ctx,paramStr); CKERR;

	if(ctx->keyLen > bufSize)
		RETERR(kS4Err_BufferTooSmall);

	err = sCalculateKey(ctx,password, password_len, ctx->keyLen, outKey); CKERR;

	if(keySize)
		*keySize = ctx->keyLen;

done:
	if(IsntNull(ctx))
	{
		XFREE(ctx);
	}

	return err;

}

