//
//  cavputilities.h
//  cryptotest
//
//  Created by vinnie on 9/13/18.
//  Copyright © 2018 4th-a. All rights reserved.
//

#ifndef cavputilities_h
#define cavputilities_h

#include   <S4Crypto/S4Crypto.h>

#define	ishex(c)	(((uint8_t)(c)) >= '0' && ((uint8_t)(c)) <= '9' || ((uint8_t)(c)) >= 'a' && ((uint8_t)(c)) <= 'f')

#define CMP(b1, b2, length)							\
(memcmp((void *)(b1), (void *)(b2), (length)) == 0)

#define FLAG_ERR(_err)   \
{err = _err;   \
goto done; }

#define FREE_AND_NULL(arg) {if((arg))XFREE((arg)); (arg) = NULL;}

void dumpHex(uint8_t* buffer, int length, int offset);
int compareResults(const void* expected, const void* calculated, size_t len,  char* comment  );

char *extname (const char *name);

bool hasPrefix(const char *pre, const char *str);
bool containsString(const char *pre, const char *str);
char* skiptohex(char *s1);
int sgetHexString(char *s, unsigned char *p);
int nextHexToken(char *s1, char **outP);

typedef S4Err (*algorTestProcPtr)( char* path);
S4Err processVectors( algorTestProcPtr testProc,  char *path);

#endif /* cavputilities_h */
