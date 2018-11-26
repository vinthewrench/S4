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
#include <ctype.h>
#include <errno.h>

#include "cavputilities.h"



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


S4Err compareResults(const void* expected, const void* calculated, size_t len,  char* comment  )
{
	S4Err err = kS4Err_NoErr;

	err = CMP(expected, calculated, len)
	? kS4Err_NoErr : kS4Err_SelfTestFailed;

	if((err != kS4Err_NoErr))
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
 
char *extname (const char *name)
{
	const char *ext;
	for (ext = name + strlen(name) ; ext != name && ( *ext != '.' &&  *ext != '/') ; ext--);
	if(ext == name ) return 0;
	else return (char*)(ext+1);
}


#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

S4Err processVectors( algorTestProcPtr testProc,  char *path)
{
	S4Err			err			= 0;
	S4Err			err1		= 0;

	struct stat  statbuf;
	char pathbuf[256];
	int	unixerr = 0;
	char	*ext = NULL;

	if ( !(unixerr = stat(path, &statbuf)))
	{
		if(statbuf.st_mode & S_IFDIR)
		{
			struct dirent **namelist;
			int i,n;

			n = scandir(path, &namelist, 0, alphasort);
			if (n < 0)
			{
				perror("scandir");
				perror(strerror(errno));
			}
			else
			{
				for (i = 0; i < n; i++)
				{
					sprintf(pathbuf,"%s/%s", path,namelist[i]->d_name);

					if (!stat(pathbuf, &statbuf) &&  statbuf.st_mode & S_IFREG)
					{
						ext = extname(namelist[i]->d_name);
						if(!ext || *ext == 0)  continue;
						if(/* (strcmp("req", ext) == 0)  || (strcmp("sam", ext) == 0) || (strcmp("txt", ext) == 0)  || */ (strcmp("rsp", ext) == 0))
							err1 = (*testProc)( pathbuf);
						if( (err1)) err = err1;
					}

					free(namelist[i]);
				}
			}
			free(namelist);

		}
		else if(statbuf.st_mode & S_IFREG)
		{
			err = (*testProc )( path);
		}
	}
	if(unixerr)
	{
		perror(strerror(errno));
	}

	return err;
}


bool hasPrefix(const char *pre, const char *str)
{
	return strncmp(pre, str, strlen(pre)) == 0;
}

bool containsString(const char *pre, const char *str)
{
	return strstr(str, pre) != NULL;
}


int nextHexToken(char *s1, char **outP)
{
	char *p = s1;
	int length = 0;

	while( *p && !ishex(*p) ) p++;

	for(length = 0; ishex( p[length]);  length++);

	if(outP)
		*outP = p;

	return length;

}

char* skiptohex(char *s1)
{
	while( *s1 && !ishex(*s1) ) s1++;
	return s1;
}

int sgetHexString(char *s, unsigned char *p)
{
	int len;

	for(len = 0; ishex(*s); p++, len++)
	{
		*p = (( *s++ | 4400 ) % 55) << 4;
		if( ishex(*s)) *p = *p | ( *s++ | 4400 ) % 55;
	}

	return len;
}

