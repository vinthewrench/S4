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
#include <libgen.h>
#include <unistd.h>

#include "cavpHashTest.h"
#include "cavputilities.h"
#include "cavpCipherTest.h"
#include "cavpHMACtest.h"

#include   <S4Crypto/S4Crypto.h>

S4Err cavpTestFile(char* path)
{
	char *base = basename((char *)path);

	S4Err err = kS4Err_NoErr;

 	if(hasPrefix("SHA", base))
	{
		if(	containsString("LongMsg", base)
		 ||  containsString("ShortMsg", base))
		{
 			err = cavpHashTestFile(path);
		}
		else if(containsString("Monte", base))
		{
 			err = cavpHashMonteTestFile(path);
		}
	}
	else if(hasPrefix("ECB", base) || hasPrefix("CBC", base))
	{
		err = cavpCipherTestFile(path);
	}
	else if(hasPrefix("HMAC", base))
	{
		err = cavpHMACTestFile(path);
	}


	return err;
}

void cavpRunTests(char* filePath)
{
	printf("Start SHA CAVP Test from %s\n",filePath);

	processVectors(cavpTestFile, filePath);

	printf("End SHA3 CAVP Test\n");

}

int main(int argc, const char * argv[]) {
	
	S4_Init();

	if( argc == 2 )
	{
		cavpRunTests( (char*)argv[1]);
	}
	else
	{
		char cwd[PATH_MAX];
		if (getcwd(cwd, sizeof(cwd)) != NULL) {
			strcat(cwd,"/KAT");
			cavpRunTests(cwd);
		}
	}
	return 0;
}
