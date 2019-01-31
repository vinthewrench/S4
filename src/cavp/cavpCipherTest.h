//
//  cavpCipherTest.h
//  S4-cavp
//
//  Created by vinnie on 9/25/18.
//  Copyright © 2018 4th-A Technologies, LLC. All rights reserved.
//

#ifndef cavpCipherTest_h
#define cavpCipherTest_h

#include <stdio.h>
#include <S4Crypto/S4Crypto.h>

S4Err cavpCipherCBCTestFile(char* filePath);
S4Err cavpCipherTestFile(char* filePath);

#endif /* cavpCipherTest_h */
