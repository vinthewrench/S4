//
//  c4Keys.h
//  C4
//
//  Created by vincent Moscaritolo on 11/10/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef c4Keys_h
#define c4Keys_h

#include "c4pubtypes.h"

#ifdef __clang__
#pragma mark - Key import Export.
#endif


typedef struct C4Key_Context *      C4KeyContextRef;

#define	kInvalidC4KeyContextRef		((C4KeyContextRef) NULL)

#define C4KeyContextRefIsValid( ref )		( (ref) != kInvalidC4KeyContextRef )


C4Err C4Key_NewSymmetric(Cipher_Algorithm       algorithm,
                         const void             *key,
                         C4KeyContextRef    *ctx);

C4Err C4Key_NewTBC(     TBC_Algorithm       algorithm,
                   const void          *key,
                   C4KeyContextRef     *ctx);

void C4Key_Free(C4KeyContextRef ctx);


C4Err C4Key_EncryptToPassPhrase(C4KeyContextRef  ctx,
                                const char       *passphrase,
                                size_t           passphraseLen,
                                uint8_t          **outData,
                                size_t           *outSize);


#endif /* c4Keys_h */
