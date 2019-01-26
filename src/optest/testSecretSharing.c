//
//  testSecretSharing.c
//  S4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "optest.h"


#define kNumShares				8
#define kShareThreshold			6


S4Err  TestSecretSharing()
{
   
    S4Err       err = kS4Err_NoErr;
    uint8_t     PT[kS4ShareInfo_MaxSecretBytes];
    uint8_t     PT1[sizeof (PT)];
    size_t      keyLen      = 0;

	S4SharesPartContext*   shareInfo[kNumShares] = {NULL};
    S4SharesPartContext*   testShares[kShareThreshold];
    uint8_t             testOffset[kShareThreshold];
    
    S4SharesContextRef   shareCTX  = kInvalidS4SharesContextRef;

    OPTESTLogInfo("\nTesting Shamir Key Spliting\n");
 
    // create a random key
    err = RNG_GetBytes(PT, sizeof(PT)); CKERR;
    
    OPTESTLogVerbose("\tKey Data: (%ld bytes)\n", kS4ShareInfo_MaxSecretBytes);
    dumpHex(IF_LOG_DEBUG, PT,  (int)sizeof (PT), 0);
    OPTESTLogDebug("\n");
 
    
    err = S4Shares_New( PT, sizeof(PT),
                      kNumShares,
                      kShareThreshold,
                      &shareCTX); CKERR;

    for(int i = 0; i < kNumShares; i++)
    {

        err = S4Shares_GetPart(shareCTX, i, &shareInfo[i]); CKERR;

		err = compare2Results(shareInfo[i]->shareOwner, kS4ShareInfo_HashBytes,
							  shareCTX->shareID, kS4ShareInfo_HashBytes,
							  kResultFormat_Byte, "Check Share Owner");  //CKERR;

        if(IF_LOG_VERBOSE)
        {
            OPTESTLogVerbose("\t  Share %d: x = %d\n", i, shareInfo[i]->xCoordinate);
            dumpHex(IF_LOG_DEBUG, shareInfo[i]->shareSecret  , (int)shareInfo[i]->shareSecretLen, 0);
            OPTESTLogDebug("\n");
        }

		/*  check shares for data leakage against known original message */
		if( CMP(shareInfo[i]->shareSecret,  PT,  shareInfo[i]->shareSecretLen ))
		{
			OPTESTLogError("\t Share data leakage against known original message...");
			RETERR(kS4Err_SelfTestFailed);
		}

	}
    
    // create threshold number of shares to test with
	createTestOffsets(testOffset, sizeof(testOffset));
    
    for(int i = 0; i < kShareThreshold; i++)
          testShares[i] = shareInfo[testOffset[i]];
  
 
    /* attempt to combine with not enough shares */
   err =  SHARES_CombineShareInfo(kShareThreshold -1, testShares, PT1, sizeof(PT1),
                             &keyLen);
    
    OPTESTLogVerbose("\t Attempt to combine with not enough shares = %s\n",
                     IsS4Err(err)?"fail":"pass");
    if(err == kS4Err_NotEnoughShares) err = kS4Err_NoErr;
    CKERR;
    
    /* Reconstruct data */
    OPTESTLogVerbose("\t Reconstructing data with just %d shares...",kShareThreshold);
  err = SHARES_CombineShareInfo(kShareThreshold, testShares, PT1, sizeof(PT1),
                              &keyLen); CKERR;

    OPTESTLogVerbose("OK\n");
    
    /*  check result against known original message */
    OPTESTLogVerbose("\t Check result against known original message...\n");
    err = compare2Results(PT, sizeof(PT), PT1, keyLen, kResultFormat_Byte, "SHAMIR Reconstruct");  //CKERR;

   
    OPTESTLogInfo("\n");
    
done:
    
    for(int i = 0; i < kNumShares; i++)
    {
        if(shareInfo[i])
			S4SharesPart_Free(shareInfo[i]);
    }
    
    if(S4SharesContextRefIsValid(shareCTX))
        S4Shares_Free(shareCTX);
    
    return err;
    
}
