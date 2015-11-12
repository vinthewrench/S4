//
//  testSecretSharing.c
//  C4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "c4.h"
#include "optest.h"
 #include <stdlib.h>



#define PTsize                  32
#define kNumShares				8
#define kShareThreshold			6


//* create fill this array with unique numbers from 0 to maxCount

void sCreateTestOffsets(uint8_t* array, int maxCount)
{
    int i;
    
      for(i = 0; i< maxCount; i++) array [i]= 0xff;

    /* pick the shares to test against */
    for(i = 0; i< maxCount; i++)
    {
        uint8_t r =  random() % maxCount;
        
        if(i == 0)  array[0] = r;
        else
        {
            int j;
            bool xOK = false;
            while (!xOK)
            {
                for(j = 0; j <= i; j++)
                {
                    if(array[j] == r)  break;
                    if(j == i)
                    {
                        array[i] = r;
                        xOK = true;
                    }
                }
                 r = random() % maxCount;
             }
        }
    }
    
    
  }

C4Err  TestSecretSharing()
{
   
    C4Err       err = kC4Err_NoErr;
    uint8_t     PT[PTsize];
    uint8_t     PT1[sizeof (PT)];
    size_t      keyLen      = 0;

    void*       shares[kNumShares];
    uint8_t     testOffset[kShareThreshold];
    void*       testShares[kShareThreshold];
     
    SHARES_ContextRef   shareCTX  = NULL;
    
      uint32_t 	i;

    
    OPTESTLogInfo("\nTesting Shamir Key Spliting\n");
 
    // create a random key
    err = RNG_GetBytes(PT, sizeof(PT)); CKERR;
    
    OPTESTLogVerbose("\t\tKey Data: (%ld bytes)\n", PTsize);
    dumpHex(IF_LOG_DEBUG, PT,  (int)sizeof (PT), 0);
    OPTESTLogDebug("\n");
 
    
    err = SHARES_Init( PT, sizeof(PT),
                      kNumShares,
                      kShareThreshold,
                      &shareCTX); CKERR;
 
    for(i = 0; i < kNumShares; i++)
    {
        size_t shareLen = 0;
        
        err = SHARES_GetShare(shareCTX, i, &shares[i], &shareLen); CKERR;
      
        if(IF_LOG_VERBOSE)
        {
            OPTESTLogVerbose("\t  Share %d: (%d bytes)\n", i,shareLen);
            dumpHex(IF_LOG_DEBUG, shares[i]  , (int)shareLen, 0);
        
            OPTESTLogVerbose("\n");
        }
        
        
//        OPTESTLogVerbose("\t Check shares for data leakage against known original message...");
//             /*  check shares for data leakage against known original message */
//            err = CMP(shareBuf+(shareSize *i) + kSHAMIR_HEADERSIZE,
//                      PT,  sizeof (PT))
//            ? kC4Err_SelfTestFailed : kC4Err_NoErr;
//            CKERR;
    
      }
    
    // create threshold number of shares to test with
    sCreateTestOffsets(testOffset, sizeof(testOffset));
    
    for(i = 0; i < kShareThreshold; i++)
          testShares[i] = shares[testOffset[i]];
    
  /* attempt to combine with not enough shares */
   err =  SHARES_ShareCombine(kShareThreshold -1, testShares, PT1, sizeof(PT1),
                             &keyLen);
    
    OPTESTLogVerbose("\t Attempt to combine with not enough shares = %s\n",
                     IsC4Err(err)?"fail":"pass");
    if(err == kC4Err_NotEnoughShares) err = kC4Err_NoErr;
    CKERR;
    
    /* Reconstruct data */
    OPTESTLogVerbose("\t Reconstructing data with just %d shares...",kShareThreshold);
  err = SHARES_ShareCombine(kShareThreshold, testShares, PT1, sizeof(PT1),
                              &keyLen); CKERR;

    OPTESTLogVerbose("OK\n");
    
    /*  check result against known original message */
    OPTESTPrintF("\t Check result against known original message...\n");
    err = compare2Results(PT, sizeof(PT), PT1, keyLen, kResultFormat_Byte, "SHAMIR Reconstruct");  //CKERR;

    
done:
    if(SHARES_ContextRefIsValid(shareCTX))
        SHARES_Free(shareCTX);
    
    return err;
    
}