//
//  s4PBKDF2.c
//  S4
//
//  Created by vincent Moscaritolo on 11/5/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//


#include "s4internal.h"


#ifdef __clang__
#pragma mark - PBKDF2  Password to Key
#endif


#define ROUNDMEASURE 10000
#define MIN_ROUNDS 1500

S4Err PASS_TO_KEY_SETUP(   unsigned long  password_len,
                        unsigned long  key_len,
                        uint8_t        *salt,
                        unsigned long  salt_len,
                        uint32_t       *rounds_out)
{
    S4Err    err         = kS4Err_NoErr;
    uint8_t     *password   = NULL;
    uint8_t     *key        = NULL;
    uint32_t    rounds = MIN_ROUNDS;
    
#if _USES_COMMON_CRYPTO_
    
    rounds = CCCalibratePBKDF(kCCPBKDF2,password_len, salt_len, kCCPRFHmacAlgSHA256, key_len, 100 );
    
    rounds = rounds > MIN_ROUNDS?rounds:MIN_ROUNDS;
    
    *rounds_out = rounds;
#else
    
    uint64_t	startTime, endTime, elapsedTime;
    
    
    uint64_t    msec = 100;   // 0.1s ?
    int i;
    
    // random password and salt
    password = XMALLOC(password_len);        CKNULL(password);
    key = XMALLOC(key_len);                  CKNULL(key);
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
    
    *rounds_out = rounds;
    
#endif
    
done:
    
    if(password) XFREE(password);
    if(key) XFREE(key);
    
    return err;
    
} // PASS_TO_KEY_SETUP()



S4Err PASS_TO_KEY (const uint8_t  *password,
                   unsigned long  password_len,
                   uint8_t       *salt,
                   unsigned long  salt_len,
                   unsigned int   rounds,
                   uint8_t        *key_buf,
                   unsigned long  key_len )

{
    S4Err    err     = kS4Err_NoErr;
    
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
                         salt,      salt_len,
                         rounds,    find_hash("sha256"),
                         key_buf,   &key_len); CKSTAT;
    
    
done:
    if(status != CRYPT_OK)
        err = sCrypt2S4Err(status);
    
#endif
    
    return err;
    
    
}
