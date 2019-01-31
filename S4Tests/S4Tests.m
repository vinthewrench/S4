//
//  S4Tests.m
//  S4Tests
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//


#import <TargetConditionals.h>

#ifdef __IPHONE_OS_VERSION_MIN_REQUIRED
#define OPTEST_IOS_SPECIFIC 1
#elif defined(__MAC_OS_X_VERSION_MIN_REQUIRED)
#define OPTEST_OSX_SPECIFIC 1
#endif

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#else
#import <Cocoa/Cocoa.h>
#endif

#import <XCTest/XCTest.h>
#include  "optest.h"
#include  <S4Crypto/S4Crypto.h>

#if TARGET_OS_IPHONE

void OutputString(char *s)
{
    
}
#endif



@interface S4Tests : XCTestCase

@end

@implementation S4Tests

unsigned int gLogLevel	= OPTESTLOG_LEVEL_ERROR;

-(void) CheckError: (S4Err) err
{
    NSString* errorStr = nil;
    
    if(IsS4Err(err))
    {
        char str[256];
        
        if(IsntS4Err( S4_GetErrorString(err, str)))
        {
            errorStr = [ NSString stringWithFormat:@"Error %d:  %s\n", err, str ];
        }
        else
        {
            errorStr = [ NSString stringWithFormat:@"Error %d\n", err ];
            
        }
        
        XCTFail(@"Fail: %@", errorStr);
        
    }
    
}

- (void)setUp {
    [super setUp];
    
    S4Err err = kS4Err_NoErr;
    
    err = S4_Init(); CKERR;
    // Put setup code here. This method is called before the invocation of each test method in the class.
    
done:
    
    [self CheckError:err];
    
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}


 

////////////////////////

- (void)testHash {
    // This is an example of a functional test case.
    S4Err err = kS4Err_NoErr;
    
    err = TestHash();CKERR;
    
done:
    
    [self CheckError:err];
}



- (void)testHMAC {
    // This is an example of a functional test case.
    S4Err err = kS4Err_NoErr;
    
    err = TestHMAC();CKERR;
    
done:
    
    [self CheckError:err];
}



- (void)testCiphers {
    // This is an example of a functional test case.
    S4Err err = kS4Err_NoErr;
    
    err = TestCiphers();CKERR;
    
done:
    
    [self CheckError:err];
}


- (void)testTBC {
    // This is an example of a functional test case.
    S4Err err = kS4Err_NoErr;
    
    err = TestTBCiphers();CKERR;
    
done:
    
    [self CheckError:err];
}


- (void)testECC {
    // This is an example of a functional test case.
    S4Err err = kS4Err_NoErr;
    
    err = TestECC();CKERR;
    
done:
    
    [self CheckError:err];
}


- (void)testP2K {
    // This is an example of a functional test case.
    S4Err err = kS4Err_NoErr;
    
    err = TestP2K();CKERR;
    
done:
    
    [self CheckError:err];
}


- (void)testSecretSharing {
     S4Err err = kS4Err_NoErr;
    
    err = TestSecretSharing();CKERR;
    
done:
    
    [self CheckError:err];
}



- (void)testUtilities {
    S4Err err = kS4Err_NoErr;
    
    err =TestUtilties();CKERR;
    
done:
    
    [self CheckError:err];
}



- (void)testKeys {
    S4Err err = kS4Err_NoErr;
    
    err =TestKeys();CKERR;
    
done:
    
    [self CheckError:err];
}



@end
