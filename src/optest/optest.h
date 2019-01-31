//
//  optest.h
//  S4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef optest_h
#define optest_h

#include <stdio.h>
#include <S4Crypto/S4Crypto.h>


#ifdef __IPHONE_OS_VERSION_MIN_REQUIRED
#define OPTEST_IOS_SPECIFIC 1
#elif defined(__MAC_OS_X_VERSION_MIN_REQUIRED)
#define OPTEST_OSX_SPECIFIC 1
#endif

#define STRICMP		strcasecmp


#define ALLOC(_n) malloc(_n)
#define FREE(_p) free(_p)
#define REALLOC(_p,_n) realloc(_p, _n)



#define DO(x) do { run_cmd((x), __LINE__, __FILE__, #x); } while (0);
typedef enum
{
    kResultFormat_None  = 0,
    kResultFormat_Byte,
    kResultFormat_Long,
    kResultFormat_Cstr,
    
    
} DumpFormatType;


#define OPTESTLOG_FLAG_ERROR    (1 << 0)  // 0...0001
#define OPTESTLOG_FLAG_WARN     (1 << 1)  // 0...0010
#define OPTESTLOG_FLAG_INFO     (1 << 2)  // 0...0100
#define OPTESTLOG_FLAG_VERBOSE  (1 << 3)  // 0...1000
#define OPTESTLOG_FLAG_DEBUG    (1 << 4)  // 0...10000

#define OPTESTLOG_LEVEL_OFF     0
#define OPTESTLOG_LEVEL_ERROR   (OPTESTLOG_FLAG_ERROR)                                                    // 0...0001
#define OPTESTLOG_LEVEL_WARN    (OPTESTLOG_FLAG_ERROR | OPTESTLOG_FLAG_WARN)                                    // 0...0011
#define OPTESTLOG_LEVEL_INFO    (OPTESTLOG_FLAG_ERROR | OPTESTLOG_FLAG_WARN | OPTESTLOG_FLAG_INFO)                    // 0...0111
#define OPTESTLOG_LEVEL_VERBOSE (OPTESTLOG_FLAG_ERROR | OPTESTLOG_FLAG_WARN | OPTESTLOG_FLAG_INFO | OPTESTLOG_FLAG_VERBOSE) // 0...1111
#define OPTESTLOG_LEVEL_DEBUG   (OPTESTLOG_FLAG_ERROR | OPTESTLOG_FLAG_WARN | OPTESTLOG_FLAG_INFO | OPTESTLOG_FLAG_VERBOSE | OPTESTLOG_FLAG_DEBUG) // 0...11111

#define IF_LOG_ERROR   (gLogLevel & OPTESTLOG_FLAG_ERROR)
#define IF_LOG_WARN    (gLogLevel & OPTESTLOG_FLAG_WARN)
#define IF_LOG_INFO    (gLogLevel & OPTESTLOG_FLAG_INFO)
#define IF_LOG_VERBOSE (gLogLevel & OPTESTLOG_FLAG_VERBOSE)
#define IF_LOG_DEBUG   (gLogLevel & OPTESTLOG_FLAG_DEBUG)

#define OPTESTLogError(frmt, ...)   LOG_MAYBE(IF_LOG_ERROR,    frmt, ##__VA_ARGS__)
#define OPTESTLogWarn(frmt, ...)    LOG_MAYBE(IF_LOG_WARN,     frmt, ##__VA_ARGS__)
#define OPTESTLogInfo(frmt, ...)    LOG_MAYBE(IF_LOG_INFO,     frmt, ##__VA_ARGS__)
#define OPTESTLogVerbose(frmt, ...) LOG_MAYBE(IF_LOG_VERBOSE,  frmt, ##__VA_ARGS__)
#define OPTESTLogDebug(frmt, ...)   LOG_MAYBE(IF_LOG_DEBUG,    frmt, ##__VA_ARGS__)

#define LOG_MAYBE(  flg, frmt, ...) \
do { if(flg) OPTESTPrintF(frmt, ##__VA_ARGS__); } while(0)


extern unsigned int gLogLevel;

int OPTESTPrintF(const char *, ...);

const char *hash_algor_table(HASH_Algorithm algor);
const char *cipher_algor_table(Cipher_Algorithm algor);
const char* mac_algor_table(MAC_Algorithm algor);
const char *key_type_table(S4KeyType type);
size_t hash_algor_bits(HASH_Algorithm algor);



void dumpHex8(int logFlag,  uint8_t* buffer);
void dumpHex32(int logFlag,  uint8_t* buffer);
void dumpHex(int logFlag,  uint8_t* buffer, int length, int offset);
void dumpLong(int logFlag, uint8_t* buffer, int length);
void dumpKeyID(int logFlag,uint8_t* b );
void dumpTime(int logFlag, const time_t date );

void dumpByteConst( uint8_t* buffer, size_t length);  // used for creating consts;

int compareResults(const void* expected, const void* calculated, size_t len,
                   DumpFormatType format, const char* comment );

int compare2Results(const void* expected, size_t expectedLen,
                    const void* calculated, size_t  calculatedLen,
                    DumpFormatType format, const char* comment );

void createTestOffsets(uint8_t* array, int maxCount);


S4Err TestHash(void);
S4Err TestHMAC(void);
S4Err TestCiphers(void);
S4Err TestECC(void);
S4Err TestP2K(void);
S4Err TestTBCiphers(void);
S4Err TestSecretSharing(void);
S4Err TestKeys(void);
S4Err  TestUtilties(void);
#endif /* optest_h */
