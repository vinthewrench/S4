//
//  optestutilities.c
//  S4
//
//  Created by vincent Moscaritolo on 11/2/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//
 
#include <stdio.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>


#ifndef __USE_BSD
#define __USE_BSD
#include <time.h>
#undef __USE_BSD
#endif


#if defined(ANDROID)
#include "timegm.c"
#endif

#include "optest.h"

void OutputString(char *s);

#ifdef OPTEST_IOS_SPECIFIC

#elif defined(OPTEST_OSX_SPECIFIC) || (OPTEST_LINUX_SPECIFIC) ||  (EMSCRIPTEN)

#ifndef INXCTEST

void OutputString(char *s)
{
    printf( "%s",s);
}

#endif
#endif



int OPTESTPrintF( const char *fmt, ...)
{
    va_list marker;
    char s[8096];
    int len;
    
    va_start( marker, fmt );
    len = vsprintf( s, fmt, marker );
    va_end( marker );
    
    OutputString(s);
    
    return 0;
}

int OPTESTVPrintF( const char *fmt, va_list marker)
{
    char s[8096];
    int	len;
    
    len = vsprintf( s, fmt, marker );
    
    OutputString(s);
    
    return 0;
}

void dumpHex8(int logFlag,  uint8_t* buffer)
{
    char hexDigit[] = "0123456789ABCDEF";
    register int			i;
    const unsigned char	  *bufferPtr = buffer;
    
    if(!logFlag) return;
    
    for (i = 0; i < 8; i++){
        OPTESTPrintF( "%c",  hexDigit[ bufferPtr[i] >>4]);
        OPTESTPrintF("%c",  hexDigit[ bufferPtr[i] &0xF]);
        if((i) &0x01) OPTESTPrintF("%c", ' ');
    }
    
}


void dumpHex32(int logFlag,  uint8_t* buffer)
{
    char hexDigit[] = "0123456789ABCDEF";
    register int			i;
    const unsigned char	  *bufferPtr = buffer;
    
    if(!logFlag) return;
    
    for (i = 0; i < 32; i++){
        OPTESTPrintF( "%c",  hexDigit[ bufferPtr[i] >>4]);
        OPTESTPrintF( "%c",  hexDigit[ bufferPtr[i] &0xF]);
        if((i) &0x01) OPTESTPrintF( "%c", ' ');
    }
    
}

void dumpByteConst( uint8_t* buffer, size_t length)
{
#define kLineSize	8
    
    printf("\n");
    
    for( int count = 0; length;  buffer++, length--)
    {
        bool newLine = (++count == kLineSize);
        
        printf("0x%02x%s%s",
               *buffer,
               length > 1?",":"",
               newLine? "\n":"");
        
        if(newLine) count = 0;
    }
    printf("\n");
    
}

void dumpHex(int logFlag,  uint8_t* buffer, int length, int offset)
{
    char hexDigit[] = "0123456789ABCDEF";
    register int			i;
    int						lineStart;
    int						lineLength;
    short					c;
    const unsigned char	  *bufferPtr = buffer;
    
    char                    lineBuf[80];
    char                    *p;
    
    if(!logFlag) return;
    
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
        
        OPTESTPrintF( "%s\n",lineBuf);
    }
#undef kLineSize
}

void dumpLong(int logFlag ,uint8_t* buffer, int length)
{
    char hexDigit[] = "0123456789abcdef";
    register int			i;
    int						lineStart;
    int						lineLength;
    const uint8_t			 *bufferPtr = buffer;
    
    if(!logFlag) return;
    
#define kLineSize	16
    for (lineStart = 0; lineStart < length; lineStart += lineLength) {
        lineLength = kLineSize;
        if (lineStart + lineLength > length)
            lineLength = length - lineStart;
        
        OPTESTPrintF("%6s ", "");
        for (i = 0; i < lineLength; i++){
#if 1
            OPTESTPrintF("%c",  hexDigit[ bufferPtr[lineStart+i] >>4]);
            OPTESTPrintF("%c",  hexDigit[ bufferPtr[lineStart+i] &0xF]);
            if( ((lineStart+i) & 0x3)  == 0x3) OPTESTPrintF("%c", ' ');
#else
            OPTESTPrintF("0x%c%c, ", hexDigit[ bufferPtr[lineStart+i] >>4] ,  hexDigit[ bufferPtr[lineStart+i] &0xF]);
#endif
            
        }
        OPTESTPrintF("\n");
    }
#undef kLineSize
}


static void dump64(int logFlag,uint8_t* b, size_t cnt )
{
    if(!logFlag) return;
    
    size_t i, j;
    for (i=0;i < cnt; i=i+8)
    {
        OPTESTPrintF( "0x");
        for(j=8; j > 0; j--)
            OPTESTPrintF("%02X",b[i+j-1]);
        OPTESTPrintF( "L, ");
        
        if (i %16 == 15 || i==cnt-1) OPTESTPrintF("\n");
    }
    OPTESTPrintF("\n");
}


static void dump8(int logFlag,uint8_t* b, size_t cnt )
{
    if(!logFlag) return;
    
    size_t i;
    
    for (i=0;i < cnt; i++)
    {
        OPTESTPrintF( "0x%02X, ",b[i]);
        
        if (i %8 == 7 || i==cnt-1) OPTESTPrintF("\n");
    }
    OPTESTPrintF("\n");
}

void dumpKeyID(int logFlag,uint8_t* b )
{
    if(!logFlag) return;
    
    for (int i=0;i < kS4Key_KeyIDBytes; i++)
    {
        OPTESTPrintF( "%02X",b[i]);
    }
}

void dumpTime(int logFlag, const time_t date )
{
     uint8_t     tempBuf[32];
    size_t      tempLen;

    static const char *kRfc339Format = "%Y-%m-%dT%H:%M:%SZ";
    struct tm *nowtm;
    
    
    if(!logFlag) return;
    
    nowtm = gmtime(&date);
   
    tempLen = strftime((char *)tempBuf, sizeof(tempBuf), kRfc339Format, nowtm);
    OPTESTPrintF( "%s",tempBuf);
    
    
 }

int compare2Results(const void* expected, size_t expectedLen,
                    const void* calculated, size_t  calculatedLen,
                    DumpFormatType format, const char* comment )
{
    S4Err err = kS4Err_NoErr;
    
    if(calculatedLen != expectedLen)
    {
        OPTESTLogError( "\n\t\tFAILED %s \n",comment );
        OPTESTLogError( "\t\texpected %d bytes , calculated %d bytes \n", expectedLen, calculatedLen);
        err =  kS4Err_SelfTestFailed;
    }
    else
        err = compareResults(expected,calculated , expectedLen, format, comment );
    
    return err;
}


S4Err compareResults(const void* expected, const void* calculated, size_t len,
                        DumpFormatType format, const char* comment  )
{
    S4Err err = kS4Err_NoErr;
    
    err = CMP(expected, calculated, len)
    ? kS4Err_NoErr : kS4Err_SelfTestFailed;
    
    if( (err != kS4Err_NoErr)  && IsntNull(comment) && (format != kResultFormat_None))
    {
        OPTESTLogError( "\n\t\tFAILED %s\n",comment );
        switch(format)
        {
            case kResultFormat_Byte:
                OPTESTLogError( "\t\texpected:\n");
                dumpHex(IF_LOG_ERROR, ( uint8_t*) expected, (int)len, 0);
                OPTESTLogError( "\t\tcalculated:\n");
                dumpHex(IF_LOG_ERROR,( uint8_t*) calculated, (int)len, 0);
                OPTESTLogError( "\n");
                break;
                
            case kResultFormat_Long:
                OPTESTLogError( "\t\texpected:\n");
                dump64(IF_LOG_ERROR,( uint8_t*) expected, len);
                OPTESTLogError( "\t\tcalculated:\n");
                dump64(IF_LOG_ERROR,( uint8_t*) calculated, len );
                OPTESTLogError( "\n");
                break;
                
            case kResultFormat_Cstr:
                OPTESTLogError( "\t\texpected:\n");
                dump8(IF_LOG_ERROR,( uint8_t*) expected, len);
                OPTESTLogError( "\t\tcalculated:\n");
                dump8(IF_LOG_ERROR,( uint8_t*) calculated, len );
                OPTESTLogError( "\n");
                break;
               
                
            default:
                break;
        }
    }
    
    return err;
}



const char *hash_algor_table(HASH_Algorithm algor)
{
	S4Err err = kS4Err_NoErr;

	const char* name = "Invalid";

	err = HASH_GetName(algor, &name);

	return name;
 }


size_t hash_algor_bits(HASH_Algorithm algor)
{
	size_t bits = 0;
	S4Err err = kS4Err_NoErr;

	err = HASH_GetBits(algor, &bits);

	return bits;
}



const char *mac_algor_table(MAC_Algorithm algor)
{
	S4Err err = kS4Err_NoErr;

	const char* name = "Invalid";

	err = MAC_GetName(algor, &name);

	return name;
}



const char *cipher_algor_table(Cipher_Algorithm algor)
{
	S4Err err = kS4Err_NoErr;

	const char* name = "Invalid";

	err = Cipher_GetName(algor, &name);

	return name;

}

const char *key_type_table(S4KeyType type)
{
    switch (type )
    {
        case kS4KeyType_Symmetric: 		return (("Symmetric"));
        case kS4KeyType_Tweekable: 		return (("TBC"));
        case kS4KeyType_PBKDF2: 		return (("Encr-PBKDF2 "));
		case kS4KeyType_P2K: 			return (("Encr-P2K "));
        case kS4KeyType_PublicEncrypted: 		return (("Encr-PubKey"));
        case kS4KeyType_PublicKey:              return (("Public Key"));
        default:				return (("Invalid"));
    }
}



