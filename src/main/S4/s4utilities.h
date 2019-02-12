//
//  s4uilities_h
//  S4Crypto
//
//  Created by vincent Moscaritolo on 11/3/15.
//  Copyright © 2019 4th-A Technologies, LLC. All rights reserved.
//

/**
 * @file s4uilities_h
 * @author 4th-A Technologies, LLC
 * @brief S4Crypto Utility functions
 *
 */

#ifndef s4utilities_h
#define s4utilities_h

#include "s4pubtypes.h"
S4_ASSUME_NONNULL_BEGIN

#ifdef __clang__
#pragma mark - Init
#endif

S4Err S4_Init(void);

#ifdef __clang__
#pragma mark - Get version
#endif

S4Err S4_GetErrorString( S4Err err,  char outString[__S4_NONNULL 256]);

S4Err S4_GetVersionString(char outString[__S4_NONNULL 256]);


#ifdef __clang__
#pragma mark - Buffer utilities
#endif

/* Functions to load and store in network (big) endian format */

S4Err S4_LoadArray( void *val, size_t len,  uint8_t __NONNULL_PP ptr, uint8_t* __S4_NULLABLE limit);

uint64_t S4_Load64( uint8_t __NONNULL_PP ptr );

uint32_t S4_Load32( uint8_t __NONNULL_PP ptr );

uint16_t S4_Load16( uint8_t __NONNULL_PP ptr );

uint8_t S4_Load8( uint8_t __NONNULL_PP ptr );

void S4_StoreArray( void *val, size_t len,  uint8_t __NONNULL_PP ptr );

void S4_StorePad( uint8_t pad, size_t len,  uint8_t __NONNULL_PP ptr );

void S4_Store64( uint64_t val, uint8_t __NONNULL_PP ptr );

void S4_Store32( uint32_t val, uint8_t __NONNULL_PP ptr );

void S4_Store16( uint16_t val, uint8_t __NONNULL_PP ptr );

void S4_Store8( uint8_t val, uint8_t __NONNULL_PP ptr );

void S4_SkipBytes( uint8_t count, uint8_t __NONNULL_PP ptr );

uint8_t* S4_GetBuffPtr( uint8_t __NONNULL_PP ptr );


#ifdef __clang__
#pragma mark - Hash word Encoding
#endif

/* given a 8 bit word.  return the  PGP word null terminated
 as defined by  http://en.wikipedia.org/wiki/PGP_word_list
 */


char* PGPWordOdd(uint8_t in);
char* PGPWordEven(uint8_t in);


#ifdef __clang__
#pragma mark - zbase32 encoding
#endif


/* Z-base-32 as defined by
 http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
 */


/*
 * Decode bits of encoded using z-base-32 and write the result into
 * decoded. If 8 is not a factor of bits, pad the output with zero bits
 * until a full byte is written.
 *
 * Returns the number of bytes written, or -1 if a byte that is not the
 * ASCII representation of a valid z-base-32 character is read.
 */
int zbase32_decode(uint8_t *decoded,
				   const uint8_t *encoded,
				   unsigned int bits);

/*
 * Encode bits of input into z-base-32, and write the result into encoded.
 *
 * Returns the number of bytes written.
 */
int zbase32_encode(uint8_t *encoded,
				   const uint8_t *input,
				   unsigned int bits);

S4_ASSUME_NONNULL_END

#endif /* s4utilities_h */
