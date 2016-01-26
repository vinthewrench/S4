//
//  s4BufferUtilities.h
//  S4
//
//  Created by vincent Moscaritolo on 11/3/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef s4BufferUtilities_h
#define s4BufferUtilities_h

#include "s4pubtypes.h"

/* Functions to load and store in network (big) endian format */

S4Err S4_LoadArray( void *val, size_t len,  uint8_t **ptr, uint8_t* limit);

uint64_t S4_Load64( uint8_t **ptr );

uint32_t S4_Load32( uint8_t **ptr );

uint16_t S4_Load16( uint8_t **ptr );

uint8_t S4_Load8( uint8_t **ptr );

void S4_StoreArray( void *val, size_t len,  uint8_t **ptr );

void S4_StorePad( uint8_t pad, size_t len,  uint8_t **ptr );

void S4_Store64( uint64_t val, uint8_t **ptr );

void S4_Store32( uint32_t val, uint8_t **ptr );

void S4_Store16( uint16_t val, uint8_t **ptr );

void S4_Store8( uint8_t val, uint8_t **ptr );

void S4_SkipBytes( uint8_t count, uint8_t **ptr );

uint8_t* S4_GetBuffPtr( uint8_t **ptr );


#endif /* s4BufferUtilities_h */
