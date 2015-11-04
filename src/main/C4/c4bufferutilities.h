//
//  c4BufferUtilities.h
//  C4
//
//  Created by vincent Moscaritolo on 11/3/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#ifndef c4BufferUtilities_h
#define c4BufferUtilities_h

#include "c4pubtypes.h"

/* Functions to load and store in network (big) endian format */

C4Err C4_LoadArray( void *val, size_t len,  uint8_t **ptr, uint8_t* limit);

uint64_t C4_Load64( uint8_t **ptr );

uint32_t C4_Load32( uint8_t **ptr );

uint16_t C4_Load16( uint8_t **ptr );

uint8_t C4_Load8( uint8_t **ptr );

void C4_StoreArray( void *val, size_t len,  uint8_t **ptr );

void C4_StorePad( uint8_t pad, size_t len,  uint8_t **ptr );

void C4_Store64( uint64_t val, uint8_t **ptr );

void C4_Store32( uint32_t val, uint8_t **ptr );

void C4_Store16( uint16_t val, uint8_t **ptr );

void C4_Store8( uint8_t val, uint8_t **ptr );


#endif /* c4BufferUtilities_h */
