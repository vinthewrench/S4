//
//  c4BufferUtilities.c
//  C4
//
//  Created by vincent Moscaritolo on 11/3/15.
//  Copyright © 2015 4th-A Technologies, LLC. All rights reserved.
//

#include <stdio.h>
#include "C4.h"


/* Functions to load and store in network (big) endian format */

C4Err C4_LoadArray( void *val, size_t len,  uint8_t **ptr, uint8_t* limit)
{
    C4Err   err = kC4Err_NoErr;
    
    uint8_t *bptr =  *ptr;
    
    if(limit && (bptr + len > limit))
        RETERR(kC4Err_BufferTooSmall);
    
    memcpy(val, bptr, len);
    
    *ptr =  bptr + len;
    
done:
    return err;
    
}


uint64_t C4_Load64( uint8_t **ptr )
{
    uint8_t *bptr = *ptr;
    uint64_t retval = ((uint64_t) bptr[0]<<56)
    | ((uint64_t) bptr[1]<<48)
    | ((uint64_t) bptr[2]<<40)
    | ((uint64_t) bptr[3]<<32)
    | ((uint64_t) bptr[4]<<24)
    | ((uint64_t) bptr[5]<<16)
    | ((uint64_t) bptr[6]<<8)
    | ((uint64_t) bptr[7]);
    
    *ptr =  bptr+sizeof(retval);
    return (retval);
}

uint32_t C4_Load32( uint8_t **ptr )
{
    uint8_t *bptr = *ptr;
    uint32_t retval = (bptr[0]<<24) | (bptr[1]<<16) | (bptr[2]<<8) | bptr[3];
    
    *ptr =  bptr+sizeof(retval);
    return (retval);
}


uint16_t C4_Load16( uint8_t **ptr )
{
    uint8_t *bptr = *ptr;
    uint16_t retval = (bptr[0]<<8) | bptr[1];
    
    *ptr =  bptr+sizeof(retval);
    return (retval);
}

uint8_t C4_Load8( uint8_t **ptr )
{
    uint8_t *bptr = *ptr;
    uint8_t retval = *bptr;
    
    *ptr =  bptr+sizeof(uint8_t);
    return (retval);
}

void C4_StoreArray( void *val, size_t len,  uint8_t **ptr )
{
    uint8_t *bptr =  *ptr;
    memcpy(bptr, val, len);
    
    *ptr =  bptr + len;
    
}

void C4_StorePad( uint8_t pad, size_t len,  uint8_t **ptr )
{
    uint8_t *bptr =  *ptr;
    memset(bptr, pad, len);
    
    *ptr =  bptr + len;
    
}


void C4_Store64( uint64_t val, uint8_t **ptr )
{
    uint8_t *bptr = *ptr;
    *bptr++ = (uint8_t)(val>>56);
    *bptr++ = (uint8_t)(val>>48);
    *bptr++ = (uint8_t)(val>>40);
    *bptr++ = (uint8_t)(val>>32);
    *bptr++ = (uint8_t)(val>>24);
    *bptr++ = (uint8_t)(val>>16);
    *bptr++ = (uint8_t)(val>> 8);
    *bptr++ = (uint8_t)val;
    
    *ptr =  bptr;
}

void C4_Store32( uint32_t val, uint8_t **ptr )
{
    uint8_t *bptr = *ptr;
    *bptr++ = (uint8_t)(val>>24);
    *bptr++ = (uint8_t)(val>>16);
    *bptr++ = (uint8_t)(val>> 8);
    *bptr++ = (uint8_t)val;
    *ptr =  bptr;
}

void C4_Store16( uint16_t val, uint8_t **ptr )
{
    uint8_t *bptr = *ptr;
    *bptr++ = (uint8_t)(val>> 8);
    *bptr++ = (uint8_t)val;
    *ptr =  bptr;
}

void C4_Store8( uint8_t val, uint8_t **ptr )
{
    uint8_t *bptr = *ptr;
    *bptr++ = (uint8_t)val;
    *ptr =  bptr;
}