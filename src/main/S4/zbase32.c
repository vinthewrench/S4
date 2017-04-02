
/*
 Copyright (c) 2014, Paul Chakravarti
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:
 
 * Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 
 * Redistributions in binary form must reproduce the above copyright notice, this
 list of conditions and the following disclaimer in the documentation and/or
 other materials provided with the distribution.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "s4internal.h"

static const char *alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";

/* The base32 values of each ASCII character. -1 = invalid */
static const char encoded_character_lookup[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 18, -1, 25, 26, 27, 30, 29, 7, 31, -1, -1,
    -1, -1, -1, -1, -1, 24, 1, 12, 3, 8, 5, 6, 28, 21, 9, 10, -1, 11, 2, 16, 13,
    14, 4, 22, 17, 19, -1, 20, 15, 0, 23, -1, -1, -1, -1, -1, -1, 24, 1, 12, 3, 8,
    5, 6, 28, 21, 9, 10, -1, 11, 2, 16, 13, 14, 4, 22, 17, 19, -1, 20, 15, 0, 23,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

int zbase32_decode(uint8_t *decoded,
                   const uint8_t *encoded,
                   unsigned int bits)

{
    char decoded_value;
    uint8_t *output = decoded;
    const uint8_t *input = encoded;
    unsigned int bits_to_read,
    undecoded_bits = bits,
    working_bits = 0,
    working_bit_count = 0;
    
    while (undecoded_bits > 0) {
        if (working_bit_count >= 8) {
            /* There are enough decoded bits to produce a byte */
            working_bit_count -= 8;
            undecoded_bits -= 8;
            *output = (uint8_t)(working_bits >> working_bit_count);
            output++;
        } else if (working_bit_count == undecoded_bits) {
            /* There are no more encoded bits to be read */
            working_bits <<= 8 - undecoded_bits;
            *output = (uint8_t)working_bits;
            output++;
            break;
        } else {
            /* Read more encoded bits */
            bits_to_read = undecoded_bits - working_bit_count;
            if (bits_to_read > 5)
                bits_to_read = 5;
            
            decoded_value = encoded_character_lookup[*input];
            if (decoded_value == -1)
                return -1;
            
            working_bits = (working_bits << bits_to_read) |
            (decoded_value >> (5 - bits_to_read));
            working_bit_count += bits_to_read;
            
            input++;
        }
    }
    
    return (int) (output - decoded);
}


int zbase32_encode(uint8_t *encoded,
                   const uint8_t *input,
                   unsigned int bits) {
    uint8_t *output = encoded;
    unsigned int character_index,
    excess_bits,
    unencoded_bits = bits,
    working_bits = 0,
    working_bit_count = 0;
    
    while (unencoded_bits > 0) {
        if (working_bit_count >= 5) {
            /* There are enough bits in working_bits to encode a character */
            working_bit_count -= 5;
            unencoded_bits -= 5;
            
            character_index = (working_bits >> working_bit_count) & 31;
            *output = alphabet[character_index];
            output++;
        } else if (unencoded_bits == working_bit_count) {
            /* There are no more bits beyond those in working_bits */
            character_index = (working_bits << (5 - unencoded_bits)) & 31;
            *output = alphabet[character_index];
            output++;
            break;
        } else if ((unencoded_bits - working_bit_count) >= 8) {
            /* Add a byte of input to working_bits */
            working_bits = (working_bits << 8) | (*input & 255);
            working_bit_count += 8;
            input++;
        } else {
            /* Add trailing input bits to working_bits */
            excess_bits = bits % 8;
            working_bits = (working_bits << excess_bits) |
            ((*input >> (8 - excess_bits)) &
             ((1 << excess_bits) - 1));
            working_bit_count += excess_bits;
        }
    }
    return (int) (output - encoded);
 }
