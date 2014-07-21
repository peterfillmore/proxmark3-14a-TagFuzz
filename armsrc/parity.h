//Library for generating iso14443 odd parity bits
//
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#ifndef __PARITY_H
#define __PARITY_H
//#include "stdint.h"
//parity is structured in the following fashion
//each 32 bytes is 1 parity byte. each bit indicates the parity value for a byte
//|  8 bytes data | 1 bit parity | 8bytes data | 1 bit parity
//so a parity value of 0x8000000000000 means the first byte of the transmission has its parity bit set.
//#pragma pack(1)
typedef struct{
    uint16_t numparitybits; //number of parity bits generated 
    uint16_t len; //number uint32_t bytes
    uint32_t byte[8]; //parity bits
} parity_t;
//#pragma pack()

//utility functions
void LeftShiftParity(parity_t* value);
void RightShiftParity(parity_t* value);
void SwapBitsParity(parity_t* value);

uint8_t oddparity(uint8_t bt);

//make sure to "pad" the input command to an input of 32 bytes
void GetParity(const uint8_t * pbtCmd, uint16_t iLen, parity_t* output);

#endif

