//parity library
//hold the data and functions needed to calculate parity bits for bytes
//#include "string.h"
#include "parity.h"

//-----------------------------------------------------------------------------
// Generate the parity value for a byte sequence
//
//-----------------------------------------------------------------------------

//removed lookup structure, most likely quicker to calculate parity then look it up, and it saves space
/*
const uint8_t OddByteParity[256] = {
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
  1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

uint8_t oddparity(const uint8_t bt)
{
	return OddByteParity[bt];
}
*/

uint8_t oddparity(uint8_t bt)
{
    uint16_t v = bt; 
    v ^= v >> 4;
    v &= 0xF;
    return ((0x9669 >> v) & 1);
}

uint32_t reverse(uint32_t x)
{
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0f0f0f0fu) | ((x & 0x0f0f0f0fu) << 4);
    x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
    x = ((x >> 16) & 0xffffu) | ((x & 0xffffu) << 16);
    return x;
}
//function to flip char bytes
unsigned char RevByte(unsigned char b)
{
  static const unsigned char t[16] =
  {
    0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE,
    0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF
  };
  return t[b >> 4] | (t[b & 0xF] << 4);
}

//shift buffer in place by 1 bit
void LeftShiftParity(parity_t* value)
{
    uint32_t *currentval; 
    uint32_t bit; 
    uint16_t size = value->len; 
    //cycle through buffer
    if(value->len == 1){ //shift just the one int
        value->byte[0] <<= 1;
    } 
    else{ 
        for(currentval = value->byte; size--; ++currentval){
            bit=0;
            if(size){
                bit = currentval[1] & (0x80000000) ? 1 : 0; //get high bit of next value
                *currentval <<= 1;
                *currentval |= bit;
            }
        }
                 
    }
}

void RightShiftParity(parity_t* value)
{
    uint32_t *currentval;
    uint32_t bit;
    uint16_t size = value->len-1; 
    //cycle through buffer
    if(value->len == 1){ //shift just the one int
        value->byte[0] >>= 1;
    } 
    else{ 
        for(currentval = (value->byte)+size-2; size--; --currentval){ 
            bit = 0; 
            if(size){ 
                bit = (currentval[0] & (0x00000001)) ? 0x80000000 : 0; //get low bit of the previous value 
                currentval[1] >>= 1; //shift by 1 bit
                currentval[1] |= bit; //add the bit back in
            }
            else{ //shift the first value 
                currentval[1] >>= 1; 
            } 
        }
    }
}

void SwapBitsParity(parity_t *value)
{
    uint32_t size = value->len-1; 
    uint32_t *lo = value->byte; //get address of start byte
    uint32_t *hi = value->byte + size-1; //get address of last byte 
    uint32_t swap; 
    while(lo < hi){
        swap = reverse(*lo); //convert the current byte
        *lo++ = *hi; //swap lo and hi values, increment lo
        *hi-- = swap; //*hi = swap, decrement hi 
    }
}

void GetParity(const uint8_t * pbtCmd, uint16_t iLen, parity_t* output)
{
    //store the length of the parity buffer 
    output->numparitybits = iLen; //number of bits generated 
    output->len = (iLen>>5)+1;  //number of long ints stored
    // scan through the input command and generate the parity bits
    for(uint8_t j=0; j < iLen; j++){ 
        output->byte[j>>5] |= (oddparity(pbtCmd[j]) << (j%32));

        //output->byte[j>>5] |= ((OddByteParity[pbtCmd[j]]) << (j%32));
        //make space in parity buffer
    }
        //make space in parity buffer
}

/*j
uint8_t GetParityStream(const uint8_t * pbtCmd, int iLen,uint8_t* paritybitstream, uint8_t* paritybitstreamlen)
{
    // Generate the parity bits
    for(int i=0; i < iLen;i++){ 	
        for (int j = 0; j < 8; j++) {
	    	// and save them to a 32Bit word
	    	paritybitstream[(i-(i%8))/8] |= ((OddByteParity[pbtCmd[i]]) << j);
	    }
    }	
    *paritybitstreamlen = ((iLen - (iLen%8) / 8)+1); 
    return 0;
}
int main()
{
    uint8_t teststring[] = {0x02,0x6f,0x31,0x84,0x0e,0x32,0x50,0x41,
0x59,0x2e,0x53,0x59,0x53,0x2e,0x44,0x44,
0x46,0x30,0x31,0xa5,0x1f,0xbf,0x0c,0x1c,
0x61,0x1a,0x4f,0x07,0xa0,0x00,0x00,0x00,
0x00,0x00,0x00};
    for(int i=0; i< sizeof(teststring); i++){
        printf("%02x\n", teststring[i]);
        printf("%02x\n", oddparity(teststring[i]));
    }
    return 0; 
}
*/

