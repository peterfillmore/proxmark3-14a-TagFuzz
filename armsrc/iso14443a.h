//-----------------------------------------------------------------------------
// Merlok - June 2011
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#ifndef __ISO14443A_H
#define __ISO14443A_H
#include "common.h"
#include "mifaresniff.h"
#include "parity.h" //library for parity functions

// mifare reader                      over DMA buffer (SnoopIso14443a())!!!
#define MIFARE_BUFF_OFFSET 3560  //              \/   \/   \/
// card emulator memory
#define EML_RESPONSES      4000
#define CARD_MEMORY        6000
#define CARD_MEMORY_LEN    4096
#define MAX_FRAME_SIZE 256 // maximum frame size of a packet.

typedef struct {
	enum {
		DEMOD_UNSYNCD,
		// DEMOD_HALF_SYNCD,
		// DEMOD_MOD_FIRST_HALF,
		// DEMOD_NOMOD_FIRST_HALF,
		DEMOD_MANCHESTER_DATA
	} state;
	uint16_t twoBits;
	uint16_t highCnt;
	uint16_t bitCount;
	uint16_t collisionPos;
	uint16_t syncBit;
    parity_t parityBits;	
    uint16_t shiftReg;
	uint16_t samples;
	uint16_t len;
	uint32_t startTime, endTime;
	uint8_t  *output;
} tDemod;

typedef enum {
	MOD_NOMOD = 0,
	MOD_SECOND_HALF,
	MOD_FIRST_HALF,
	MOD_BOTH_HALVES
	} Modulation_t;

typedef struct {
	enum {
		STATE_UNSYNCD,
		STATE_START_OF_COMMUNICATION,
		STATE_MILLER_X,
		STATE_MILLER_Y,
		STATE_MILLER_Z,
		// DROP_NONE,
		// DROP_FIRST_HALF,
		} state;
	uint16_t shiftReg;
	uint16_t bitCount;
	uint16_t len;
	uint16_t byteCntMax;
	uint16_t posCnt;
	uint16_t syncBit;
	parity_t parityBits; //max frame size of 256 bytes
	uint16_t highCnt;
	uint16_t twoBits;
	uint32_t startTime, endTime;
    uint8_t *output;
} tUart;

//
// ISO14443 timing:
//
// minimum time between the start bits of consecutive transfers from reader to tag: 7000 carrier (13.56Mhz) cycles
#define REQUEST_GUARD_TIME (7000/16 + 1)
// minimum time between last modulation of tag and next start bit from reader to tag: 1172 carrier cycles 
#define FRAME_DELAY_TIME_PICC_TO_PCD (1172/16 + 1) 
// bool LastCommandWasRequest = FALSE;

//
// Total delays including SSC-Transfers between ARM and FPGA. These are in carrier clock cycles (1/13,56MHz)
//
// When the PM acts as reader and is receiving tag data, it takes
// 3 ticks delay in the AD converter
// 16 ticks until the modulation detector completes and sets curbit
// 8 ticks until bit_to_arm is assigned from curbit
// 8*16 ticks for the transfer from FPGA to ARM
// 4*16 ticks until we measure the time
// - 8*16 ticks because we measure the time of the previous transfer 
#define DELAY_AIR2ARM_AS_READER (3 + 16 + 8 + 8*16 + 4*16 - 8*16) 

// When the PM acts as a reader and is sending, it takes
// 4*16 ticks until we can write data to the sending hold register
// 8*16 ticks until the SHR is transferred to the Sending Shift Register
// 8 ticks until the first transfer starts
// 8 ticks later the FPGA samples the data
// 1 tick to assign mod_sig_coil
#define DELAY_ARM2AIR_AS_READER (4*16 + 8*16 + 8 + 8 + 1)

// When the PM acts as tag and is receiving it takes
// 2 ticks delay in the RF part (for the first falling edge),
// 3 ticks for the A/D conversion,
// 8 ticks on average until the start of the SSC transfer,
// 8 ticks until the SSC samples the first data
// 7*16 ticks to complete the transfer from FPGA to ARM
// 8 ticks until the next ssp_clk rising edge
// 4*16 ticks until we measure the time 
// - 8*16 ticks because we measure the time of the previous transfer 
#define DELAY_AIR2ARM_AS_TAG (2 + 3 + 8 + 8 + 7*16 + 8 + 4*16 - 8*16)
 
// The FPGA will report its internal sending delay in
uint16_t FpgaSendQueueDelay;
// the 5 first bits are the number of bits buffered in mod_sig_buf
// the last three bits are the remaining ticks/2 after the mod_sig_buf shift
#define DELAY_FPGA_QUEUE (FpgaSendQueueDelay<<1)

// When the PM acts as tag and is sending, it takes
// 4*16 ticks until we can write data to the sending hold register
// 8*16 ticks until the SHR is transferred to the Sending Shift Register
// 8 ticks until the first transfer starts
// 8 ticks later the FPGA samples the data
// + a varying number of ticks in the FPGA Delay Queue (mod_sig_buf)
// + 1 tick to assign mod_sig_coil
#define DELAY_ARM2AIR_AS_TAG (4*16 + 8*16 + 8 + 8 + DELAY_FPGA_QUEUE + 1)

// When the PM acts as sniffer and is receiving tag data, it takes
// 3 ticks A/D conversion
// 14 ticks to complete the modulation detection
// 8 ticks (on average) until the result is stored in to_arm
// + the delays in transferring data - which is the same for
// sniffing reader and tag data and therefore not relevant
#define DELAY_TAG_AIR2ARM_AS_SNIFFER (3 + 14 + 8) 
 
// When the PM acts as sniffer and is receiving reader data, it takes
// 2 ticks delay in analogue RF receiver (for the falling edge of the 
// start bit, which marks the start of the communication)
// 3 ticks A/D conversion
// 8 ticks on average until the data is stored in to_arm.
// + the delays in transferring data - which is the same for
// sniffing reader and tag data and therefore not relevant
#define DELAY_READER_AIR2ARM_AS_SNIFFER (2 + 3 + 8) 

//variables used for timing purposes:
//these are in ssp_clk cycles:
uint32_t NextTransferTime;
uint32_t LastTimeProxToAirStart;
uint32_t LastProxToAirDuration;



// CARD TO READER - manchester
// Sequence D: 11110000 modulation with subcarrier during first half
// Sequence E: 00001111 modulation with subcarrier during second half
// Sequence F: 00000000 no modulation with subcarrier
// READER TO CARD - miller
// Sequence X: 00001100 drop after half a period
// Sequence Y: 00000000 no drop
// Sequence Z: 11000000 drop at start
#define	SEC_D 0xf0
#define	SEC_E 0x0f
#define	SEC_F 0x00
#define	SEC_X 0x0c
#define	SEC_Y 0x00
#define	SEC_Z 0xc0

extern uint32_t iso14a_timeout;
extern uint8_t *trace;
extern int rsamples;
extern unsigned int traceLen;
extern int tracing;
extern uint8_t trigger;
extern uint8_t iso14_pcb_blocknum;

extern void ReaderTransmit(uint8_t *frame, int len, uint32_t *timing);
extern void ReaderTransmitBitsPar(uint8_t *frame, int bits, parity_t* parity, uint32_t *timing);
extern void ReaderTransmitPar(uint8_t *frame, int len, parity_t* parity, uint32_t *timing);
extern int ReaderReceive(uint8_t *receivedAnswer);
extern int ReaderReceivePar(uint8_t *receivedAnswer, parity_t* parptr);

extern void iso14443a_setup(uint8_t fpga_minor_mode);
extern int iso14_apdu(uint8_t *cmd, size_t cmd_len, void *data);
extern int iso14443a_select_card(uint8_t *uid_ptr, iso14a_card_select_t *resp_data, uint32_t *cuid_ptr);
extern void iso14a_set_trigger(bool enable);
extern void iso14a_clear_trace();
extern void iso14a_set_tracing(bool enable);
extern void iso14a_get_timeout(uint32_t* timeout);
extern void iso14a_set_timeout(uint32_t timeout);
extern void iso14a_clear_tracelen();

//parity functions moved to its own library
//extern byte_t oddparity (const byte_t bt);
//returns parity bits as a uint32 - limits packet size
//extern uint256_t GetParity(const uint8_t *pbtCmd, int iLen);
//extern uint8_t GetParityStream(const uint8_t *pbtCmd, int iLen, uint256_t parity, uint8_t* paritybitstreamlen);
extern void AppendCrc14443a(uint8_t *data, int len);

//changed to use new parity functions
extern bool RAMFUNC LogTrace(const uint8_t * btBytes, uint8_t iLen, uint32_t timestamp, parity_t* parity, bool bReader);

//extern tUart Uart;
// Lookup-Table to decide if 4 raw bits are a modulation.
// We accept two or three consecutive "0" in any position with the rest "1"

const bool Mod_Miller_LUT[16];
#define IsMillerModulationNibble1(b) (Mod_Miller_LUT[(b & 0x00F0) >> 4])
#define IsMillerModulationNibble2(b) (Mod_Miller_LUT[(b & 0x000F)])

extern int EmGetCmd(uint8_t *received, int *len);
extern void UartReset();

RAMFUNC bool MillerDecoding(uint8_t bit, uint32_t non_real_time);
//setup parity buffer

// Lookup-Table to decide if 4 raw bits are a modulation.
// We accept three or four "1" in any position
const bool Mod_Manchester_LUT[16];
#define IsManchesterModulationNibble1(b) (Mod_Manchester_LUT[(b & 0x00F0) >> 4])
#define IsManchesterModulationNibble2(b) (Mod_Manchester_LUT[(b & 0x000F)])

extern void DemodReset();
RAMFUNC int ManchesterDecoding(uint8_t bit, uint16_t offset, uint32_t non_real_time);

void RAMFUNC SnoopIso14443a(uint8_t param);
//void CodeIso14443aAsTagPar(const uint8_t *cmd, uint16_t len, parity_t* parity);
void CodeIso14443aAsTagNoPar(const uint8_t *cmd, uint16_t len);
void CodeIso14443aAsTag(const uint8_t *cmd, uint16_t len);
void Code4bitAnswerAsTag(uint8_t cmd);
int GetIso14443aCommandFromReader(uint8_t *received, uint16_t *len, uint16_t maxLen, uint16_t timeout);
int EmSendCmd14443aRaw(uint8_t *resp, int respLen, bool correctionNeeded);
int EmSend4bitEx(uint8_t resp, bool correctionNeeded);
int EmSend4bit(uint8_t resp);
int EmSendCmdExPar(uint8_t *resp, int respLen, bool correctionNeeded, parity_t* parity);
int EmSendCmdEx(uint8_t *resp, int respLen, bool correctionNeeded);
int EmSendCmd(uint8_t *resp, int respLen);
int EmSendCmdPar(uint8_t *resp, int respLen, parity_t* parity);
bool EmLogTrace(uint8_t *reader_data, uint16_t reader_len, uint32_t reader_StartTime, uint32_t reader_EndTime, parity_t* reader_Parity,
				 uint8_t *tag_data, uint16_t tag_len, uint32_t tag_StartTime, uint32_t tag_EndTime, parity_t* tag_Parity);

extern uint8_t* free_buffer_pointer;

typedef struct {
  uint8_t* response;
  size_t   response_n;
  uint8_t* modulation;
  size_t   modulation_n;
  uint32_t ProxToAirDuration;
} tag_response_info_t;

void reset_free_buffer(); 
bool prepare_tag_modulation(tag_response_info_t* response_info, size_t max_buffer_size); 
bool prepare_allocated_tag_modulation(tag_response_info_t* response_info); 
//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void SimulateIso14443aTag(int tagType, int uid_1st, int uid_2nd, byte_t* data);

//-------------------------------------------------------------------------------------
// Transmit the command (to the tag) that was placed in ToSend[].
// Parameter timing:
// if NULL: transfer at next possible time, taking into account
// 			request guard time and frame delay time
// if == 0:	transfer immediately and return time of transfer
// if != 0: delay transfer until time specified
//-------------------------------------------------------------------------------------
void TransmitFor14443a(const uint8_t *cmd, int len, uint32_t *timing);

//-----------------------------------------------------------------------------
// Prepare reader command (in bits, support short frames) to send to FPGA
// removed the parity requirement, we generate this on the fly npw
//-----------------------------------------------------------------------------
void CodeIso14443aBitsAsReader(const uint8_t * cmd, int bits);

//-----------------------------------------------------------------------------
// Prepare reader command to send to FPGA
//-----------------------------------------------------------------------------
void CodeIso14443aAsReaderPar(const uint8_t * cmd, int len, parity_t* parity);

//-----------------------------------------------------------------------------
// Wait for commands from reader
// Stop when button is pressed (return 1) or field was gone (return 2)
// Or return 0 when command is captured
//-----------------------------------------------------------------------------
int EmGetCmd(uint8_t *received, int *len);


int EmSendCmd14443aRaw(uint8_t *resp, int respLen, bool correctionNeeded);

int EmSend4bitEx(uint8_t resp, bool correctionNeeded);

int EmSend4bit(uint8_t resp);
int EmSendCmdExPar(uint8_t *resp, int respLen, bool correctionNeeded, parity_t* parity);
int EmSendCmdEx(uint8_t *resp, int respLen, bool correctionNeeded);
int EmSendCmd(uint8_t *resp, int respLen);
int EmSendCmdPar(uint8_t *resp, int respLen, parity_t* parity);
bool EmLogTrace(uint8_t *reader_data, uint16_t reader_len, uint32_t reader_StartTime, uint32_t reader_EndTime, parity_t* reader_Parity,
				 uint8_t *tag_data, uint16_t tag_len, uint32_t tag_StartTime, uint32_t tag_EndTime, parity_t* tag_Parity);

 int GetIso14443aAnswerFromTag(uint8_t *receivedResponse, uint16_t offset, uint16_t maxLen);

void ReaderTransmitBitsPar(uint8_t* frame, int bits, parity_t* paritystream, uint32_t *timing);

void ReaderTransmitPar(uint8_t* frame, int len, parity_t* paritystream, uint32_t *timing);

void ReaderTransmitBits(uint8_t* frame, int len, uint32_t *timing);
void ReaderTransmit(uint8_t* frame, int len, uint32_t *timing);
int ReaderReceiveOffset(uint8_t* receivedAnswer, uint16_t offset);
int ReaderReceive(uint8_t* receivedAnswer);
int ReaderReceivePar(uint8_t *receivedAnswer, parity_t *parptr);

/* performs iso14443a anticollision procedure
 * fills the uid pointer unless NULL
 * fills resp_data unless NULL */
int iso14443a_select_card(byte_t* uid_ptr, iso14a_card_select_t* p_hi14a_card, uint32_t* cuid_ptr); 
void iso14443a_setup(uint8_t fpga_minor_mode);

void ReaderIso14443a(UsbCommand *c);

// Determine the distance between two nonces.
// Assume that the difference is small, but we don't know which is first.
// Therefore try in alternating directions.
int32_t dist_nt(uint32_t nt1, uint32_t nt2); 

//-----------------------------------------------------------------------------
// Recover several bits of the cypher stream. This implements (first stages of)
// the algorithm described in "The Dark Side of Security by Obscurity and
// Cloning MiFare Classic Rail and Building Passes, Anywhere, Anytime"
// (article by Nicolas T. Courtois, 2009)
//-----------------------------------------------------------------------------
void ReaderMifare(bool first_try);

/**
  *MIFARE 1K simulate.
  *
  *@param flags :
  *	FLAG_INTERACTIVE - In interactive mode, we are expected to finish the operation with an ACK
  * 4B_FLAG_UID_IN_DATA - means that there is a 4-byte UID in the data-section, we're expected to use that
  * 7B_FLAG_UID_IN_DATA - means that there is a 7-byte UID in the data-section, we're expected to use that
  *	FLAG_NR_AR_ATTACK  - means we should collect NR_AR responses for bruteforcing later
  *@param exitAfterNReads, exit simulation after n blocks have been read, 0 is inifite
  */
void Mifare1ksim(uint8_t flags, uint8_t exitAfterNReads, uint8_t arg2, uint8_t *datain);

//-----------------------------------------------------------------------------
// MIFARE sniffer. 
// 
//-----------------------------------------------------------------------------
void RAMFUNC SniffMifare(uint8_t param);
#endif /* __ISO14443A_H */
