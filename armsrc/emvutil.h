//-----------------------------------------------------------------------------
// Peter Fillmore 2014
// code derived off merloks mifare code
// 
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// code for work with EMV cards.
//-----------------------------------------------------------------------------
#ifndef __EMVUTIL_H
#define __EMVUTIL_H
#include <stdarg.h>
#include <stdint.h>
#include "tlv.h"
#include "emvcard.h"
#include "emvdataels.h"
// mifare 4bit card answers
// reader voltage field detector
#define EMV_MINFIELDV      4000

// debug
// 0 - no debug messages 1 - error messages 2 - all messages 4 - extended debug mode
#define EMV_DBG_NONE          0
#define EMV_DBG_ERROR         1
#define EMV_DBG_ALL           2
#define EMV_DBG_EXTENDED      4

extern int EMV_DBGLEVEL;

//EMV emulator states need to update
#define EMVEMUL_NOFIELD      0
#define EMVEMUL_IDLE         1
#define EMVEMUL_SELECT1      2
#define EMVEMUL_SELECT2      3
#define EMVEMUL_SELECT3      4
#define EMVEMUL_AUTH1       5 
#define EMVEMUL_AUTH2       6 
#define EMVEMUL_WORK	   7
#define EMVEMUL_HALTED      8 
#define EMVEMUL_ACK 9
//#define cardSTATE_TO_IDLE() cardSTATE = EMVEMUL_IDLE; LED_B_OFF(); LED_C_OFF();

//grabbed from iso14443a.c
//static int EmGetCmd(uint8_t *received, int *len);
int EmSendCmdEx(uint8_t *resp, int respLen, bool correctionNeeded);//tag types
int EmSendCmd(uint8_t *resp, int respLen);
//#define cardSTATE_TO_IDLE() cardSTATE = MFEMUL_IDLE; LED_B_OFF(); LED_C_OFF();

//functions
int emv_sendapdu( uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,  uint8_t lc, uint8_t* data, uint8_t le); 
int emv_select( uint8_t* AID, uint8_t AIDlength);
int emv_selectPPSE();
int emv_readrecord( uint8_t recordnumber, uint8_t sfi, uint8_t* rr_response);
int emv_getprocessingoptions( uint8_t* pdol, uint8_t pdollen); 
int emv_computecryptogram( uint8_t* UDOL, uint8_t UDOLlen);
//return 8 8byte ICC random number. 
int emv_getchallenge(); 
int emv_loopback( uint8_t datalen, uint8_t* data, uint8_t* response);
int emv_generateAC( uint8_t refcontrolparam, uint8_t* cdolinput, uint8_t cdolinputlen);
int emv_decodeAFL(uint8_t* AFL, uint8_t AFLlen);
int emv_decodeAIP(uint8_t* AIP);
int emv_decodeCVM(uint8_t* CVM, uint8_t CVMlen);
//memory management
uint8_t* emv_get_bigbufptr(void);
uint8_t* emv_get_bigbufptr_sendbuf(void);
uint8_t* emv_get_bigbufptr_recbuf(void);

//emulator
void EMVsim();

//utils
int emv_printtag(uint8_t* selected_tag,emvcard* inputcard, uint8_t* outputstring, uint8_t* outputlen);
int emv_decode_field(uint8_t* inputfield,uint16_t inputlength, emvcard *result);
int emv_emvcard_decode_tag(tlvtag* inputtag, emvcard* currentcard);
//look up a tag in the current structure 
int emv_lookuptag(uint8_t* tag, emvcard* currentcard, uint8_t* outputval, uint8_t* outputvallen);
//generate a valid PDOL list from the returned card value, used in get processing options
int emv_generateDOL(uint8_t* DOL, uint8_t DOLlen,emvcard* currentcard, uint8_t* DOLoutput, uint8_t* DOLoutputlen);

int emv_generatetemplate(uint8_t* templateval,emvcard* currentcard, uint8_t* returnedval, uint8_t* returnedlen, uint8_t numtags, ...);
#endif
