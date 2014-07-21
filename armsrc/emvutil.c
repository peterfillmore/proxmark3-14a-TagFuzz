//-----------------------------------------------------------------------------
// Merlok, May 2011, 2012
// Many authors, whom made it possible
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Work with mifare cards.
//-----------------------------------------------------------------------------
#include <stdarg.h>
#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

#include "iso14443crc.h"
#include "iso14443a.h"
#include "emvutil.h"
#include "emvdataels.h" //EMV data elements 
//#include "emvcard.h" //EMV card structure

int EMV_DBGLEVEL = EMV_DBG_ALL;
uint8_t PCB = 0x00; //track Protocol Control Byte externally

//util functions
//print detected tag name over the serial link
int emv_printtag(uint8_t* selected_tag, emvcard* inputcard, uint8_t* outputstring, uint8_t* outputlen)
{
    //search tag list and print the match
    //get the value of the tag 
    uint8_t tagvalue[255];
    uint8_t tagvaluelen; 
    emv_lookuptag(selected_tag, inputcard, tagvalue, &tagvaluelen);
    //loop through selected tag, print the value found 
    for(int i=0; i<(sizeof(EMV_TAG_LIST)/sizeof(EMV_TAG_LIST[0])); i++){
        if(!memcmp(selected_tag, EMV_TAG_LIST[i].tag, 2)){
            memcpy(outputstring, EMV_TAG_LIST[i].description, strlen(EMV_TAG_LIST[i].description));
            memcpy(outputstring+(strlen(EMV_TAG_LIST[i].description)), "=", 1);
            memcpy(outputstring+(strlen(EMV_TAG_LIST[i].description))+1, tagvalue, tagvaluelen);
            *outputlen = strlen(EMV_TAG_LIST[i].description) + 1 + tagvaluelen; 
            break;
        }
    }  
    return 0;
}

//returns the value of the emv tag in the supplied emvcard structure
int emv_lookuptag(uint8_t* tag, emvcard *currentcard, uint8_t* outputval, uint8_t* outputvallen)
{
    //loop through tag and return the appropriate value
    uint8_t returnedtag[255]; 
    uint8_t returnedlength; 
    memset(returnedtag, 0x00, sizeof(returnedtag)); 
    if(!memcmp(tag, "\x4F\x00",2)){
         memcpy(&returnedtag, currentcard->tag_4F,  currentcard->tag_4F_len);
         returnedlength = currentcard->tag_4F_len; goto exitfunction;}
    else if(!memcmp(tag, "\x50\x00",2)){
         memcpy(&returnedtag, currentcard->tag_50,  currentcard->tag_50_len);
         returnedlength = currentcard->tag_50_len; goto exitfunction;}    
    else if(!memcmp(tag, "\x56\x00",2)){
         memcpy(&returnedtag, currentcard->tag_56,  currentcard->tag_56_len);
         returnedlength = currentcard->tag_56_len; goto exitfunction;}
    else if(!memcmp(tag, "\x57\x00",2)){
         memcpy(&returnedtag, currentcard->tag_50,  currentcard->tag_50_len);
         returnedlength = currentcard->tag_50_len; goto exitfunction;}
    else if(!memcmp(tag, "\x5A\x00",2)){
         memcpy(&returnedtag, currentcard->tag_5A,  currentcard->tag_5A_len);
         returnedlength = currentcard->tag_5A_len; goto exitfunction;}
    else if(!memcmp(tag, "\x82\x00",2)){
         memcpy(&returnedtag, currentcard->tag_82,  sizeof(currentcard->tag_82));
         returnedlength = sizeof(currentcard->tag_82);goto exitfunction;}
    else if(!memcmp(tag, "\x84\x00",2)){
         memcpy(&returnedtag, currentcard->tag_84,  currentcard->tag_84_len);
         returnedlength = currentcard->tag_84_len; goto exitfunction;}
    else if(!memcmp(tag, "\x86\x00",2)){
         memcpy(&returnedtag, currentcard->tag_86,  currentcard->tag_86_len);
         returnedlength = currentcard->tag_86_len; goto exitfunction;}
    else if(!memcmp(tag, "\x87\x00",2)){
         memcpy(&returnedtag, currentcard->tag_87,  sizeof(currentcard->tag_87));
         returnedlength = sizeof(currentcard->tag_87);goto exitfunction;}
    else if(!memcmp(tag, "\x88\x00",2)){
         memcpy(&returnedtag, currentcard->tag_88,  currentcard->tag_50_len);
         returnedlength = sizeof(currentcard->tag_88); goto exitfunction;}
    else if(!memcmp(tag, "\x8A\x00",2)){
         memcpy(&returnedtag, currentcard->tag_8A,  sizeof(currentcard->tag_8A));
         returnedlength = sizeof(currentcard->tag_8A);goto exitfunction;}
    else if(!memcmp(tag, "\x8C\x00",2)){
         memcpy(&returnedtag, currentcard->tag_8C,  currentcard->tag_8C_len);
         returnedlength = currentcard->tag_8C_len; goto exitfunction;}
    else if(!memcmp(tag, "\x8D\x00",2)){
         memcpy(&returnedtag, currentcard->tag_8D,  currentcard->tag_8D_len);
         returnedlength = currentcard->tag_8D_len; goto exitfunction;}
    else if(!memcmp(tag, "\x8E\x00",2)){
        memcpy(&returnedtag, currentcard->tag_8E,  currentcard->tag_8E_len);
         returnedlength = currentcard->tag_8E_len; goto exitfunction;}
    else if(!memcmp(tag, "\x8F\x00",2)){
         memcpy(&returnedtag, currentcard->tag_8F,  sizeof(currentcard->tag_8F));
         returnedlength = sizeof(currentcard->tag_8F);goto exitfunction;}
    else if(!memcmp(tag, "\x90\x00",2)){
         memcpy(&returnedtag, currentcard->tag_90,  currentcard->tag_90_len);
         returnedlength = currentcard->tag_90_len; goto exitfunction;}
    else if(!memcmp(tag, "\x92\x00",2)){
         memcpy(&returnedtag, currentcard->tag_92,  currentcard->tag_92_len);
         returnedlength = currentcard->tag_92_len; goto exitfunction;}
    else if(!memcmp(tag, "\x93\x00",2)){
         memcpy(&returnedtag, currentcard->tag_93,  currentcard->tag_93_len);
         returnedlength = currentcard->tag_93_len; goto exitfunction;}
    else if(!memcmp(tag, "\x94\x00",2)){
         memcpy(&returnedtag, currentcard->tag_94,  currentcard->tag_94_len);
         returnedlength = currentcard->tag_94_len; goto exitfunction;}
    else if(!memcmp(tag, "\x95\x00",2)){
         memcpy(&returnedtag, currentcard->tag_95,  sizeof(currentcard->tag_95));
         returnedlength = sizeof(currentcard->tag_95);goto exitfunction;}
    else if(!memcmp(tag, "\x97\x00",2)){
        memcpy(&returnedtag, currentcard->tag_97,  currentcard->tag_97_len);
         returnedlength = currentcard->tag_97_len; goto exitfunction;}
    else if(!memcmp(tag, "\x98\x00",2)){
         memcpy(&returnedtag, currentcard->tag_98,  sizeof(currentcard->tag_98));
         returnedlength = sizeof(currentcard->tag_98);goto exitfunction;}
    else if(!memcmp(tag, "\x99\x00",2)){
        memcpy(&returnedtag, currentcard->tag_99,  currentcard->tag_99_len);
         returnedlength = currentcard->tag_99_len; goto exitfunction;}
    else if(!memcmp(tag, "\x9A\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9A,  sizeof(currentcard->tag_9A));
         returnedlength = sizeof(currentcard->tag_9A);goto exitfunction;}
    else if(!memcmp(tag, "\x9B\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9B,  sizeof(currentcard->tag_9B));
         returnedlength = sizeof(currentcard->tag_9B);goto exitfunction;}
    else if(!memcmp(tag, "\x9C\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9C,  sizeof(currentcard->tag_9C));
         returnedlength = sizeof(currentcard->tag_9C);goto exitfunction;}
    else if(!memcmp(tag, "\x9D\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9D,  currentcard->tag_9D_len);
         returnedlength = currentcard->tag_9D_len; goto exitfunction;}
    else if(!memcmp(tag, "\x9D\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9D,  currentcard->tag_9D_len);
         returnedlength = currentcard->tag_9D_len; goto exitfunction;}
    else if(!memcmp(tag, "\xCD\x00",2)){
         memcpy(&returnedtag, currentcard->tag_CD,  sizeof(currentcard->tag_CD));
         returnedlength = sizeof(currentcard->tag_CD);goto exitfunction;}
    else if(!memcmp(tag, "\xCE\x00",2)){
         memcpy(&returnedtag, currentcard->tag_CE,  sizeof(currentcard->tag_CE));
         returnedlength = sizeof(currentcard->tag_CE);goto exitfunction;}
    else if(!memcmp(tag, "\xCF\x00",2)){
         memcpy(&returnedtag, currentcard->tag_CF,  sizeof(currentcard->tag_CF));
         returnedlength = sizeof(currentcard->tag_CF);goto exitfunction;}
    else if(!memcmp(tag, "\xD7\x00",2)){
         memcpy(&returnedtag, currentcard->tag_D7,  sizeof(currentcard->tag_D7));
         returnedlength = sizeof(currentcard->tag_D7);goto exitfunction;}
    else if(!memcmp(tag, "\xD8\x00",2)){
         memcpy(&returnedtag, currentcard->tag_D8,  sizeof(currentcard->tag_D8));
         returnedlength = sizeof(currentcard->tag_D8);goto exitfunction;}
    else if(!memcmp(tag, "\xD9\x00",2)){
    memcpy(&returnedtag, currentcard->tag_D9,  currentcard->tag_D9_len);
         returnedlength = currentcard->tag_D9_len;goto exitfunction;}
    else if(!memcmp(tag, "\xDA\x00",2)){
         memcpy(&returnedtag, currentcard->tag_DA,  sizeof(currentcard->tag_DA));
         returnedlength = sizeof(currentcard->tag_DA);goto exitfunction;}
    else if(!memcmp(tag, "\xDB\x00",2)){
         memcpy(&returnedtag, currentcard->tag_DB,  sizeof(currentcard->tag_DB));
         returnedlength = sizeof(currentcard->tag_DB);goto exitfunction;}
    else if(!memcmp(tag, "\xDC\x00",2)){
         memcpy(&returnedtag, currentcard->tag_DC,  sizeof(currentcard->tag_DC));
         returnedlength = sizeof(currentcard->tag_DC);goto exitfunction;}
    else if(!memcmp(tag, "\xDD\x00",2)){
         memcpy(&returnedtag, currentcard->tag_DD,  sizeof(currentcard->tag_DD));
         returnedlength = sizeof(currentcard->tag_DD);goto exitfunction;}
    else if(!memcmp(tag, "\xA5\x00",2)){
   memcpy(&returnedtag, currentcard->tag_A5,  currentcard->tag_A5_len);
         returnedlength = currentcard->tag_A5_len; goto exitfunction;}
    else if(!memcmp(tag, "\xAF\x00",2)){
   memcpy(&returnedtag, currentcard->tag_AF,  currentcard->tag_AF_len);
         returnedlength = currentcard->tag_AF_len; goto exitfunction;}
    if(*tag == 0x5F){ 
        if(*(tag+1) == 0x20){ 
            memcpy(&returnedtag, currentcard->tag_5F20,  currentcard->tag_5F20_len);
             returnedlength = currentcard->tag_5F20_len; goto exitfunction;}
        else if(*(tag+1) == 0x24){ 
             memcpy(&returnedtag, currentcard->tag_5F24,  sizeof(currentcard->tag_5F24));
             returnedlength = sizeof(currentcard->tag_5F24);goto exitfunction;}
        else if(*(tag+1) == 0x25){ 
             memcpy(&returnedtag, currentcard->tag_5F25,  sizeof(currentcard->tag_5F25));
             returnedlength = sizeof(currentcard->tag_5F25);goto exitfunction;}
        else if(*(tag+1) == 0x28){ 
             memcpy(&returnedtag, currentcard->tag_5F28,  sizeof(currentcard->tag_5F28));
             returnedlength = sizeof(currentcard->tag_5F28);goto exitfunction;}
        else if(*(tag+1) == 0x2A){ 
             memcpy(&returnedtag, currentcard->tag_5F2A,  sizeof(currentcard->tag_5F2A));
             returnedlength = sizeof(currentcard->tag_5F2A);goto exitfunction;}
        else if(*(tag+1) == 0x2D){ 
            memcpy(&returnedtag, currentcard->tag_5F2D,  currentcard->tag_5F2D_len);
             returnedlength = currentcard->tag_5F2D_len; goto exitfunction;}
        else if(*(tag+1) == 0x30){ 
             memcpy(&returnedtag, currentcard->tag_5F30,  sizeof(currentcard->tag_5F30));
             returnedlength = sizeof(currentcard->tag_5F30);goto exitfunction;}
        else if(*(tag+1) == 0x34){ 
             memcpy(&returnedtag, currentcard->tag_5F34,  sizeof(currentcard->tag_5F34));
             returnedlength = sizeof(currentcard->tag_5F34);goto exitfunction;}
        else if(*(tag+1) == 0x36){ 
             memcpy(&returnedtag, currentcard->tag_5F36,  sizeof(currentcard->tag_5F36));
             returnedlength = sizeof(currentcard->tag_5F36);goto exitfunction;}
        else if(*(tag+1) == 0x50){ 
            memcpy(&returnedtag, currentcard->tag_5F50,  currentcard->tag_5F50_len);
             returnedlength = currentcard->tag_5F50_len; goto exitfunction;}
        else if(*(tag+1) == 0x54){ 
            memcpy(&returnedtag, currentcard->tag_5F54,  currentcard->tag_5F54_len);
             returnedlength = currentcard->tag_5F54_len; goto exitfunction;}
        }
    if(*tag == 0x9F) {
        if(*(tag+1) == 0x01){ 
             memcpy(&returnedtag, currentcard->tag_9F01,  sizeof(currentcard->tag_9F01));
             returnedlength = sizeof(currentcard->tag_9F01);goto exitfunction;}
        else if(*(tag+1) == 0x02){ 
             memcpy(&returnedtag, currentcard->tag_9F02,  sizeof(currentcard->tag_9F02));
             returnedlength = sizeof(currentcard->tag_9F02);goto exitfunction;}
        else if(*(tag+1) == 0x03){ 
             returnedlength = sizeof(currentcard->tag_9F03);goto exitfunction;}
        else if(*(tag+1) == 0x04){ 
             memcpy(&returnedtag, currentcard->tag_9F04,  sizeof(currentcard->tag_9F04));
             returnedlength = sizeof(currentcard->tag_9F04);goto exitfunction;}
        else if(*(tag+1) == 0x05){ 
       memcpy(&returnedtag, currentcard->tag_9F05,  currentcard->tag_9F05_len);
             returnedlength = currentcard->tag_9F05_len; goto exitfunction;}
        else if(*(tag+1) == 0x06){ 
       memcpy(&returnedtag, currentcard->tag_9F06,  currentcard->tag_9F06_len);
             returnedlength = currentcard->tag_9F06_len; goto exitfunction;}
        else if(*(tag+1) == 0x07){ 
             memcpy(&returnedtag, currentcard->tag_9F07,  sizeof(currentcard->tag_9F07));
             returnedlength = sizeof(currentcard->tag_9F07);goto exitfunction;}
        else if(*(tag+1) == 0x08){ 
             memcpy(&returnedtag, currentcard->tag_9F08,  sizeof(currentcard->tag_9F08));
             returnedlength = sizeof(currentcard->tag_9F08);goto exitfunction;}
        else if(*(tag+1) == 0x09){ 
             memcpy(&returnedtag, currentcard->tag_9F09,  sizeof(currentcard->tag_9F09));
             returnedlength = sizeof(currentcard->tag_9F09);goto exitfunction;} 
        else if(*(tag+1) == 0x0B){ 
       memcpy(&returnedtag, currentcard->tag_9F0B,  currentcard->tag_9F0B_len);
             returnedlength = currentcard->tag_9F0B_len; goto exitfunction;}
        else if(*(tag+1) == 0x0D){ 
             memcpy(&returnedtag, currentcard->tag_9F0D,  sizeof(currentcard->tag_9F0D));
             returnedlength = sizeof(currentcard->tag_9F0D);goto exitfunction;}
        else if(*(tag+1) == 0x0E){ 
             memcpy(&returnedtag, currentcard->tag_9F0E,  sizeof(currentcard->tag_9F0E));
             returnedlength = sizeof(currentcard->tag_9F0E);goto exitfunction;}
        else if(*(tag+1) == 0x0F){ 
             memcpy(&returnedtag, currentcard->tag_9F0F,  sizeof(currentcard->tag_9F0F));
             returnedlength = sizeof(currentcard->tag_9F0F);goto exitfunction;}
        else if(*(tag+1) == 0x10){ 
            memcpy(&returnedtag, currentcard->tag_9F10,  currentcard->tag_9F10_len);
             returnedlength = currentcard->tag_9F10_len;goto exitfunction;}
        else if(*(tag+1) == 0x11){ 
             memcpy(&returnedtag, currentcard->tag_9F11,  sizeof(currentcard->tag_9F11));
             returnedlength = sizeof(currentcard->tag_9F11);goto exitfunction;}
        else if(*(tag+1) == 0x12){ 
             memcpy(&returnedtag, currentcard->tag_9F12,  currentcard->tag_9F12_len);
             returnedlength = currentcard->tag_9F12_len;goto exitfunction;}
        else if(*(tag+1) == 0x1A){ 
             memcpy(&returnedtag, currentcard->tag_9F1A,  sizeof(currentcard->tag_9F1A));
            goto exitfunction;}
        else if(*(tag+1) == 0x1F){ 
       memcpy(&returnedtag, currentcard->tag_9F1F,  currentcard->tag_9F1F_len);
             returnedlength = currentcard->tag_9F1F_len; goto exitfunction;}
        else if(*(tag+1) == 0x32){ 
       memcpy(&returnedtag, currentcard->tag_9F32,  currentcard->tag_9F32_len);
             returnedlength = currentcard->tag_9F32_len; goto exitfunction;}
        else if(*(tag+1) == 0x34){ 
       memcpy(&returnedtag, currentcard->tag_9F34,  sizeof(currentcard->tag_9F34));
             returnedlength = sizeof(currentcard->tag_9F34); goto exitfunction;}
else if(*(tag+1) == 0x35){ 
       memcpy(&returnedtag, currentcard->tag_9F35,  sizeof(currentcard->tag_9F35));
             returnedlength = sizeof(currentcard->tag_9F35); goto exitfunction;}
else if(*(tag+1) == 0x37){ 
             memcpy(&returnedtag, currentcard->tag_9F37,  sizeof(currentcard->tag_9F37));
             returnedlength = sizeof(currentcard->tag_9F37);goto exitfunction;}
        else if(*(tag+1) == 0x38){ 
       memcpy(&returnedtag, currentcard->tag_9F38,  currentcard->tag_9F38_len);
             returnedlength = currentcard->tag_9F38_len; goto exitfunction;}
        else if(*(tag+1) == 0x44){ 
             memcpy(&returnedtag, currentcard->tag_9F44,  sizeof(currentcard->tag_9F44));
             returnedlength = sizeof(currentcard->tag_9F44);goto exitfunction;}
        else if(*(tag+1) == 0x45){ 
             memcpy(&returnedtag, currentcard->tag_9F45,  sizeof(currentcard->tag_9F45));
             returnedlength = sizeof(currentcard->tag_9F45);goto exitfunction;}
        else if(*(tag+1) == 0x46){ 
            memcpy(&returnedtag, currentcard->tag_9F46,  currentcard->tag_9F46_len);
             returnedlength = currentcard->tag_9F46_len; goto exitfunction;}
        else if(*(tag+1) == 0x47){ 
       memcpy(&returnedtag, currentcard->tag_9F47,  currentcard->tag_9F47_len);
             returnedlength = currentcard->tag_9F47_len; goto exitfunction;}
        else if(*(tag+1) == 0x48){ 
       memcpy(&returnedtag, currentcard->tag_9F48,  currentcard->tag_9F48_len);
             returnedlength = currentcard->tag_9F48_len; goto exitfunction;}
        else if(*(tag+1) == 0x49){ 
       memcpy(&returnedtag, currentcard->tag_9F49,  currentcard->tag_9F49_len);
             returnedlength = currentcard->tag_9F49_len; goto exitfunction;}
        else if(*(tag+1) == 0x4A){ 
             memcpy(&returnedtag, currentcard->tag_9F4A,  sizeof(currentcard->tag_9F4A));
             returnedlength = sizeof(currentcard->tag_9F4A);goto exitfunction;}
        else if(*(tag+1) == 0x4B){ 
       memcpy(&returnedtag, currentcard->tag_9F4B,  currentcard->tag_9F4B_len);
             returnedlength = currentcard->tag_9F4B_len; goto exitfunction;}
        else if(*(tag+1) == 0x4C){ 
             memcpy(&returnedtag, currentcard->tag_9F4C,  sizeof(currentcard->tag_9F4C));
             returnedlength = sizeof(currentcard->tag_9F4C); goto exitfunction;}
else if(*(tag+1) == 0x60){ 
             memcpy(&returnedtag, currentcard->tag_9F60,  sizeof(currentcard->tag_9F60));
             returnedlength = sizeof(currentcard->tag_9F60);goto exitfunction;}
        else if(*(tag+1) == 0x61){ 
             memcpy(&returnedtag, currentcard->tag_9F61,  sizeof(currentcard->tag_9F61));
             returnedlength = sizeof(currentcard->tag_9F61);goto exitfunction;}
        else if(*(tag+1) == 0x62){ 
             memcpy(&returnedtag, currentcard->tag_9F62,  sizeof(currentcard->tag_9F62));
             returnedlength = sizeof(currentcard->tag_9F62);goto exitfunction;}
        else if(*(tag+1) == 0x63){ 
             memcpy(&returnedtag, currentcard->tag_9F63,  sizeof(currentcard->tag_9F63));
             returnedlength = sizeof(currentcard->tag_9F63);goto exitfunction;}
        else if(*(tag+1) == 0x64){ 
             memcpy(&returnedtag, currentcard->tag_9F64,  sizeof(currentcard->tag_9F64));
             returnedlength = sizeof(currentcard->tag_9F64);goto exitfunction;}
        else if(*(tag+1) == 0x65){ 
             memcpy(&returnedtag, currentcard->tag_9F65,  sizeof(currentcard->tag_9F65));
             returnedlength = sizeof(currentcard->tag_9F65);goto exitfunction;}
        else if(*(tag+1) == 0x66){ 
            memcpy(&returnedtag, currentcard->tag_9F66,  sizeof(currentcard->tag_9F66));
             returnedlength = sizeof(currentcard->tag_9F66);goto exitfunction;}
        else if(*(tag+1) == 0x67){ 
             memcpy(&returnedtag, currentcard->tag_9F67,  sizeof(currentcard->tag_9F67));
             returnedlength = sizeof(currentcard->tag_9F67);goto exitfunction;}
        else if(*(tag+1) == 0x68){ 
        memcpy(&returnedtag, currentcard->tag_9F68,  currentcard->tag_9F68_len);
             returnedlength = currentcard->tag_9F68_len;goto exitfunction;}
        else if(*(tag+1) == 0x69){ 
       memcpy(&returnedtag, currentcard->tag_9F69,  currentcard->tag_9F69_len);
             returnedlength = currentcard->tag_9F69_len; goto exitfunction;}
        else if(*(tag+1) == 0x6A){ 
             memcpy(&returnedtag, currentcard->tag_9F6A,  sizeof(currentcard->tag_9F6A));
             returnedlength = sizeof(currentcard->tag_9F6A);goto exitfunction;}
        else if(*(tag+1) == 0x6B){ 
       memcpy(&returnedtag, currentcard->tag_9F6B,  currentcard->tag_9F6B_len);
             returnedlength = currentcard->tag_9F6B_len; goto exitfunction;}
        else if(*(tag+1) == 0x6C){ 
             memcpy(&returnedtag, currentcard->tag_9F6C,  sizeof(currentcard->tag_9F6C));
             returnedlength = sizeof(currentcard->tag_9F6C);goto exitfunction;}
    }
    else {
        if(!memcmp(tag, "\x61\x00",2)){
       memcpy(&returnedtag, currentcard->tag_61,  currentcard->tag_61_len);
             returnedlength = currentcard->tag_61_len; goto exitfunction;}
        else if(!memcmp(tag, "\x6F\x00",2)){
       memcpy(&returnedtag, currentcard->tag_6F,  currentcard->tag_6F_len);
             returnedlength = currentcard->tag_6F_len; goto exitfunction;}
        else if(!memcmp(tag, "\xAF\x00",2)){
       memcpy(&returnedtag, currentcard->tag_AF,  currentcard->tag_AF_len);
             returnedlength = currentcard->tag_AF_len; goto exitfunction;}
        else if(!memcmp(tag, "\x70\x00",2)){
       memcpy(&returnedtag, currentcard->tag_70,  currentcard->tag_70_len);
             returnedlength = currentcard->tag_70_len; goto exitfunction;}
        else if(!memcmp(tag, "\x77\x00",2)){
       memcpy(&returnedtag, currentcard->tag_77,  currentcard->tag_77_len);
             returnedlength = currentcard->tag_77_len; goto exitfunction;}
        else if(!memcmp(tag, "\x80\x00",2)){
       memcpy(&returnedtag, currentcard->tag_80,  currentcard->tag_80_len);
             returnedlength = currentcard->tag_80_len; goto exitfunction;}
        else if(!memcmp(tag, "\xBF\x0C",2)){
       memcpy(&returnedtag, currentcard->tag_BF0C,  currentcard->tag_BF0C_len);
             returnedlength = currentcard->tag_BF0C_len; goto exitfunction;}
    }
exitfunction:  //goto label to exit search quickly once found
    memcpy(outputval, &returnedtag, returnedlength);
    *outputvallen = returnedlength; 
    return 0;
}  

int emv_generatetemplate(uint8_t* templateval,emvcard* currentcard, uint8_t* returnedval, uint8_t* returnedlen,uint8_t numtags, ...)
{
    va_list arguments;
    uint8_t* currenttag; //value of the current tag
    uint8_t tagval[256]; //buffer to hold the extracted tag value 
    uint8_t taglen = 0; //extracted tag length 
    uint8_t bufferval[256]; 
    uint8_t counter = 0; 
    uint32_t encodedlen = 0; 
    va_start(arguments, numtags);
    for(int x=0; x<numtags; x++){
        currenttag = va_arg(arguments, uint8_t*);     
        emv_lookuptag(currenttag, currentcard, tagval, &taglen);
        encode_ber_tlv_item(currenttag, (uint8_t)strlen((const char*)currenttag), tagval, (uint32_t)taglen, bufferval+counter, &encodedlen);
        counter +=encodedlen; 
    } 
    encode_ber_tlv_item(templateval, strlen((const char*) templateval), bufferval, counter, returnedval, &encodedlen);   
    *returnedlen = encodedlen; 
    return 0;
}

//generate a valid pdol list
int emv_generateDOL(uint8_t* DOL, uint8_t DOLlen,emvcard* currentcard,uint8_t* DOLoutput, uint8_t* DOLoutputlen)
{
    if(!DOL || !currentcard || !DOLoutput) // null pointer checks
        return 1; 
    //scan through the DOL list and construct the result.
    uint8_t i = 0;
    uint8_t DOLcounter = 0; //points to the current DOL buffer location 
    uint8_t scannedtaglen = 0; //length of a scanned tag
    uint8_t scannedtag[2] = {0x00,0x00}; //buffer for the scanned tag
    uint8_t DOLoutputbuffer[255]; 
    uint8_t retrievedtagvallen; 
    
    memset(DOLoutputbuffer,0x00, 255); //clear the output buffer
    while(i< DOLlen)
    {
        //length of DOL tag 
        if((*(DOL+i) & 0x1F) == 0x1F){ scannedtaglen = 2;}
        else{scannedtaglen=1;}
        memcpy(scannedtag, DOL+i,scannedtaglen);
        //look up tag value and copy
        emv_lookuptag(scannedtag,currentcard,&(DOLoutputbuffer[DOLcounter]),&retrievedtagvallen);
        DOLcounter += (uint8_t)DOL[i+scannedtaglen];
        i += scannedtaglen + 1; 
        memset(scannedtag, 0x00, 2); //clear current tag 
    }
    memcpy(DOLoutput, DOLoutputbuffer, DOLcounter);
    *DOLoutputlen = DOLcounter; 
    return 0; 
}


//decode the tag inputted and fill in the supplied structure. clean up the cleanup_passpass function
int emv_emvcard_decode_tag(tlvtag* inputtag, emvcard* currentcard)
{
    if(!inputtag || !currentcard) {
        return 1;
    } 
    //scan decoded tag 
    if(*(inputtag->tag) == 0x5F) {
        if(*(inputtag->tag+1) == 0x20){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F20)))
            return 1; 
            memcpy(currentcard->tag_5F20, inputtag->value, inputtag->valuelength);
            currentcard->tag_5F20_len = inputtag->valuelength;
        }
        if(*(inputtag->tag+1) == 0x24){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F24)))
                return 1; 
            memcpy(currentcard->tag_5F24, inputtag->value, sizeof(currentcard->tag_5F24));}
        if(*(inputtag->tag+1) == 0x25){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F25)))
                return 1; 
            memcpy(currentcard->tag_5F25, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x28){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F28)))
                return 1; 
            memcpy(currentcard->tag_5F28, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x2A){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F2A)))
                return 1; 
            memcpy(currentcard->tag_5F2A, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x2D){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F2D)))
                return 1; 
            memcpy(currentcard->tag_5F2D, inputtag->value, inputtag->valuelength);
            currentcard->tag_5F2D_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x30){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F30)))
                return 1; 
            memcpy(currentcard->tag_5F30, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x34){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F34)))
                return 1; 
            memcpy(currentcard->tag_5F34, inputtag->value, sizeof(currentcard->tag_5F34));}
        if(*(inputtag->tag+1) == 0x36){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F36)))
                return 1; 
            memcpy(currentcard->tag_5F36, inputtag->value, sizeof(currentcard->tag_5F36));}
        if(*(inputtag->tag+1) == 0x50){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F50)))
                return 1; 
            memcpy(currentcard->tag_5F50, inputtag->value, inputtag->valuelength);
            currentcard->tag_5F50_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x54){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F54)))
                return 1; 
            memcpy(currentcard->tag_5F54, inputtag->value, inputtag->valuelength);
            currentcard->tag_5F54_len = inputtag->valuelength;}
    }
    if(*(inputtag->tag) == 0x9F){
        if(*(inputtag->tag+1) == 0x01){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F01)))
            return 1; 
        memcpy(currentcard->tag_9F01, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x02){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F02)))
            return 1; 
        memcpy(currentcard->tag_9F02, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x03){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F03)))
            return 1; 
        memcpy(currentcard->tag_9F03, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x04){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F04)))
            return 1; 
        memcpy(currentcard->tag_9F04, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x05){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F05)))
            return 1; 
        memcpy(currentcard->tag_9F05, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F05_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x06){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F06)))
            return 1; 
        memcpy(currentcard->tag_9F06, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F06_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x07){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F07)))
            return 1; 
        memcpy(currentcard->tag_9F07, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x08){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F08)))
            return 1; 
        memcpy(currentcard->tag_9F08, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x09){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F09)))
            return 1; 
        memcpy(currentcard->tag_9F09, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x0B){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F0B)))
            return 1; 
        memcpy(currentcard->tag_9F0B, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F0B_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x0D){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F0D)))
            return 1; 
        memcpy(currentcard->tag_9F0D, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x0E){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F0E)))
            return 1; 
        memcpy(currentcard->tag_9F0E, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x0F){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F0F)))
            return 1; 
        memcpy(currentcard->tag_9F0F, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x11){ 
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F11)))
                return 1; 
            memcpy(currentcard->tag_9F11, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x12){ 
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F12)))
                return 1; 
            memcpy(currentcard->tag_9F12, inputtag->value, inputtag->valuelength);
            currentcard->tag_9F12_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x13){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F13)))
            return 1; 
        memcpy(currentcard->tag_9F13, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x14){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F14)))
            return 1; 
        memcpy(currentcard->tag_9F14, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x15){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F15)))
            return 1; 
        memcpy(currentcard->tag_9F15, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x16){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F16)))
            return 1; 
        memcpy(currentcard->tag_9F16, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x17){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F17)))
            return 1; 
        memcpy(currentcard->tag_9F17, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x18){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F18)))
            return 1; 
        memcpy(currentcard->tag_9F18, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1A){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1A)))
            return 1; 
        memcpy(currentcard->tag_9F1A, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1B){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1B)))
            return 1; 
        memcpy(currentcard->tag_9F1B, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1C){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1C)))
            return 1; 
        memcpy(currentcard->tag_9F1C, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1D){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1D)))
            return 1; 
        memcpy(currentcard->tag_9F1D, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F1D_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x1E){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1E)))
            return 1; 
        memcpy(currentcard->tag_9F1E, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1F){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1F)))
            return 1; 
        memcpy(currentcard->tag_9F1F, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F1F_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x32){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F32)))
            return 1; 
        memcpy(currentcard->tag_9F32, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x34){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F34)))
            return 1; 
        memcpy(currentcard->tag_9F34, inputtag->value, inputtag->valuelength);}
if(*(inputtag->tag+1) == 0x35){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F35)))
            return 1; 
        memcpy(currentcard->tag_9F35, inputtag->value, inputtag->valuelength);}
if(*(inputtag->tag+1) == 0x37){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F37)))
            return 1; 
        memcpy(currentcard->tag_9F37, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x38){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F38)))
            return 1; 
        memcpy(currentcard->tag_9F38, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F38_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x44){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F44)))
            return 1; 
        memcpy(currentcard->tag_9F44, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x45){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F45)))
            return 1; 
        memcpy(currentcard->tag_9F45, inputtag->value, inputtag->valuelength);}
if(*(inputtag->tag+1) == 0x46){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F46)))
            return 1; 
        memcpy(currentcard->tag_9F46, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F46_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x47){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F47)))
            return 1; 
        memcpy(currentcard->tag_9F47, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F47_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x48){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F48)))
            return 1; 
        memcpy(currentcard->tag_9F48, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F48_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x49){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F49)))
            return 1; 
        memcpy(currentcard->tag_9F49, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F49_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x4A){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F4A)))
            return 1; 
        memcpy(currentcard->tag_9F4A, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x4B){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F4B)))
            return 1; 
        memcpy(currentcard->tag_9F4B, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F4B_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x4C){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F4C)))
            return 1; 
        memcpy(currentcard->tag_9F4C, inputtag->value, inputtag->valuelength);}
if(*(inputtag->tag+1) == 0x60){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F60)))
            return 1; 
        memcpy(currentcard->tag_9F60, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x61){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F61)))
            return 1; 
        memcpy(currentcard->tag_9F61, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x62){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F62)))
            return 1; 
        memcpy(currentcard->tag_9F62, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x63){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F63)))
            return 1; 
        memcpy(currentcard->tag_9F63, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x64){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F64)))
            return 1; 
        memcpy(currentcard->tag_9F64, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x65){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F65)))
            return 1; 
        memcpy(currentcard->tag_9F65, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x66){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F66)))
            return 1; 
        memcpy(currentcard->tag_9F66, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x67){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F67)))
            return 1; 
        memcpy(currentcard->tag_9F67, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x68){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F68)))
            return 1; 
        memcpy(currentcard->tag_9F68, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F68_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x69){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F69)))
            return 1; 
        memcpy(currentcard->tag_9F69, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F69_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x6A){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F6A)))
            return 1; 
        memcpy(currentcard->tag_9F6A, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x6B){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F6B)))
            return 1; 
        memcpy(currentcard->tag_9F6B, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F6B_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x6C){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F6C)))
            return 1; 
        memcpy(currentcard->tag_9F6C, inputtag->value, inputtag->valuelength);}
}
else 
{ 
    if(*(inputtag->tag) == 0xBF){ //BF0C 
        if(*(inputtag->tag+1) == 0x0C){ 
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_BF0C)))
                return 1; 
            memcpy(currentcard->tag_BF0C, inputtag->value, inputtag->valuelength);
            currentcard->tag_BF0C_len = inputtag->valuelength;}
    }
    else if(*(inputtag->tag) == 0x4F){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_4F)))
            return 1; 
        memcpy(currentcard->tag_4F, inputtag->value, inputtag->valuelength);
        currentcard->tag_4F_len = inputtag->valuelength;}
    else if(*(inputtag->tag) == 0x50){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_50)))
            return 1; 
        memcpy(currentcard->tag_50, inputtag->value, inputtag->valuelength);
        currentcard->tag_50_len = inputtag->valuelength;
    } 
    else if(*(inputtag->tag) == 0x56){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_56)))
            return 1; 
        memcpy(currentcard->tag_56, inputtag->value, inputtag->valuelength);
        currentcard->tag_56_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x57){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_57)))
            return 1; 
        memcpy(currentcard->tag_57, inputtag->value, inputtag->valuelength);
        currentcard->tag_57_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x5A){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_5A)))
            return 1; 
        memcpy(currentcard->tag_5A, inputtag->value, inputtag->valuelength);
        currentcard->tag_5A_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x61){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_61)))
            return 1; 
        memcpy(currentcard->tag_61, inputtag->value, inputtag->valuelength);
        currentcard->tag_61_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x6F){ //BF0C 
        memcpy(currentcard->tag_6F,inputtag->value,inputtag->valuelength);}
    
    else if(*(inputtag->tag) == 0x70){ //BF0C 
        memcpy(currentcard->tag_70,inputtag->value,inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x77){ //BF0C 
        memcpy(currentcard->tag_77,inputtag->value,inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x80){ //BF0C 
        memcpy(currentcard->tag_80,inputtag->value,inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x82){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_82)))
            return 1; 
        memcpy(currentcard->tag_82, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x84){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_84)))
            return 1; 
        memcpy(currentcard->tag_84, inputtag->value, inputtag->valuelength);
        currentcard->tag_84_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x86){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_86)))
            return 1; 
        memcpy(currentcard->tag_86, inputtag->value, inputtag->valuelength);
        currentcard->tag_86_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x87){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_87)))
            return 1; 
        memcpy(currentcard->tag_87, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x88){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_88)))
            return 1; 
        memcpy(currentcard->tag_88, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x8A){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8A)))
            return 1; 
        memcpy(currentcard->tag_8A, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x8C){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8C)))
            return 1; 
        memcpy(currentcard->tag_8C, inputtag->value, inputtag->valuelength);
        currentcard->tag_8C_len = inputtag->valuelength;
    }    
    else if(*(inputtag->tag) == 0x8D){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8D)))
            return 1; 
        memcpy(currentcard->tag_8D, inputtag->value, inputtag->valuelength);
        currentcard->tag_8D_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x8E){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8E)))
            return 1; 
        memcpy(currentcard->tag_8E, inputtag->value, inputtag->valuelength);
        currentcard->tag_8E_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x8F){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8F)))
            return 1; 
        memcpy(currentcard->tag_8F,inputtag->value,sizeof(currentcard->tag_8F));}
    else if(*(inputtag->tag) == 0x90){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_90)))
            return 1; 
        memcpy(currentcard->tag_90, inputtag->value, inputtag->valuelength);
        currentcard->tag_90_len = inputtag->valuelength;}
    else if(*(inputtag->tag) == 0x92){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_92)))
            return 1; 
        memcpy(currentcard->tag_92, inputtag->value, inputtag->valuelength);
        currentcard->tag_92_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x93){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_93)))
            return 1; 
        memcpy(currentcard->tag_93, inputtag->value, inputtag->valuelength);
        currentcard->tag_93_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x94){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_94)))
            return 1; 
        memcpy(currentcard->tag_94, inputtag->value, inputtag->valuelength);
        currentcard->tag_94_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x95){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_95)))
            return 1; 
        memcpy(currentcard->tag_95, inputtag->value, inputtag->valuelength);} 
    else if(*(inputtag->tag) == 0x97){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_97)))
            return 1; 
        memcpy(currentcard->tag_97, inputtag->value, inputtag->valuelength);
        currentcard->tag_97_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x98){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_98)))
            return 1; 
        memcpy(currentcard->tag_98, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x99){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_99)))
            return 1; 
        memcpy(currentcard->tag_99, inputtag->value, inputtag->valuelength);
        currentcard->tag_99_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x9A){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9A)))
            return 1; 
        memcpy(currentcard->tag_9A, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x9B){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9B)))
            return 1; 
        memcpy(currentcard->tag_9B, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x9C){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9C)))
            return 1; 
        memcpy(currentcard->tag_9C, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x9D){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9D)))
            return 1; 
        memcpy(currentcard->tag_9D, inputtag->value, inputtag->valuelength);
        currentcard->tag_9D_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0xA5){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_A5)))
            return 1; 
        memcpy(currentcard->tag_A5, inputtag->value, inputtag->valuelength);
        currentcard->tag_A5_len = inputtag->valuelength;}
   } 
   return 0;
}

int emv_decode_field(uint8_t* inputfield,uint16_t inputlength, emvcard *result)
{
    uint16_t lengthcounter=0; 
    tlvtag newtag; 
    //copy result to the testtag
    if(!result){
        return 1;
    } 
    //loop through and decode template 
    while(lengthcounter < inputlength)
    {
        //decode the tlv tag 
        decode_ber_tlv_item((inputfield+lengthcounter),&newtag);
        //write the the emvcard strucutre 
        emv_emvcard_decode_tag(&newtag,result); 
        //move to next value and decode 
        lengthcounter += newtag.fieldlength-1; 
    }
    return 0;
}
// memory management
uint8_t* emv_get_bigbufptr(void) {
	return (((uint8_t *)BigBuf) + MIFARE_BUFF_OFFSET);	// was 3560 - tied to other size changes
}

uint8_t* emv_get_bigbufptr_sendbuf(void) {
	return (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);	
}

uint8_t* emv_get_bigbufptr_recbuf(void) {
	return (((uint8_t *)BigBuf) + MIFARE_BUFF_OFFSET);	
}

//commands
int emv_sendapdu(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint8_t lc, uint8_t* data, uint8_t le)
{
    uint8_t *answer = emv_get_bigbufptr();  
    int cmdcounter = 0; 
    uint8_t apdulength = 0; 
    if(PCB == 0x00) //first transaction
        {PCB = 0x02;} 
    else if(PCB == 0x02){
        PCB = 0x03;}
    else if(PCB == 0x03){
        PCB = 0x02;}
    if(lc != 0x00) {
        apdulength = 9+lc; //get length of the packet assume 8 bits for now
    } 
    else{
        apdulength = 8; //no data packet present
    } 
        //generate APDU  
    uint8_t cmd[apdulength]; //buffer for the command
    cmd[cmdcounter++] = PCB ; //toggle block bit 
    cmd[cmdcounter++] = cla;
    cmd[cmdcounter++] = ins;
    cmd[cmdcounter++] = p1;
    cmd[cmdcounter++] = p2;
    if(lc != 0x00) { 
        cmd[cmdcounter++] = lc;
        for(int i=cmdcounter;i < (lc+cmdcounter);i++){
            cmd[i] = *(data+i-cmdcounter);
        }
        cmdcounter += lc;
    }
    cmd[cmdcounter++] = le;
    AppendCrc14443a(cmd, cmdcounter);
    ReaderTransmit(cmd, sizeof(cmd),NULL);
    int len = ReaderReceive(answer);
	if(!len)
	{
        if (EMV_DBGLEVEL >= 1)   
            Dbprintf("APDU sending failed, time-out, %u", len);
        return 2;
    } 
    //check the protocol control byte
    //check if its an I block 
    if((answer[0] & 0xE2) == 0x02) {}
    else if((answer[0] & 0xE6) == 0xA2){} //S block
    else if((answer[0] & 0xC7) == 0xC2){
        if(answer[0] == 0xF2){
            //accept frame waiting command
            uint8_t FWTcommand[4] = {0x00, 0x00, 0x00, 0x00};
            FWTcommand[0] = 0xF2;
            FWTcommand[1] |= (0xCF) & answer[1];
            AppendCrc14443a(FWTcommand,2);
            ReaderTransmit(FWTcommand, sizeof(FWTcommand), NULL);    
            //resend the command
            emv_sendapdu(cla, ins, p1, p2, lc, data, le); 
        }
    }
    return len;
}

int emv_select(uint8_t* AID, uint8_t AIDlength)
{
    int isOK = 0; 
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
    while(true) { 
        if(!emv_sendapdu(0x00,0xA4,0x04,0x00,AIDlength,AID,0x00)){
            if(MF_DBGLEVEL >= 1) Dbprintf("APDU send failed");
                break; 
        } 
        isOK=1;
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("SELECT Finished");
    LED_B_ON();
    /* 
    if(((*select_response+1) & 0x60) == 0x60){ //error
        if(EMV_DBGLEVEL >= 1){
            if(memcmp(select_response+1, "\x62\x83", 2))
                Dbprintf("SWI1=%02X SWI2=%02X:Selected file invalidated", select_response[1], select_response[2]);
             if(memcmp(select_response+1, "\x67\x00", 2))
                Dbprintf("SWI1=%02X SWI2=%02X:Wrong length", select_response[1], select_response[2]);
             if(memcmp(select_response+1, "\x6A\x81", 2))
                Dbprintf("SWI1=%02X SWI2=%02X:Function not supported", select_response[1], select_response[2]);
            if(memcmp(select_response+1, "\x6A\x82", 2))
                Dbprintf("SWI1=%02X SWI2=%02X:Selected file invalidated", select_response[1], select_response[2]);
            if(memcmp(select_response+1, "\x6A\x86", 2))
                Dbprintf("SWI1=%02X SWI2=%02X:Selected file invalidated", select_response[1], select_response[2]);
        } */ 
    LED_B_OFF();
    return isOK;
}

int emv_selectPPSE()
{
    int isOK = 0; 
    //PPSE directory = "2PAY.SYS.DDF01"
    //uint8_t AID[14] = {0x32,0x50,0x41,0x59,0x2E,0x53,0x59,0x53,0x2E,0x44,0x44,0x46,0x30,0x31}; 
    while(true) { 
        if(!emv_select((uint8_t*)DF_PSE, 14)){
            if(MF_DBGLEVEL >= 1) Dbprintf("SELECT PPSE FAILED");
                break; 
        } 
        isOK=1;
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("SELECT_PPSE Finished");
    return isOK;
}

int emv_readrecord(uint8_t recordnumber, uint8_t sfi, uint8_t* rr_response)
{
    int isOK = 0;
    while(true) {
        if(!emv_sendapdu(0x00, 0xB2, recordnumber, ((sfi << 3) | 0x04), 0x00, NULL, 0x00)){
            if(MF_DBGLEVEL >= 1) Dbprintf("Read Record failed");
                break;
            } 
            isOK = 1;
            break;
    }
    rr_response =  emv_get_bigbufptr();
    return isOK;
}

int emv_getprocessingoptions(uint8_t* pdol, uint8_t pdollen)
{
    int isOK = 0;
    uint8_t command[pdollen+2];  
    command[0] = 0x83;
    command[1] = pdollen;
    if(pdollen > 0) 
        memcpy(&command[2], pdol, pdollen); 
    while(true) {
            if(!emv_sendapdu(0x80, 0xA8, 0x00,0x00, pdollen+2, command,0x00)){
                if(MF_DBGLEVEL >= 1) Dbprintf("Get Processing Options Failed");
                    break;
            }
        isOK = 1;
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("Get Processing Options Finished");
    return isOK;
}

int emv_computecryptogram(uint8_t* UDOL, uint8_t UDOLlen)
{
    int isOK = 0;
    while(true) {
        if(!emv_sendapdu(0x80, 0x2A, 0x8E,0x80, UDOLlen, UDOL,0x00)){
            if(MF_DBGLEVEL >= 1) Dbprintf("Compute Cryptographic Checksum Failed");
                break;
            } 
            isOK = 1;
            break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("Compute Cryptographic Checksum finished");
    return isOK;
}

int emv_getchallenge()
{
    int isOK = 0;
    while(true) {
        if(!emv_sendapdu(0x00, 0x84, 0x00,0x00, 0, NULL,0x00)){
            if(MF_DBGLEVEL >= 1) Dbprintf("Get Challenge Failed");
                break;
            } 
            isOK = 1;
            break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("Get Challenge finished");
    return isOK;
}
int emv_loopback(uint8_t datalen, uint8_t* data, uint8_t* response)
{
    int isOK = 0;
    while(true) {
        if(!emv_sendapdu(0x80, 0xEE, 0x00,0x00, datalen, data, 0x00)){
            if(MF_DBGLEVEL >= 1) Dbprintf("Loopback Failed");
                break;
            } 
            isOK = 1;
            break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("Loopback Completed");
    response = emv_get_bigbufptr();
    return isOK;
}

//generateAC
int emv_generateAC(uint8_t refcontrolparam, uint8_t* cdolinput, uint8_t cdolinputlen)
{
    int isOK = 0;
    /* 
    uint8_t command[cdolinputlen+2]; 
    command[0] = 0x83;
    command[1] = cdolinputlen;
    
    memcpy(&command[2], cdolinput, cdolinputlen);
    */
    while(true) {
            if(!emv_sendapdu(0x80, 0xAE, refcontrolparam,0x00, cdolinputlen, cdolinput,0x00)){
                if(MF_DBGLEVEL >= 1) Dbprintf("Get AC Failed");
                    break;
            }
        isOK = 1;
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("Get AC Finished");
    return isOK;
}

int emv_decodeAFL(uint8_t* AFL, uint8_t AFLlen )
{
    return 0;
}
int emv_decodeAIP(uint8_t* AIP)
{
    if((AIP[0] & AIP_SDA_SUPPORTED) == AIP_SDA_SUPPORTED)
        Dbprintf("SDA supported");
    if((AIP[0] & AIP_DDA_SUPPORTED) == AIP_DDA_SUPPORTED)
        Dbprintf("DDA supported");  
    if((AIP[0] & AIP_CARDHOLDER_VERIFICATION)==AIP_CARDHOLDER_VERIFICATION)
        Dbprintf("Cardholder verification is supported");  
    if((AIP[0] & AIP_TERMINAL_RISK) == AIP_TERMINAL_RISK)
        Dbprintf("Terminal risk management is to be performed");  
    if((AIP[0] & AIP_ISSUER_AUTH) == AIP_ISSUER_AUTH)
        Dbprintf("Issuer authentication is supported ");  
    if((AIP[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED)
        Dbprintf("CDA supported");  
    if((AIP[1] & AIP_CHIP_SUPPORTED) == AIP_CHIP_SUPPORTED)
        Dbprintf("Chip supported");
    if((AIP[1] & AIP_MSR_SUPPORTED) == AIP_MSR_SUPPORTED)
        Dbprintf("MSR supported"); 
    return 0;
}
int emv_decodeCVM(uint8_t* CVM, uint8_t CVMlen)
{
    uint8_t counter = 0;
    uint32_t amountX = 0;
    uint32_t amountY = 0; 
    amountX = bytes_to_num(CVM, 4);
    amountY = bytes_to_num(CVM+4, 4); 
    counter +=8;
    while(counter < CVMlen)
    {
        if((CVM[counter] & 0x40) == 0x40){
            if((CVM[counter] & 0x3F)== 0x00){
                Dbprintf("Fail CVM processing");
            }
            if((CVM[counter] & 0x3F) == 0x01){
                Dbprintf("Plaintext PIN verification performed by ICC");
            }
            if((CVM[counter] & 0x3F) == 0x02){
                Dbprintf("Enciphered PIN verified online");
            }
            if((CVM[counter] & 0x3F) == 0x03){
                Dbprintf("Plaintext PIN verification performed by ICC and signature (paper)");
            }
            if((CVM[counter] & 0x3F) == 0x04){
                Dbprintf("Enciphered PIN verification performed by ICC");
            }  
            if((CVM[counter] & 0x3F) == 0x05){
                Dbprintf("Enciphered PIN verification performed by ICC and signature (paper)");
            }  
            if((CVM[counter] & 0x3F) == 0x30){
                Dbprintf("Signature (paper)");
            }  
            if((CVM[counter] & 0x3F) == 0x40){
                Dbprintf("No CVM required");
            }
            counter +=2; 
        }
        else{
            Dbprintf("Fail cardholder verification if this CVM is unsuccessful"); 
            counter +=2; 
        }
        if(CVM[counter+1] == 0x00){
            Dbprintf("Always");}
        if(CVM[counter+1] == 0x01){
            Dbprintf("If unattended cash");}
        if(CVM[counter+1] == 0x02){
            Dbprintf("If not unattended cash and not manual cash and not purchase with cashback");}
        if(CVM[counter+1] == 0x03){
            Dbprintf("If terminal supports the CVM");}
        if(CVM[counter+1] == 0x04){
            Dbprintf("If manual cash");}
        if(CVM[counter+1] == 0x05){
            Dbprintf("If purchase with cashback");}
        if(CVM[counter+1] == 0x06){
            Dbprintf("If transaction is in the application currency and is under %lu value", amountX);}
         if(CVM[counter+1] == 0x07){
            Dbprintf("If transaction is in the application currency and is over %lu value", amountX);}
         if(CVM[counter+1] == 0x08){
            Dbprintf("If transaction is in the application currency and is under %lu value", amountY);}
         if(CVM[counter+1] == 0x09){
            Dbprintf("If transaction is in the application currency and is over %lu value", amountY);}
     }
    return 0;
}

//simulate a emvcard card
//input is a structure containing values to simulate
//clones an EMV card 

void emvsnoop()
{
    //states
    int cardSTATE = EMVEMUL_NOFIELD; 
    int vHf = 0;
    int res;
    //uint32_t selTimer = 0;
 
    //setup emvcard card vals 
    /* 
    struct emvcard cardvals;
    cardvals.TL = 0x0B;
    cardvals.T0 = 0x78;
    cardvals.TA1 = 0x80;
    cardvals.TB1 = 0x81;
    cardvals.TC1 = 0x02;
    cardvals.historicalbytes={0x4B, 0x4F, 0x41, 0x14, 0x11}
    */
    int len = 0; 
    uint8_t* receivedCmd = emv_get_bigbufptr_recbuf();
    //uint8_t* response = emv_get_bigbufptr_sendbuf();
    
    uint8_t rATQA[] = {0x04,0x00};
    uint8_t rUIDBCC[] = {0x8F,0x2F,0x27,0xE1, 0x66};
    uint8_t rSAK[] = {0x28, 0xB4, 0xFC};

    iso14a_clear_trace();
    iso14a_set_tracing(TRUE);
    
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    bool finished=FALSE;

    while (!BUTTON_PRESS() && !finished){
        WDT_HIT();
        //find reader field
        if(cardSTATE == EMVEMUL_NOFIELD){
            vHf = (33000 * AvgAdc(ADC_CHAN_HF)) >> 10;
            if(vHf > EMV_MINFIELDV){
                cardSTATE_TO_IDLE();
                LED_A_ON();
            }
        }
        if(cardSTATE == EMVEMUL_NOFIELD) continue;

        //get data
        res = EmGetCmd(receivedCmd, &len);
        if(res == 2) { //field is off
            cardSTATE = EMVEMUL_NOFIELD;
            LEDsoff();
            continue;
        }
        else if(res==1){
            break; // button press
        }

        if(len==1 && ((receivedCmd[0] == 0x26 && cardSTATE != EMVEMUL_HALTED) || receivedCmd[0] == 0x52)){
            //selTime = GetTickCount();
            EmSendCmdEx(rATQA, sizeof(rATQA), (receivedCmd[0] == 0x52));
            cardSTATE = EMVEMUL_SELECT1;
            continue;
        }
        switch(cardSTATE){
            case EMVEMUL_NOFIELD:
            case EMVEMUL_HALTED:
            case EMVEMUL_IDLE:{
                break;
            }
            case EMVEMUL_SELECT1:{
                //select all
                if(len==2 && (receivedCmd[0] == 0x93 && receivedCmd[1] == 0x20)) {
                    EmSendCmd(rUIDBCC, sizeof(rUIDBCC));
                    break;
                }
                if(len==2 && (receivedCmd[0] == 0x93 && receivedCmd[1] == 0x70 && memcmp(&receivedCmd[2], rUIDBCC, 4) == 0)) {
                    EmSendCmd(rSAK, sizeof(rSAK));
                    break;
                }
            }
        }
    }
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}




