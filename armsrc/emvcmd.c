//Peter Fillmore - 2014
//
//--------------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
//Routines to support EMV transactions
//--------------------------------------------------------------------------------

#include "mifare.h"
#include "iso14443a.h"
#include "emvcmd.h"
#include "apps.h"
//global emvcard struct
static emvcard currentcard;
static tUart Uart;
//static tDemod Demod;

void EMVTest()
{
    uint8_t rats[0x0b] = {0x0b,0x78,0x80,0x81,0x02,0x4b,0x4f,0x4e,0x41, 0x14, 0x11};
    EMVFuzz_RATS(0xb,rats);
    //grab card
    //EMVClone(1,1);
    /* 
    uint8_t tagvalbuffer[256];
    uint8_t tagvallen;  
    uint8_t template6F[] = {0x6F,0x00}; 
    uint8_t templateA5[] = {0xA5,0x00}; 
    uint8_t tag1[] = {0x50,0x00,0x00};
    uint8_t tag2[] = {0x87,0x00,0x00};
    uint8_t tag3[] = {0x9f,0x38,0x00};
    uint8_t tag4[] = {0x5F,0x2D,0x00};
    uint8_t tag5[] = {0x9F,0x11,0x00};
    uint8_t tag6[] = {0x9F,0x12,0x00};

    uint8_t tag7[] = {0x84, 0x00};
    uint8_t tag8[] = {0xA5, 0x00};
    emv_generatetemplate(templateA5,&currentcard,tagvalbuffer,&tagvallen, 6, tag1, tag2, tag3, tag4, tag5, tag6);
    memcpy(currentcard.tag_A5, tagvalbuffer+2, tagvallen-2);
    currentcard.tag_A5_len = tagvallen-2;
    emv_generatetemplate(template6F,&currentcard,currentcard.tag_6F ,&currentcard.tag_6F_len, 2, tag7, tag8);
    Dbprintf("TAG A5=");
    Dbhexdump(currentcard.tag_A5_len,currentcard.tag_A5 , false); 
    */
    //EMVSim(); 
}

void EMVReadRecord(uint8_t arg0, uint8_t arg1,emvcard *currentcard)
{
    //params
    uint8_t record = arg0;
    uint8_t sfi = arg1 & 0x0F; //convert arg1 to number
    uint8_t *responsebuffer  = emv_get_bigbufptr(); 
    //variables
    tlvtag inputtag;
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
    
    while(true) { 
        if(!emv_readrecord(record,sfi,responsebuffer)) {
            if(EMV_DBGLEVEL >= 1) Dbprintf("readrecord failed");
            break;
        }
        if(*(responsebuffer+1) == 0x70){ 
            decode_ber_tlv_item(responsebuffer+1, &inputtag);
            emv_decode_field(inputtag.value, inputtag.valuelength, currentcard); 
        } 
        else{
            if(EMV_DBGLEVEL >= 1) 
                Dbprintf("Record not found SFI=%i RECORD=%i", sfi, record); 
            } 
        LED_B_ON();
        LED_B_OFF();
        break;
    }
    LEDsoff();
}


void EMVSelectAID(uint8_t *AID, uint8_t AIDlen, emvcard* inputcard)
{
    uint8_t* responsebuffer = emv_get_bigbufptr_recbuf(); 
    //variables
    tlvtag inputtag;
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
    //change timeout value
    //Dbprintf("timeout=%i", iso14a_timeout);
    while(true) { 
        if(!emv_select(AID, AIDlen)){
            if(EMV_DBGLEVEL >= 1) Dbprintf("AID Select failed");
            break;
        }
        if(*(responsebuffer+1) == 0x6F){ 
            decode_ber_tlv_item(responsebuffer+1, &inputtag);
            emv_decode_field(inputtag.value, inputtag.valuelength, inputcard); 
        }
        
        LED_B_ON();
        LED_B_OFF();
         
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("SELECT AID COMPLETED");
    LEDsoff();
}

void EMVSelectPPSE()
{
    while(true) { 
        if(!emv_selectPPSE()) {
            if(EMV_DBGLEVEL >= 1) Dbprintf("PPSE failed");
            break;
        }
         
        LED_B_ON();
        LED_B_OFF();
         
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("SELECT PPSE COMPLETED");
    LEDsoff();
}

int EMV_PaywaveTransaction()
{
    uint8_t *responsebuffer  = emv_get_bigbufptr(); 
    tlvtag temptag; //buffer for decoded tags 
    //get the current block counter 
    //select the AID (Mastercard 
    EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
    
    if(responsebuffer[1] == 0x6F){ //decode template
        decode_ber_tlv_item(&responsebuffer[1], &temptag);
        //decode 84 and A5 tags 
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
        //decode the A5 tag 
        emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
        //decode the BF0C result, assuming 1 directory entry for now 
        //retrieve the AID 
    }
    //get PDOL
    uint8_t pdolcommand[20]; //20 byte buffer for pdol data 
    uint8_t pdolcommandlen = 0; 
    if(currentcard.tag_9F38_len > 0) { 
        emv_generateDOL(currentcard.tag_9F38, currentcard.tag_9F38_len, &currentcard, pdolcommand, &pdolcommandlen); 
    }
    else{
        //pdolcommand = NULL; //pdol val is null
        pdolcommandlen = 0;
    }
    if(!emv_getprocessingoptions(pdolcommand,pdolcommandlen)) {
        if(EMV_DBGLEVEL >= 1) Dbprintf("PDOL failed");
        return 1; 
    }
    if(responsebuffer[1] == 0x80) //format 1 data field returned
    { 
        memcpy(currentcard.tag_82, &responsebuffer[3],2); //copy AIP
        currentcard.tag_94_len =  responsebuffer[2]-2; //AFL len
        memcpy(currentcard.tag_94, &responsebuffer[5],currentcard.tag_94_len); //copy AFL 
    }
    else if(responsebuffer[1] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&responsebuffer[1], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    } 
    else
    {
        //throw an error
    }
    Dbprintf("AFL=");
    Dbhexdump(currentcard.tag_94_len, currentcard.tag_94,false); 
    Dbprintf("AIP=");
    Dbhexdump(2, currentcard.tag_82, false); 
    emv_decodeAIP(currentcard.tag_82); 
    
    //decode the AFL list and read records 
       
    //record, sfi 
    EMVReadRecord( 1,1, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    EMVReadRecord( 2,1, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    EMVReadRecord( 1,2, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    EMVReadRecord( 2,2, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    EMVReadRecord( 3,2, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    EMVReadRecord( 4,2, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    EMVReadRecord( 1,3, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    EMVReadRecord( 2,3, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    EMVReadRecord( 4,2, &currentcard);
    EMVReadRecord( 1,3, &currentcard);
    Dbhexdump(200, responsebuffer,false); 
    //EMVReadRecord( 2,3, &currentcard);
    //Dbhexdump(200, responsebuffer,false); 
    
    //DDA supported, so read more records 
    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED){ 
        EMVReadRecord( 1,4, &currentcard);
        EMVReadRecord( 2,4, &currentcard);
    }

     
   emv_decodeCVM(currentcard.tag_8E, currentcard.tag_8E_len); 
    /* get ICC dynamic data */
    //if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED)
    {
        //DDA supported, so perform GENERATE AC 
        uint8_t cdolcommand[40]; //20 byte buffer for pdol data 
        uint8_t cdolcommandlen; 
        //generate the iCC UN 
        emv_getchallenge();
        memcpy(currentcard.tag_9F37,&responsebuffer[1],8); // ICC UN 
        memcpy(currentcard.tag_9F4C,&responsebuffer[1],8); // ICC UN 
        if(currentcard.tag_8C_len > 0) { 
            emv_generateDOL(currentcard.tag_8C, currentcard.tag_8C_len, &currentcard, cdolcommand, &cdolcommandlen); }
        else{
            //cdolcommand = NULL; //cdol val is null
            cdolcommandlen = 0;
        }
        Dbhexdump(currentcard.tag_8C_len, currentcard.tag_8C,false); 
        Dbhexdump(cdolcommandlen, cdolcommand,false); 
        emv_generateAC(0x41, cdolcommand,cdolcommandlen);
         
        Dbhexdump(100, responsebuffer,false); 
        //Dbhexdump(200, responsebuffer,false); 
       /* 
        if(responsebuffer[1] == 0x77) //format 2 data field returned
        {
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
        }
        //generate AC2  
        if(currentcard.tag_8D_len > 0) { 
            emv_generateDOL(currentcard.tag_8D, currentcard.tag_8D_len, &currentcard, cdolcommand, &cdolcommandlen); }
        else{
            //cdolcommand = NULL; //cdol val is null
            cdolcommandlen = 0;
        }
        emv_generateAC(0x80, cdolcommand,cdolcommandlen);
        
        if(responsebuffer[1] == 0x77) //format 2 data field returned
        {
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
        }
    } 
    //generate cryptographic checksum
    uint8_t udol[4] = {0x00,0x00,0x00,0x00}; 
    emv_computecryptogram(udol, sizeof(udol));
    if(responsebuffer[1] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&responsebuffer[1], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); */ 
    } 
return 0;    
} 

int EMV_PaypassTransaction()
{
    uint8_t *responsebuffer  = emv_get_bigbufptr(); 
    tlvtag temptag; //buffer for decoded tags 
    //get the current block counter 
    //select the AID (Mastercard 
    EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
    
    if(responsebuffer[1] == 0x6F){ //decode template
        decode_ber_tlv_item(&responsebuffer[1], &temptag);
        //decode 84 and A5 tags 
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
        //decode the A5 tag 
        emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
        //decode the BF0C result, assuming 1 directory entry for now 
        //retrieve the AID 
    }
    //get PDOL
    uint8_t pdolcommand[20]; //20 byte buffer for pdol data 
    uint8_t pdolcommandlen = 0; 
    if(currentcard.tag_9F38_len > 0) { 
        emv_generateDOL(currentcard.tag_9F38, currentcard.tag_9F38_len, &currentcard, pdolcommand, &pdolcommandlen); 
    }
    else{
        //pdolcommand = NULL; //pdol val is null
        pdolcommandlen = 0;
    }
    if(!emv_getprocessingoptions(pdolcommand,pdolcommandlen)) {
        if(EMV_DBGLEVEL >= 1) Dbprintf("PDOL failed");
        return 1; 
    }
    if(responsebuffer[1] == 0x80) //format 1 data field returned
    { 
        memcpy(currentcard.tag_82, &responsebuffer[3],2); //copy AIP
        currentcard.tag_94_len =  responsebuffer[2]-2; //AFL len
        memcpy(currentcard.tag_94, &responsebuffer[5],currentcard.tag_94_len); //copy AFL 
    }
    else if(responsebuffer[1] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&responsebuffer[1], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    } 
    else
    {
        //throw an error
    }
    Dbprintf("AFL=");
    Dbhexdump(currentcard.tag_94_len, currentcard.tag_94,false); 
    Dbprintf("AIP=");
    Dbhexdump(2, currentcard.tag_82, false); 
    emv_decodeAIP(currentcard.tag_82); 
    
            //decode the AFL list and read records 
    /*
    uint8_t i = 0; 
    uint8_t sfi = 0;
    uint8_t recordstart = 0; 
    uint8_t recordend = 0; 
   
    while( i< currentcard.tag_94_len){
        sfi = (currentcard.tag_94[i++] & 0xF8) >> 3;
        recordstart = currentcard.tag_94[i++];
        recordend = currentcard.tag_94[i++];
        for(int j=recordstart; j<(recordend+1); j++){
        //read records 
            EMVReadRecord(blockcounter, j,sfi, &currentcard);
            emv_decodePCB(&blockcounter);
            while(responsebuffer[0] == 0xF2) {
                EMVReadRecord(blockcounter, j,sfi, &currentcard);
                emv_decodePCB(&blockcounter);
            }
        }  
        i++;
    }
    */
    //record, sfi 
    EMVReadRecord( 1,1, &currentcard);
    EMVReadRecord( 1,2, &currentcard);
    EMVReadRecord( 1,3, &currentcard);
    EMVReadRecord( 2,3, &currentcard);
    
    //DDA supported, so read more records 
    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED){ 
        EMVReadRecord( 1,4, &currentcard);
        EMVReadRecord( 2,4, &currentcard);
    }

    /* 
    //lets read records! 
    //limit for now to 10 SFIs and 10 records each 
    
    for(uint8_t sfi=1; sfi<11;sfi++){ 
        for(uint8_t record=1; record < 11; record++){ 
            EMVReadRecord(blockcounter, record,sfi, &currentcard);
            emv_decodePCB(&blockcounter);
            while(responsebuffer[0] == 0xF2) {
                EMVReadRecord(blockcounter, record,sfi, &currentcard);
                emv_decodePCB(&blockcounter);
            }       
        }
    }
    */ 
    /* get ICC dynamic data */
    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED)
    {
        //DDA supported, so perform GENERATE AC 
        uint8_t cdolcommand[40]; //20 byte buffer for pdol data 
        uint8_t cdolcommandlen; 
        //generate the iCC UN 
        emv_getchallenge();
        memcpy(currentcard.tag_9F4C,&responsebuffer[1],8); // ICC UN 
        if(currentcard.tag_8C_len > 0) { 
            emv_generateDOL(currentcard.tag_8C, currentcard.tag_8C_len, &currentcard, cdolcommand, &cdolcommandlen); }
        else{
            //cdolcommand = NULL; //cdol val is null
            cdolcommandlen = 0;
        }
        emv_generateAC(0x80, cdolcommand,cdolcommandlen);
        if(responsebuffer[1] == 0x77) //format 2 data field returned
        {
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
        }
        //generate AC2  
        if(currentcard.tag_8D_len > 0) { 
            emv_generateDOL(currentcard.tag_8D, currentcard.tag_8D_len, &currentcard, cdolcommand, &cdolcommandlen); }
        else{
            //cdolcommand = NULL; //cdol val is null
            cdolcommandlen = 0;
        }
        emv_generateAC(0x80, cdolcommand,cdolcommandlen);
        
        if(responsebuffer[1] == 0x77) //format 2 data field returned
        {
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
        }
    } 
    //generate cryptographic checksum
    uint8_t udol[4] = {0x00,0x00,0x00,0x00}; 
    emv_computecryptogram(udol, sizeof(udol));
    if(responsebuffer[1] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&responsebuffer[1], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    } 
return 0;
}

void EMVTransaction()
{
    //params
    //uint8_t recordNo = arg0;
    //uint8_t sfi = arg1;
    uint8_t uid[10];
    uint32_t cuid;
    
    uint8_t *responsebuffer  = emv_get_bigbufptr(); 
    //variables
    tlvtag temptag; //used to buffer decoded tag valuesd  
    //byte_t isOK = 0;
    //initialize the emv card structure
    //extern emvcard currentcard;
    
    memset(&currentcard, 0x00, sizeof(currentcard)); //set all to zeros 
    //memcpy(currentcard.tag_9F66,"\x20\x00\x00\x00",4);
    memcpy(currentcard.tag_9F66,"\xD7\x20\xC0\x00",4);
    //memcpy(currentcard.tag_9F66,"\xC0\x00\x00\x00",2);
    memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6); //20 dollars 
    memcpy(currentcard.tag_9F37, "\x01\x02\x03\x04", 4); //UN 
    memcpy(currentcard.tag_5F2A, "\x00\x36",2); //currency code
    //CDOL stuff 
    //memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6);
    memcpy(currentcard.tag_9F03,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(currentcard.tag_9F1A,"\x00\x36",2); //country code
    memcpy(currentcard.tag_95,"\x00\x00\x00\x00\x00",5); //TVR
    //memcpy(currentcard.tag_5F2A,"\x00\x36",2);
    memcpy(currentcard.tag_9A,"\x14\x04\x01",3); //date
    memcpy(currentcard.tag_9C,"\x00",1); //processingcode;
    memcpy(currentcard.tag_9F45, "\x00\x00", 2); //Data Authentication Code
    memset(currentcard.tag_9F4C,0x00,8); // ICC UN
    memcpy(currentcard.tag_9F35,"\x12",1);
    memcpy(currentcard.tag_9F34,"\x3F\x00\x00", 3); //CVM 
      
    iso14a_clear_trace();
    //iso14a_set_tracing(true);
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
    
    while(true) { 
        if(!iso14443a_select_card(uid,NULL,&cuid)) {
            if(EMV_DBGLEVEL >= 1) Dbprintf("Can't select card");
            break;
        }
        EMVSelectPPSE();
        //get response
        if(responsebuffer[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            //decode the BF0C result, assuming 1 directory entry for now 
            if(currentcard.tag_BF0C_len !=0){
                emv_decode_field(currentcard.tag_BF0C, currentcard.tag_BF0C_len, &currentcard);}
            //retrieve the AID, use the AID to decide what transaction flow to use 
            if(currentcard.tag_61_len !=0){
                emv_decode_field(currentcard.tag_61, currentcard.tag_61_len, &currentcard);}
        } 
        if(!memcmp(currentcard.tag_4F, AID_MASTERCARD,sizeof(AID_MASTERCARD))){
            Dbprintf("Mastercard Paypass Card Detected"); 
            EMV_PaypassTransaction();
        }
        else if(!memcmp(currentcard.tag_4F, AID_VISA, sizeof(AID_VISA))){            
            Dbprintf("VISA Paywave Card Detected"); 
            EMV_PaywaveTransaction();
        }
        
        LED_B_ON();
        //output the sensitive data
        cmd_send(CMD_ACK, 0, 0,0,responsebuffer,100); 
        LED_B_OFF();
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("EMV TRANSACTION FINISHED");
        //finish up
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}

//EMV clone a card - read up to the max SFI and max records for that SFI
void EMVClone(uint8_t maxsfi, uint8_t maxrecord)
{
     //params
    //uint8_t recordNo = arg0;
    //uint8_t sfi = arg1;
    uint8_t uid[10];
    uint32_t cuid;
    //uint32_t selTimer = 0; 
    uint8_t *responsebuffer  = emv_get_bigbufptr(); 
    iso14a_card_select_t hi14a_card; //card select values
    //variables
    tlvtag temptag; //used to buffer decoded tag valuesd  
    //byte_t isOK = 0;
    //initialize the emv card structure
    //extern emvcard currentcard;
    
    memset(&currentcard, 0x00, sizeof(currentcard)); //set all to zeros 
    //memcpy(currentcard.tag_9F66,"\x20\x00\x00\x00",4);
    memcpy(currentcard.tag_9F66,"\xD7\x20\xC0\x00",4);
    //memcpy(currentcard.tag_9F66,"\xC0\x00\x00\x00",2);
    memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6); //20 dollars 
    memcpy(currentcard.tag_9F37, "\x01\x02\x03\x04", 4); //UN 
    memcpy(currentcard.tag_5F2A, "\x00\x36",2); //currency code
    //CDOL stuff 
    //memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6);
    memcpy(currentcard.tag_9F03,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(currentcard.tag_9F1A,"\x00\x36",2); //country code
    memcpy(currentcard.tag_95,"\x00\x00\x00\x00\x00",5); //TVR
    //memcpy(currentcard.tag_5F2A,"\x00\x36",2);
    memcpy(currentcard.tag_9A,"\x14\x04x01",3); //date
    memcpy(currentcard.tag_9C,"\x00",1); //processingcode;
    memcpy(currentcard.tag_9F45, "\x00\x00", 2); //Data Authentication Code
    memset(currentcard.tag_9F4C,0x00,8); // ICC UN
    memcpy(currentcard.tag_9F35,"\x12",1);
    memcpy(currentcard.tag_9F34,"\x3F\x00\x00", 3); //CVM 
      
    iso14a_clear_trace();
    //iso14a_set_tracing(true);
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
    
    while(true) { 
        if(!iso14443a_select_card(uid,&hi14a_card,&cuid)) {
            if(EMV_DBGLEVEL >= 1) Dbprintf("Can't select card");
            break;
        }
        //copy UID and ATQA SAK and ATS values
        memcpy(currentcard.UID, hi14a_card.uid, hi14a_card.uidlen);  
        currentcard.UID_len = hi14a_card.uidlen; 
        memcpy(currentcard.ATQA, hi14a_card.atqa, 2);
        currentcard.SAK = (uint8_t)hi14a_card.sak;
        memcpy(currentcard.ATS, hi14a_card.ats, hi14a_card.ats_len);
        currentcard.ATS_len = hi14a_card.ats_len;
 
        if(EMV_DBGLEVEL >= 1){
            Dbprintf("UID=");
            Dbhexdump(currentcard.UID_len, currentcard.UID, false);
            Dbprintf("ATQA=");
            Dbhexdump(2, currentcard.ATQA,false);
            Dbprintf("SAK=");
            Dbhexdump(1, &currentcard.SAK,false);
            Dbprintf("ATS=");
            Dbhexdump(currentcard.ATS_len, currentcard.ATS,false);
        }
        EMVSelectPPSE();
        //get response
        if(responsebuffer[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            //decode the BF0C result, assuming 1 directory entry for now 
            if(currentcard.tag_BF0C_len !=0){
                emv_decode_field(currentcard.tag_BF0C, currentcard.tag_BF0C_len, &currentcard);}
            //retrieve the AID, use the AID to decide what transaction flow to use 
            if(currentcard.tag_61_len !=0){
                emv_decode_field(currentcard.tag_61, currentcard.tag_61_len, &currentcard);}
        } 
        //perform AID selection 
        EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
        if(responsebuffer[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&responsebuffer[1], &temptag);
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            //decode the BF0C result, assuming 1 directory entry for now 
        }
        //decode the AFL list and read records 
        
        //scan all card records 
        Dbprintf("Reading %u SFIs and %u records...", maxsfi, maxrecord); 
        for(uint8_t sfi = 1; sfi < maxsfi; sfi++){ //all possible SFI values
            for(uint8_t record = 1; record < maxrecord; record++){
                EMVReadRecord(record,sfi, &currentcard);
                if(responsebuffer[1] == 0x70){ 
                Dbprintf("Record Found! SFI=%u RECORD=%u", sfi, record);
                } 
            }
        }
        Dbprintf("Reading finished"); 
        
        LED_B_ON();
        //output the sensitive data
        cmd_send(CMD_ACK, 0, 0,0,responsebuffer,100); 
        LED_B_OFF();
        break;
    }
    if(EMV_DBGLEVEL >= 2) DbpString("EMV TRANSACTION FINISHED");
        //finish up
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}

//EMV simulated card - uses values in the current card structure
void EMVSim()
{
    // Enable and clear the trace
	iso14a_clear_trace();
	//iso14a_set_tracing(FALSE);
	iso14a_set_tracing(TRUE);
    UartReset();
    DemodReset();
	uint8_t sak;

	// The first response contains the ATQA (note: bytes are transmitted in reverse order).
	uint8_t response1[2];
    
    response1[0] = currentcard.ATQA[0];
    response1[1] = currentcard.ATQA[1];
    sak = currentcard.SAK;	
	
    //setup the UID	
    uint8_t rUIDBCC1[5]; //UID 93+BCC
    uint8_t rUIDBCC2[5]; //UID 95+BCC
    uint8_t rUIDBCC3[5]; //UID 97+BCC
    
    if(currentcard.UID_len == 4){
        memcpy(rUIDBCC1, currentcard.UID,4);
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3]; 
    }
    else if(currentcard.UID_len == 7){
        rUIDBCC1[0] = 0x88; //CT
        memcpy(&rUIDBCC1[1], currentcard.UID, 3);
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3]; 
        memcpy(rUIDBCC2, &currentcard.UID[3], 4);
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3]; 
    }
    else if(currentcard.UID_len == 10){
        rUIDBCC1[0] = 0x88; //CT
        memcpy(&rUIDBCC1[1], currentcard.UID, 3);
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3]; 
        rUIDBCC2[0] = 0x88; //CT
        memcpy(&rUIDBCC2[1], &currentcard.UID[3], 3);
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
        memcpy(rUIDBCC3, &currentcard.UID[6], 4);
        rUIDBCC3[4] = rUIDBCC3[0] ^ rUIDBCC3[1] ^ rUIDBCC3[2] ^ rUIDBCC3[3]; 
    }
    else{ //error - exit
       if(EMV_DBGLEVEL >= 2)
            Dbprintf("UID not set");
            return;  
    }

	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t response3[3];
	response3[0] = sak;
	ComputeCrc14443(CRC_14443_A, response3, 1, &response3[1], &response3[2]);

	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
	uint8_t response3a[3];
	response3a[0] = sak & 0xFB;
    ComputeCrc14443(CRC_14443_A, response3a, 1, &response3a[1], &response3a[2]);
	//ComputeCrc14443(CRC_14443_A, response6, 4, &response6[4], &response6[5]);
    uint8_t ACK1[] = {0xa3,0x6f,0xc6}; 
    uint8_t ACK2[] = {0xa2,0x00,0x00};
    AppendCrc14443a(ACK2, 1); 
    uint8_t tagvalbuffer[256];
    uint8_t tagvallen;  
    //create "Record 1 1"	
    uint8_t template6F[] = {0x6F,0x00}; 
    uint8_t templateA5[] = {0xA5,0x00}; 
    uint8_t tag1[] = {0xBF,0x0C,0x00};
    
    uint8_t tag7[] = {0x84, 0x00};
    uint8_t tag8[] = {0xA5, 0x00}; 
    emv_generatetemplate(templateA5,&currentcard,tagvalbuffer,&tagvallen, 1, tag1);
    memcpy(currentcard.tag_A5, tagvalbuffer+2, tagvallen-2);
    currentcard.tag_A5_len = tagvallen-2;
    emv_generatetemplate(template6F,&currentcard,currentcard.tag_6F ,&currentcard.tag_6F_len, 2, tag7, tag8);
    Dbprintf("TAG 6F=%i", currentcard.tag_6F_len);
    Dbhexdump(currentcard.tag_6F_len, currentcard.tag_6F, false); 
    Dbprintf("TAG A5=%i", currentcard.tag_A5_len);
    Dbhexdump(currentcard.tag_A5_len, currentcard.tag_A5, false); 
    //pre-generate the tag for speed.
    //Define PPSS responses (always say yes)
    uint8_t PPSS_0[] = {0xD0,0x73,0x87};
    uint8_t PPSS_1[] = {0xD1,0x00,0x00};
    AppendCrc14443a(PPSS_1, 1); 
    uint8_t DESELECT[] = {0xC2,0xE0, 0xB4};
 
    #define TAG_RESPONSE_COUNT 12 
	tag_response_info_t responses[TAG_RESPONSE_COUNT] = {
		{ .response = response1,  .response_n = sizeof(response1)  },  // Answer to request - respond with card type
		{ .response = rUIDBCC1,  .response_n = sizeof(rUIDBCC1)  },  // Anticollision cascade1 - respond with uid
		{ .response = rUIDBCC2, .response_n = sizeof(rUIDBCC2) },  // Anticollision cascade2 - respond with 2nd half of uid if asked
		{ .response = rUIDBCC3,  .response_n = sizeof(rUIDBCC3)  },  // Acknowledge select - cascade 3 - respond with 3rd part of UID 
		{ .response = response3,  .response_n = sizeof(response3)  },  // Acknowledge select - cascade 1
		{ .response = response3a, .response_n = sizeof(response3a) },  // Acknowledge select - cascade 2
		{ .response = currentcard.ATS,  .response_n = currentcard.ATS_len  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK1,  .response_n = 3},  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK2,  .response_n = 3},  // dummy ATS (pseudo-ATR), answer to RATS
        { .response = PPSS_0, .response_n = 3},
        { .response = PPSS_1, .response_n = 3}, 
        { .response = DESELECT, .response_n = 3},
    };

	// Allocate 512 bytes for the dynamic modulation, created when the reader queries for it
	// Such a response is less time critical, so we can prepare them on the fly
	#define DYNAMIC_RESPONSE_BUFFER_SIZE 64 
	#define DYNAMIC_MODULATION_BUFFER_SIZE 512 
	uint8_t dynamic_response_buffer[DYNAMIC_RESPONSE_BUFFER_SIZE];
	uint8_t dynamic_modulation_buffer[DYNAMIC_MODULATION_BUFFER_SIZE];
	tag_response_info_t dynamic_response_info = {
		.response = dynamic_response_buffer,
		.response_n = 0,
		.modulation = dynamic_modulation_buffer,
		.modulation_n = 0
	};
  
	// Reset the offset pointer of the free buffer
	reset_free_buffer();
  
	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
	for (size_t i=0; i<TAG_RESPONSE_COUNT; i++) {
		prepare_allocated_tag_modulation(&responses[i]);
	}

	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	uint16_t len = 0;
	// To control where we are in the protocol
	int order = 0;
	int lastorder;

	// Just to allow some checks
	int happened = 0;
	int happened2 = 0;
	int cmdsRecvd = 0;

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

	cmdsRecvd = 0;
	tag_response_info_t* p_response;

	LED_A_ON();
	for(;;) {
		// Clean receive command buffer
		
		if(!GetIso14443aCommandFromReader(receivedCmd, &len, RECV_CMD_SIZE,1000)) {
			DbpString("Button press");
			break;
		}
		p_response = NULL;
		
		// doob - added loads of debug strings so we can see what the reader is saying to us during the sim as hi14alist is not populated
		// Okay, look at the command now.
		lastorder = order;
		if(receivedCmd[0] == 0x26) { // Received a REQUEST
			p_response = &responses[0]; order = 1;
		} else if(receivedCmd[0] == 0x52) { // Received a WAKEUP
			p_response = &responses[0]; order = 6;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
			p_response = &responses[1]; order = 2;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x95) { // Received request for UID (cascade 2)
			p_response = &responses[2]; order = 20;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
			p_response = &responses[4]; order = 3;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x95) {	// Received a SELECT (cascade 2)
			p_response = &responses[5]; order = 30;
		} 
        else if(receivedCmd[0] == 0xB2){
            if(order == 4) { //send NACK, no command sent	
                //p_response = &DFETag; order = 30;
            }
            else{ //send last command again
			    p_response = &responses[7]; order = 30;
            }
        }  
        else if(receivedCmd[0] == 0xB3) {	// Received a SELECT (cascade 2)
            if(order == 4 ) { //send NACK, no command sent	
                //p_response = &DFETag; order = 30;
		    }
            else{ //send last command again
			    p_response = &responses[8]; order = 30;
            }		
        } 
        else if(receivedCmd[0] == 0xD0) {	// Received a SELECT (cascade 2)
			    p_response = &responses[9]; order = 30;
        }
        else if(receivedCmd[0] == 0xD1) {	// Received a SELECT (cascade 2)
			    p_response = &responses[10]; order = 30;
        }
        else if(receivedCmd[0] == 0xC2) {	// Received a DESELECT 
			    p_response = &responses[11]; order = 30;
        } 
        else if(receivedCmd[0] == 0x30) {	// Received a (plain) READ
			//EmSendCmdEx(data+(4*receivedCmd[0]),16,false);
			// Dbprintf("Read request from reader: %x %x",receivedCmd[0],receivedCmd[1]);
			// We already responded, do not send anything with the EmSendCmd14443aRaw() that is called below
			p_response = NULL;}
		 else if(receivedCmd[0] == 0x50) {	// Received a HALT
//			DbpString("Reader requested we HALT!:");
			if (tracing) {
				LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, &Uart.parityBits, TRUE);
				LogTrace(NULL, 0, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, NULL, TRUE);
			}
			p_response = NULL;
		} else if(receivedCmd[0] == 0x60 || receivedCmd[0] == 0x61) {	// Received an authentication request
			p_response = &responses[5]; order = 7;
		} else if(receivedCmd[0] == 0xE0) {	
            // Received a RATS request
            /*if (tagType == 1 || tagType == 2) {	// RATS not supported
				EmSend4bit(CARD_NACK_NA);
				p_response = NULL;
			} else */ {
				p_response = &responses[6]; 
			}
		} /*else if(receivedCmd[0] == 0x02) {
				p_response = &responses[9]; 
        } */ 
        else {
			// Check for ISO 14443A-4 compliant commands, look at left nibble
			switch (receivedCmd[0]) {
                case 0x02:
				case 0x03: { // Readers sends deselect command
                  Dbprintf("COMMAND_RECEIVED"); 
                  //dynamic_response_info.response[0] = receivedCmd[0];
				  if(receivedCmd[1] == 0x00){
                    if(receivedCmd[2] == 0xA4){ //SELECT AID
                       if(receivedCmd[6] == 0x32 ){ //DFE present 
                        //canned response
				        dynamic_response_info.response[0] = receivedCmd[0];
                        dynamic_response_info.response_n = 1 + currentcard.tag_6F_len;
                        memcpy(&dynamic_response_info.response[1], currentcard.tag_6F,currentcard.tag_6F_len); 
                        }
                        if (tracing) {
						LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, &Uart.parityBits, TRUE);
						LogTrace(NULL, 0, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, NULL, TRUE);}
                    break;}}
                    else if(receivedCmd[1] == 0x80){
                        }	
            } break;  
                default: {
					// Never seen this command before
					if (tracing) {
						LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, &Uart.parityBits, TRUE);
						LogTrace(NULL, 0, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, NULL, TRUE);
					}
					Dbprintf("Received unknown command (len=%d):",len);
					Dbhexdump(len,receivedCmd,false);
					// Do not respond
					dynamic_response_info.response_n = 0;
				} break;
			}
      
			if (dynamic_response_info.response_n > 0) {
				// Copy the CID from the reader query
				//dynamic_response_info.response[1] = receivedCmd[1];

				// Add CRC bytes, always used in ISO 14443A-4 compliant cards
				AppendCrc14443a(dynamic_response_info.response,dynamic_response_info.response_n);
				dynamic_response_info.response_n += 2;
                  
				if (prepare_tag_modulation(&dynamic_response_info,DYNAMIC_MODULATION_BUFFER_SIZE) == false) {
					Dbprintf("Error preparing tag response");
					if (tracing) {
						LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, &Uart.parityBits, TRUE);
						LogTrace(NULL, 0, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, NULL, TRUE);
					}
					break;
				}
				p_response = &dynamic_response_info;
			     
            }
		}

		// Count number of wakeups received after a halt
		if(order == 6 && lastorder == 5) { happened++; }

		// Count number of other messages after a halt
		if(order != 6 && lastorder == 5) { happened2++; }

		if(cmdsRecvd > 999) {
			DbpString("1000 commands later...");
			break;
		}
		cmdsRecvd++;

		if (p_response != NULL) {
                EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, (receivedCmd[0] == 0x52) || (receivedCmd[0]==0x26));
			    //Dbprintf("Sending:");
                //Dbhexdump(p_response->response_n, p_response->response, false); 
                // do the tracing for the previous reader request and this tag answer:
		        //uint32_t paritybuffer[(p_response->response_n/32)+1];
                //parity_t parity;
                //parity.byte = paritybuffer;
                //GetParity(p_response->response, p_response->response_n, &parity);
                //SwapBitsParity(&parity); 
                /* EmLogTrace(Uart.output, 
						Uart.len, 
						Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, 
						Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, 
						&Uart.parityBits,
						p_response->response, 
						p_response->response_n,
						LastTimeProxToAirStart*16 + DELAY_ARM2AIR_AS_TAG,
						(LastTimeProxToAirStart + p_response->ProxToAirDuration)*16 + DELAY_ARM2AIR_AS_TAG, 
                &parity);*/
		}
	/*	
		if (!tracing) {
			Dbprintf("Trace Full. Simulation stopped.");
			break;
		} */
    }    

	Dbprintf("%x %x %x", happened, happened2, cmdsRecvd);
	LED_A_OFF();
}

//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void EMVFuzz_RATS(uint8_t ratslen, uint8_t* RATS)
{
    // Enable and clear the trace
	//iso14a_clear_trace();
	//iso14a_set_tracing(FALSE);
	//iso14a_set_tracing(TRUE);
    UartReset();
    DemodReset();
    uint16_t len; 
	uint8_t sak;
    //copy input rats into a buffer
    uint8_t ratscmd[ratslen+2]; 
    memcpy(ratscmd, RATS, ratslen);
	
    // The first response contains the ATQA (note: bytes are transmitted in reverse order).
	uint8_t atqa[2];
	atqa[0] = 0x04;
	atqa[1] = 0x00;
	sak = 0x28;
	
	// The second response contains the (mandatory) first 24 bits of the UID
	uint8_t uid0[5] = {0x12,0x34,0x56,0x78,0x9A};

	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	uid0[4] = uid0[0] ^ uid0[1] ^ uid0[2] ^ uid0[3];

	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t sakresponse[3];
	sakresponse[0] = sak;
	ComputeCrc14443(CRC_14443_A, sakresponse, 1, &sakresponse[1], &sakresponse[2]);

	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
    
    uint8_t ACK1[] = {0xa3,0x6f,0xc6}; //ACK packets 
    uint8_t ACK2[] = {0xa2,0x00,0x00};
    AppendCrc14443a(ACK2, 1);
    
    AppendCrc14443a(ratscmd, sizeof(ratscmd)-2); 
    //ComputeCrc14443(CRC_14443_A, response6, 4, &response6[4], &response6[5]);

    //handle the PPS selection
    uint8_t PPSR[3] = {0xD0,0x00,0x00};
    AppendCrc14443a(PPSR, 1);
    
	//#define TAG_RESPONSE_COUNT 9 
	tag_response_info_t responses[7] = {
		{ .response = atqa,  .response_n = sizeof(atqa)  },  // Answer to request - respond with card type
		{ .response = uid0,  .response_n = sizeof(uid0)  },  // Anticollision cascade1 - respond with uid
		{ .response = sakresponse,  .response_n = sizeof(sakresponse)  },  // Acknowledge select - cascade 1
		{ .response = ratscmd,  .response_n = sizeof(ratscmd)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK1,  .response_n = sizeof(ACK1)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK2,  .response_n = sizeof(ACK2)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = PPSR,  .response_n = sizeof(PPSR)  },  // dummy ATS (pseudo-ATR), answer to RATS
	};

	// Reset the offset pointer of the free buffer
	reset_free_buffer();
  
	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
    for (size_t i=0; i<7; i++) {
		prepare_allocated_tag_modulation(&responses[i]);
	}
	uint8_t *receivedCmd = (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);
	//uint16_t len = 0;

	// To control where we are in the protocol
	int order = 0;
	// Just to allow some checks

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
	tag_response_info_t* p_response;
    
	LED_C_ON();
	// Clean receive command buffer
    for(;;){  
        if(!GetIso14443aCommandFromReader(receivedCmd, &len, RECV_CMD_SIZE, 250)){
            //Dbprintf("timeout");
            break;
        } 
	    p_response = NULL;
        //Dbhexdump(len, receivedCmd,false); 
        if((receivedCmd[0] == 0x26) || (receivedCmd[0] == 0x52)) { // Received a REQUEST
	    	p_response = &responses[0]; order = 1;
        }	
	    if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
            p_response = &responses[1]; order = 2; //send the UID 
	    }  
        if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
	    	p_response = &responses[2]; order = 3; //send the SAK
	    }
        if(receivedCmd[0] == 0xD0) {	// Received a PPS request
	    	//p_response = &responses[6]; order = 70;
	    	p_response = &responses[6]; order = 70;
	    } 
	    if(receivedCmd[0] == 0xE0) {	// Received a RATS request
	    	//p_response = &responses[6]; order = 70;
	    	p_response = &responses[3]; order = 70;
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, (receivedCmd[0] == 0x52) || (receivedCmd[0] == 0x26));
            break;
	    }
        if(p_response != NULL){
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n, (receivedCmd[0] == 0x52) || (receivedCmd[0] == 0x26));
        }
        else{
            //Dbprintf("finished"); 
            break;
        } 
    } 
    //Dbprintf("finished"); 
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_C_OFF();
    return;
}

