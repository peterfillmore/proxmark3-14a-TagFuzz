//-----------------------------------------------------------------------------
// Copyright (C) 2011,2012 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE commands
//-----------------------------------------------------------------------------

#include "cmdhfmf.h"

static int CmdHelp(const char *Cmd);

int CmdHF14AEMVTest(const char *Cmd)
{
    //send command	
  UsbCommand c = {CMD_EMV_TEST, {0, 0, 0}};
  SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1000)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}
	return 0;
}

int CmdHF14AEMVReadRecord(const char *Cmd)
{
	uint8_t recordNo = 0;
	uint8_t sfi = 0;
	
	if (strlen(Cmd)<3) {
		PrintAndLog("Usage:  hf emv readrecord <Record Number> <SFI>");
		PrintAndLog("        sample: hf emv readrecord 1 1");
		return 0;
	}	

	recordNo = param_get8(Cmd, 0);
	sfi = param_getchar(Cmd, 1);
    //check inputs 
    if(recordNo > 32){
        PrintAndLog("Record must be less than 32"); 
    }	
	
	PrintAndLog("--record no:%02x SFI:%02x ", recordNo, sfi);

    //send command	
  UsbCommand c = {CMD_EMV_READ_RECORD, {recordNo, sfi, 0}};
  SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1000)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}
	return 0;
}

int CmdHF14AEMVSim(const char *Cmd)
{
    UsbCommand c = {CMD_EMV_SIM, {0,0, 0}};
    SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1000)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}
return 0;
}
 
int CmdHF14AEMVClone(const char *Cmd)
{
	uint8_t sfi = param_get8(Cmd, 0);
	uint8_t record = param_get8(Cmd, 1);
    if (strlen(Cmd) < 3) {
		PrintAndLog("Usage:  hf emv clone <#of SFI records> <# of records>");
		PrintAndLog("        sample: hf emv clone 10 10");
		return 0;
	}	
	//send command	
  UsbCommand c = {CMD_EMV_CLONE, {sfi, record, 0}};
  SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1000)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		PrintAndLog("isOk:%02x", isOK);
	} else {
		PrintAndLog("Command execute timeout");
	}

	return 0;
}
int CmdHF14AEMVTransaction(const char *Cmd)
{
    //send command	
  UsbCommand c = {CMD_EMV_TRANSACTION};
  SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,5000)) {
		uint8_t isOK  = resp.arg[0] & 0xff;
		PrintAndLog("isOk:%02x", isOK);
        for(int x = 0; x<sizeof(resp.d.asBytes);x++){
            printf("%02X", *(resp.d.asBytes+x));
        } 
    } else {
		PrintAndLog("Command execute timeout");
	}

	return 0;
}


static command_t CommandTable[] =
{
  {"help",		CmdHelp,						1, "This help"},
  {"readrecord",			CmdHF14AEMVReadRecord,			0, "EMV Read Record"},
  {"transaction",CmdHF14AEMVTransaction,     0, "Perform EMV Transaction"}, 
  {"clone",     CmdHF14AEMVClone, 0, "Clone an EMV card"}, 
  {"sim",     CmdHF14AEMVSim, 0, "Simulate an EMV card (clone it first)"}, 
  {"test",     CmdHF14AEMVTest, 0, "Test Function"}, 
  {NULL, NULL, 0, NULL} }; 

int CmdHFEMV(const char *Cmd)
{
	// flush
	WaitForResponseTimeout(CMD_ACK,NULL,100);

  CmdsParse(CommandTable, Cmd);
  return 0;
}

int CmdHelp(const char *Cmd)
{
  CmdsHelp(CommandTable);
  return 0;
}
