//-----------------------------------------------------------------------------
// Copyright (C) 2011 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE commands
//-----------------------------------------------------------------------------

#ifndef CMDHFEMV_H__
#define CMDHFEMV_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "proxmark3.h"
#include "iso14443crc.h"
#include "data.h"
//#include "proxusb.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "emvhost.h"

int CmdHFEMV(const char *Cmd);

int CmdHF14AEMVReadRecord(const char* cmd);

#endif
