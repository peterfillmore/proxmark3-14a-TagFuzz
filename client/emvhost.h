// Merlok, 2011
// people from mifare@nethemba.com, 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "cmdmain.h"
#include "ui.h"
#include "data.h"
//#include "proxusb.h"
#include "util.h"
#include "iso14443crc.h"

extern char logHexFileName[200];


