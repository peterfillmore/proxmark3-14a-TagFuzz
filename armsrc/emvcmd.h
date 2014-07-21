//------------------------------------------------------------------------------
// Peter Fillmore -2012
// Based off MIFARECMD code
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support EMV Transactions.
//-----------------------------------------------------------------------------

#ifndef __EMVCMD_H
#define __EMVCMD_H

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

#include "iso14443crc.h"
#include "iso14443a.h"
#include "common.h"
#include "emvutil.h"
#include "emvcard.h"
//create an external pointer to the emvcard
//this is to allow other functions to process scanned cards
//emvcard currentcard;
#endif
