/*
 *  Digital Signature (DigSig)
 *
 * dsi_sig_verify.h
 *	
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 * 
 * Author: M. Pourzandi 
 */

#ifndef _DSI_EXTRACT_KEY_H_
#define _DSI_EXTRACT_KEY_H_

int dsi_get_pkey(unsigned char *raw_public_key_n,
		 unsigned char *raw_public_key_e, char *pkey_file);

#endif
