/*
 * dsi_ltm_rsa
 *
 * This file contains the code to verify an RSA signature using the LTM
 * library.
 * 
 * Copyright (C) 2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: Axelle Apvrille <axelle.apvrille@ericsson.ca>
 *        
 */
#ifndef _DSI_LTM_RSA_H_
#define _DSI_LTM_RSA_H_

#include "ltm/tommath.h"

int dsi_ltm_rsa_verify(mp_int *hash, mp_int *data, mp_int *exponent, mp_int *modulus);

#endif
