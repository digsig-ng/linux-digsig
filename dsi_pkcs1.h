/*
 * dsi_pkcs1
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
#ifndef _PKCS1_DSM_H_
#define _PKCS1_DSM_H_

void EMSA_PKCS1_V1_5_encode(char *out, int outlen, char *hashed, int hashalgo);

#endif
