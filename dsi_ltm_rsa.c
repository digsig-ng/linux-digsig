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
#include "dsi_ltm_rsa.h"
#include "dsi.h"

/******************************************************************************
Description : Prints an mp_int in syslog. For Debug only !
Parameters  : 
Return value: 
******************************************************************************/
/*
static void dsi_ltm_print_mp(char * msg, mp_int *data)
{
  unsigned char str[4096];
  int rc;

  rc = mp_toradix(data,str,16);
  if (rc != MP_OKAY)
    DSM_ERROR("Cannot mp_to_unsigned_bin: %s\n",msg);
  else 
    DSM_PRINT(DEBUG_SIGN, "%s: Used=%d (alloc=%d) Bytes=%d: %s\n",
    msg,data->used,data->alloc,mp_unsigned_bin_size(data),str);
}
*/


/******************************************************************************
Description : 
   Performs RSA verification of a signature 
Parameters  : 
Return value: 0 - RSA signature is valid
              1 - RSA signature is invalid
******************************************************************************/

int
dsi_ltm_rsa_verify(mp_int * hash, mp_int * data, mp_int * exponent,
		   mp_int * modulus)
{
	mp_int result;
	int rc, ret;
	mp_init(&result);
	rc = 0;
	/*
	   dsi_ltm_print_mp("Hash",hash);
	   dsi_ltm_print_mp("Data",data);
	   dsi_ltm_print_mp("Exp.",exponent);
	   dsi_ltm_print_mp("Mod.",modulus);
	 */

	/* verify: data ^ public exp * modulus == ? hash */
	ret = mp_exptmod(data, exponent, modulus, &result);
	/*dsi_ltm_print_mp("Res.",&result); */
	if (ret != MP_OKAY) {
		DSM_ERROR
		    ("dsi_ltm_rsa_verify(): failed to compute modular exp: %d\n",
		     ret);
		rc = 1;
	} else {
		if (mp_cmp(&result, hash) != 0) {
			DSM_PRINT(DEBUG_SIGN,
				  "Signature differs from expected result\n");
			rc = 1;
		}
	}
	mp_clear(&result);
	return rc;
}
