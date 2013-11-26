/*
 * Digital Signature (DigSig)
 *
 * dsi_extract_mpi.c
 *
 * Copyright (C) 2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Authors: 
 *          David Gordon Aug 2003 
 *          Makan Pourzandi Sep 2003 
 * Modifs: Vincent Roy 
 */

#include <linux/fs.h>

#include "dsi.h"
#include "dsi_debug.h"
#include "dsi_extract_mpi.h"

#define DSI_ELF_SIG_SIZE 512	/* this is a redefinition */
#define DSI_PKEY_N_OFFSET        8	/* offset for pkey->n */

/******************************************************************************
                             Internal functions 
******************************************************************************/

/******************************************************************************
Description : 
Parameters  : 
Return value: 
******************************************************************************/
int dsi_get_pkey(unsigned char *raw_public_key_n,
		 unsigned char *raw_public_key_e, char *pkey_file)
{

/*
 * Format of an MPI:
 * - 2 bytes: length of MPI in BITS
 * - MPI
 */
	struct file *fd = NULL;
	int i;
	unsigned int len;
	unsigned char c;
	int offset = DSI_PKEY_N_OFFSET;

	DSM_PRINT(DEBUG_SIGN, "Call filp_open\n");

	fd = filp_open(pkey_file, O_RDONLY, 0400);
	if (IS_ERR(fd) || (fd == NULL)) {
		DSM_ERROR("digsig: Unable to open file %s !\n", pkey_file);
		return -1;
	}

	if (!fd->f_op || !fd->f_op->mmap || !fd->f_op->read) {
		DSM_ERROR("No file_operations struct\n");
		return -1;
	}

	DSM_PRINT(DEBUG_SIGN, "pkey->n MPI:\n{ ");

	kernel_read(fd, offset++, &c, 1);
	raw_public_key_n[0] = c;
	DSM_PRINT_NO_PREFIX (DEBUG_SIGN, "%#x, ", c & 0xff);
	len = c << 8;

	kernel_read(fd, offset++, &c, 1);
	raw_public_key_n[1] = c;
	len |= c;
	DSM_PRINT_NO_PREFIX (DEBUG_SIGN, "%#x, ", c & 0xff);
	len = (len + 7) / 8;

	if (len > DSI_ELF_SIG_SIZE) {
		DSM_PRINT(DEBUG_SIGN,
			  "\nLength of 'n' MPI is too large %#x\n", len);
		return -1;
	}

	for (i = 0; i < len; i++) {
		kernel_read(fd, offset++, &c, 1);
		raw_public_key_n[i + 2] = c;
		DSM_PRINT_NO_PREFIX (DEBUG_SIGN, "%#x, ", c & 0xff);
	}

	DSM_PRINT_NO_PREFIX (DEBUG_SIGN, "}\n");

	DSM_PRINT(DEBUG_SIGN, "pkey->e MPI:\n{ ");
	kernel_read(fd, offset++, &c, 1);
	raw_public_key_e[0] = c;
	DSM_PRINT_NO_PREFIX (DEBUG_SIGN, "%#x, ", c & 0xff);
	len = c << 8;

	kernel_read(fd, offset++, &c, 1);
	raw_public_key_e[1] = c;
	len |= c;
	DSM_PRINT_NO_PREFIX (DEBUG_SIGN, "%#x, ", c & 0xff);
	len = (len + 7) / 8;

	if (len > DSI_ELF_SIG_SIZE) {
		DSM_PRINT(DEBUG_SIGN,
			  "\nLength of 'e' MPI is too large %#x\n", len);
		return -1;
	}

	for (i = 0; i < len; i++) {
		kernel_read(fd, offset++, &c, 1);
		DSM_PRINT_NO_PREFIX (DEBUG_SIGN, "%#x, ", c & 0xff);
		raw_public_key_e[i + 2] = c;
	}
	DSM_PRINT_NO_PREFIX (DEBUG_SIGN, "}\n");
	filp_close(fd, 0);

	return 0;

}
