/*
 * Digital Signature (DigSig)
 *
 * dsi_dev.c
 *
 * This file contains the DSM hooks to the kernel.
 * The set of function was defined by the LSM interface.
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: Vincent Roy
 * Modifications: Axelle Apvrille
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>

#include <linux/elf.h>

#include "dsi.h"
#include "dsi_dev.h"
#include "dsi_sig_verify.h"

/* For use with LTM, we copy everything except the first three bytes
   which are 'n' or 'e' + size.
   For use with GnuPG, we should copy everything except the first byte
*/
#ifdef DIGSIG_LTM
#define DSI_KEY_OFFSET 3
#else
#define DSI_KEY_OFFSET 1
#endif

extern int g_init; /* digsig.c */
extern unsigned char *raw_public_key_n; /* dsi_sig_verify */
extern unsigned char *raw_public_key_e; /* dsi_sig_verify */
extern int dsi_mpi_size_n; /* dsi_sig_verify */
extern int dsi_mpi_size_e; /* dsi_sig_verify */
int device_file_major = 0; /* digsig.c */

/********************************************************************************
Description : This function reads the public key parts
We receive first n (the modulus) and then e (public exponent). They follow
this format:
 - 1 byte : character 'n' or 'e'
 - 2 bytes: length of MPI in BITS
 - MPI
Parameters  : 
Return value: 
*********************************************************************************/
ssize_t dsi_write(struct file *filp, const char *buff, size_t count,
		  loff_t * offp)
{

	/* do not accept to re-initialize the module with
	   new public key. This avoids many coherency
	   problem when updating keys while checking the
	   signatures.*/
	if (g_init)
		return -1;

	switch (buff[0]) {

	case 'n':
		raw_public_key_n =
			(unsigned char *) kmalloc(count - DSI_KEY_OFFSET, DIGSIG_SAFE_ALLOC);
		if (!raw_public_key_n) {
			DSM_ERROR("kmalloc fail for n in dsi_write\n");
			return -ENOMEM;
		}
		if (copy_from_user(raw_public_key_n, &buff[DSI_KEY_OFFSET], count - DSI_KEY_OFFSET))
			return -EFAULT;
		dsi_mpi_size_n = count -DSI_ KEY_OFFSET;
		DSM_PRINT(DEBUG_DEV, "pkey->n size is %i\n",
			  dsi_mpi_size_n);
		break;
	case 'e':
		raw_public_key_e =
			(unsigned char *) kmalloc(count - DSI_KEY_OFFSET, DIGSIG_SAFE_ALLOC);
		if (!raw_public_key_e) {
			DSM_ERROR("kmalloc fail for e in dsi_write\n");
			return -ENOMEM;
		}
		if (copy_from_user(raw_public_key_e, &buff[DSI_KEY_OFFSET], count - DSI_KEY_OFFSET))
			return -EFAULT;
		dsi_mpi_size_e = count - DSI_KEY_OFFSET;
		DSM_PRINT(DEBUG_DEV, "pkey->e size is %i\n",
			  dsi_mpi_size_e);
		break;
	default:
		return -EINVAL;
	}

	dsi_init_pkey(buff[0]);

	if (raw_public_key_n && raw_public_key_e) {
		g_init = 1;
	}

	return count;
}
