/*
 * Distributed Security Module (DSM)
 *
 * dsi_sysfs.c
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
#include <linux/slab.h>

#include "dsi.h"
#include "dsi_debug.h"
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
extern long int total_jiffies; /* digsig.c */
extern unsigned char *raw_public_key_n; /* dsi_sig_verify */
extern unsigned char *raw_public_key_e; /* dsi_sig_verify */
extern int dsi_mpi_size_n; /* dsi_sig_verify */
extern int dsi_mpi_size_e; /* dsi_sig_verify */

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
ssize_t	digsig_store (struct kobject *obj, struct attribute *attr, const char *buff, size_t count)
{
	switch (buff[0]) {
	case 'i':
		total_jiffies = 0;
		break;
	case 'p':
		printk ("total jiffies = %li\n", total_jiffies);
		break;
	}

	/* do not accept to re-initialize the module with
	   new public key. This avoids many coherency
	   problem when updating keys while checking the
	   signatures.*/
	if (g_init)
		return -1;

	switch (buff[0]) {

	case 'n':
		raw_public_key_n =
			(unsigned char *) kmalloc(count - DSI_KEY_OFFSET, DSI_SAFE_ALLOC);
		if (!raw_public_key_n) {
			DSM_ERROR("kmalloc fail for n in dsi_write\n");
			return -ENOMEM;
		}
		memcpy(raw_public_key_n, &buff[DSI_KEY_OFFSET], count - DSI_KEY_OFFSET);
		dsi_mpi_size_n = count - DSI_KEY_OFFSET;
		DSM_PRINT(DEBUG_DEV, "pkey->n size is %i\n",
			  dsi_mpi_size_n);
		break;
	case 'e':
		raw_public_key_e =
			(unsigned char *) kmalloc(count - DSI_KEY_OFFSET, DSI_SAFE_ALLOC);
		if (!raw_public_key_e) {
			DSM_ERROR("kmalloc fail for e in dsi_write\n");
			return -ENOMEM;
		}
		memcpy(raw_public_key_e, &buff[DSI_KEY_OFFSET], count - DSI_KEY_OFFSET);
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


ssize_t	digsig_show (struct kobject *obj, struct attribute *attr, char *buff)
{

	return 0;
}
