/*
 * Distributed Security Module (DSM)
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

extern int g_init;
extern unsigned char *raw_public_key_n;
extern unsigned char *raw_public_key_e;
extern int dsi_mpi_size_n;
extern int dsi_mpi_size_e;
int device_file_major = 0;

/********************************************************************************
Description : This function reads the public key parts: e and n. 
Parameters  : 
Return value: 
*********************************************************************************/
ssize_t dsi_write(struct file *filp, const char *buff, size_t count,
		  loff_t * offp)
{

	int i;
	if (g_init)		// do not accept to re-initialize the module with
		// new public key. This avoids many coherency
		// problem when updating jeys while checking the
		// signatures.
		return -1;

	if (buff[0] == 'n') {
		raw_public_key_n =
		    (unsigned char *) kmalloc(count - 1, DSI_SAFE_ALLOC);
		if (!raw_public_key_n) {
			DSM_ERROR("kmalloc fail for n in dsi_write\n");
			return -ENOMEM;
		}
		if (copy_from_user(raw_public_key_n, &buff[1], count - 1))
			return -EFAULT;
		dsi_mpi_size_n = count - 1;
		DSM_PRINT(DEBUG_DEV, "pkey->n size is %i\n",
			  dsi_mpi_size_n);
		DSM_PRINT(DEBUG_DEV, "pkey->n MPI:\n{ ");
		for (i = 0; i < dsi_mpi_size_n; i++) {
			DSM_PRINT(DEBUG_DEV, "%#x, ",
				  raw_public_key_n[i] & 0xff);
		}
		DSM_PRINT(DEBUG_DEV, "}\n");
	} else if (buff[0] == 'e') {
		raw_public_key_e =
		    (unsigned char *) kmalloc(count - 1, DSI_SAFE_ALLOC);
		if (!raw_public_key_e) {
			DSM_ERROR("kmalloc fail for e in dsi_write\n");
			return -ENOMEM;
		}
		if (copy_from_user(raw_public_key_e, &buff[1], count - 1))
			return -EFAULT;
		dsi_mpi_size_e = count - 1;
		DSM_PRINT(DEBUG_DEV, "pkey->e size is %i\n",
			  dsi_mpi_size_e);
		DSM_PRINT(DEBUG_DEV, "pkey->e MPI:\n{ ");
		for (i = 0; i < dsi_mpi_size_e; i++) {
			DSM_PRINT(DEBUG_DEV, "%#x, ",
				  raw_public_key_e[i] & 0xff);
		}
		DSM_PRINT(DEBUG_DEV, "}\n");
	} else {
		return -EINVAL;
	}

	dsi_init_pkey(buff[0]);

	if (raw_public_key_n && raw_public_key_e) {
		g_init = 1;
	}

	return count;
}
