/*
 *  Digital Signature (DigSig)
 *
 * This file implements a list of revoked signatures, and checks each loaded
 * library or binary against the list.  If its signature has been revoked,
 * execution will be halted.
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 * Copyright (c) 2003-2004 International Business Machines <serue@us.ibm.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: Serge Hallyn Mar 2004
 */

#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/kobject.h>
#include "dsi.h"
#include "digsig_cache.h"
#include "digsig_revocation.h"
#include "dsi_sig_verify.h"

#ifdef DSI_DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#define DIGSIG_BENCH 1
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#define DIGSIG_BENCH 0
#endif

extern int DSIDebugLevel;

extern int dsi_max_hashed_sigs, dsi_num_hashed_sigs;
struct list_head dsi_revoked_sigs;

/*
 * Description: Called at module unload to free the list of revoked
 * signatures
 */
void dsi_free_revoked_sigs(void)
{
	struct list_head *tmp;
	struct revoked_sig *rsig;

	while (!list_empty(&dsi_revoked_sigs)) {
		tmp = dsi_revoked_sigs.next;
		if (tmp != &dsi_revoked_sigs) {
			list_del(tmp);
			rsig = list_entry(tmp, struct revoked_sig, next);
			mpi_free(rsig->sig);
			kfree(rsig);
		} else {
			DSM_ERROR("major list screwyness\n");
			return;
		}
	}
}

/*
 * Description: Called at exec (dsi_verify_signature) to check whether the
 *  signature has been revoked.  If it has, exec permission is outright
 *  denied.
 */
#ifdef DSI_REVOCATION
int dsi_is_revoked_sig(char *buffer)
{
	struct list_head *tmp;
	struct revoked_sig *rsig;
	char *tmp1 = buffer + DSI_BSIGN_INFOS + DSI_RSA_DATA_OFFSET;
	int count;
	int ret = 0;
	MPI file_sig = mpi_read_from_buffer(tmp1, &count, 0);

	list_for_each(tmp, &dsi_revoked_sigs) {
		rsig = list_entry(tmp, struct revoked_sig, next);
		if (mpi_cmp(file_sig, rsig->sig) == 0) {
			ret = 1;
			goto out;
		}
	}

out:
	mpi_free(file_sig);
	return ret;
}
#endif

inline void dsi_init_revocation()
{
	INIT_LIST_HEAD(&dsi_revoked_sigs);
}

inline void dsi_cleanup_revocation()
{
	dsi_free_revoked_sigs();
}
