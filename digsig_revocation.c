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

#ifdef DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#define DIGSIG_BENCH 1
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#define DIGSIG_BENCH 0
#endif

static LIST_HEAD(digsig_revoked_sigs);
static spinlock_t revoked_list_lock = SPIN_LOCK_UNLOCKED;

/*
 * Description: Called at module unload to free the list of revoked
 * signatures
 */
void digsig_free_revoked_sigs(void)
{
	struct list_head *tmp;
	struct revoked_sig *rsig;

	spin_lock(&revoked_list_lock);
	while (!list_empty(&digsig_revoked_sigs)) {
		tmp = digsig_revoked_sigs.next;
		if (tmp != &digsig_revoked_sigs) {
			list_del(tmp);
			rsig = list_entry(tmp, struct revoked_sig, next);
			mpi_free(rsig->sig);
			kfree(rsig);
		} else {
			DSM_ERROR("major list screwyness\n");
			break;
		}
	}
	spin_unlock(&revoked_list_lock);
}

/*
 * Description: Called at exec (digsig_verify_signature) to check whether the
 *  signature has been revoked.  If it has, exec permission is outright
 *  denied.
 */
#ifdef DIGSIG_REVOCATION
int digsig_is_revoked_sig(char *buffer)
{
	struct revoked_sig *rsig;
	char *tmp1 = buffer + DIGSIG_BSIGN_INFOS + DIGSIG_RSA_DATA_OFFSET;
	int count = DIGSIG_ELF_SIG_SIZE - DIGSIG_BSIGN_INFOS - DIGSIG_RSA_DATA_OFFSET;
	int ret = 0;
	MPI file_sig = mpi_read_from_buffer(tmp1, &count, 0);

	spin_lock(&revoked_list_lock);
	list_for_each_entry(rsig, &digsig_revoked_sigs, next) {
		if (mpi_cmp(file_sig, rsig->sig) == 0) {
			ret = 1;
			goto out;
		}
	}
out:
	spin_unlock(&revoked_list_lock);
	mpi_free(file_sig);
	return ret;
}
#endif

void digsig_add_revoked_sig(struct revoked_sig *sig)
{
	spin_lock(&revoked_list_lock);
        list_add_tail(&sig->next, &digsig_revoked_sigs);
	spin_unlock(&revoked_list_lock);
}

void digsig_cleanup_revocation(void)
{
	digsig_free_revoked_sigs();
}
