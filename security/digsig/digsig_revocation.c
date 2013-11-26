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
 * modifs: Chris Wright Sept 2004 
 *         Serge Hallyn Sep 2004: added a hash table (keyed on the first 4
 +                        bytes of the hash) for quicker revocation lookup.
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
#include <linux/hash.h>

#ifdef DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#define DIGSIG_BENCH 1
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#define DIGSIG_BENCH 0
#endif

static spinlock_t revoked_list_wlock = SPIN_LOCK_UNLOCKED;

#define REVOKE_BITS 6
#define REVOKE_BUCKETS 64

static struct hlist_head dsi_revoked_sigs[REVOKE_BUCKETS];

/*
 * Description: Called at exec (digsig_verify_signature) to check whether the
 *  signature has been revoked.  If it has, exec permission is outright
 *  denied.
 */
#ifdef DIGSIG_REVOCATION
int digsig_is_revoked_sig(char *buffer)
{
	struct hlist_node *tmp;
	char *tmp1 = buffer + DIGSIG_BSIGN_INFOS + DIGSIG_RSA_DATA_OFFSET;
	int count = DIGSIG_ELF_SIG_SIZE - DIGSIG_BSIGN_INFOS - DIGSIG_RSA_DATA_OFFSET;
	int h, ret = 0;
	MPI file_sig = mpi_read_from_buffer(tmp1, &count, 0);

	h = hash_long(*(unsigned long *)tmp1, REVOKE_BITS);

	hlist_for_each(tmp, &dsi_revoked_sigs[h]) {
		struct revoked_sig *e = hlist_entry(tmp, struct revoked_sig, next);
		if (mpi_cmp(file_sig, e->sig) == 0) {
			ret = 1;
			goto out;
		}
	}

out:
	mpi_free(file_sig);
	return ret;
}
#endif

int digsig_add_revoked_sig(const char *buffer) {
	int rcount = DIGSIG_ELF_SIG_SIZE - DIGSIG_BSIGN_INFOS - DIGSIG_RSA_DATA_OFFSET;
	const char *tmp1 = buffer + DIGSIG_BSIGN_INFOS + DIGSIG_RSA_DATA_OFFSET;
	struct revoked_sig *s;
	int h;

	s = kmalloc(sizeof(struct revoked_sig), GFP_ATOMIC);

	if (!s)
		return -ENOMEM;

	INIT_HLIST_NODE(&s->next);

	h = hash_long(*(unsigned long*)tmp1, REVOKE_BITS);
	s->sig = mpi_read_from_buffer(tmp1, &rcount, 0);
	spin_lock(&revoked_list_wlock);
	hlist_add_head(&s->next, &dsi_revoked_sigs[h]);
	spin_unlock(&revoked_list_wlock);

	return 0;
}

inline void digsig_init_revocation(void)
{
	int i;

	for (i=0; i<REVOKE_BUCKETS; i++)
		INIT_HLIST_HEAD(&dsi_revoked_sigs[i]);
}

void digsig_cleanup_revocation(void)
{
	int i;
	struct hlist_node *tmp;
	struct revoked_sig *e;

	for (i=0; i<REVOKE_BUCKETS; i++) {
		while (!hlist_empty(&dsi_revoked_sigs[i])) {
			tmp = dsi_revoked_sigs[i].first;
			hlist_del(tmp);
			e = hlist_entry(tmp, struct revoked_sig, next);
			mpi_free(e->sig);
			kfree(e);
		}
	}
}
