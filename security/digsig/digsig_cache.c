/*
 * Digital Signature (DigSig)
 *
 * This file contains the signature caching code.
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 * Copyright (c) 2003-2004 International Business Machines <serue@us.ibm.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: Serge Hallyn Nov 2003, Jan 2004: add caching of signature validation
 * modifs: Makan Pourzandi Mar 2004 
 *         Chris Wright    Sep 2004 
 *         Serge Hallyn Sep 2004: moved to smp-scalable seqlock-based design.
 *         
 */

#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/kobject.h>
#include "dsi.h"
#include "digsig_cache.h"
#include "dsi_sig_verify.h"
#include <linux/hash.h>
#include <linux/seqlock.h>

#ifdef DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#define DIGSIG_BENCH 1
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#define DIGSIG_BENCH 0
#endif

extern int dsi_cache_buckets;

/*
 * digsig_hash_line: seqlock_t = 28 bytes; next_evicted=2;
 * Assuming 128 byte cache line, this leaves 98 bytes for
 * the entry structs.  Each of those is 12 bytes, so we'll
 * use 8 entries per bucket (96 bytes)
 *
 * We will default to 128 buckets, taking 16384 bytes, and
 * giving between 128 and 1024 (depending on # collisions)
 * entries.
 */
#define ENTRIES_PER_BUCKET 8

/*
 * digsig_hash_entry: a single inode signature validation cache
 * entry.  Since we don't clear these on file unload, we check the
 * inode number and i_sb to ensure the inode was not cleared since
 * we cached the validation.
 *
 * 12 bytes
 */
struct digsig_hash_entry {
	struct inode *inode;
	unsigned long i_ino;
	struct super_block *i_sb;
};

/*
 * digsig_hash_line: this is a cache entry bucket.  hash(inode)
 * will index to a hash bucket, which contains ENTRIES_PER_BUCKET
 * entries for collisions.  In this way a lookup should be write-less,
 * and entirely contained within one cache line.
 *
 * When a bucket is full, we evict in a round-robin fashion (unless
 * the next_evicted happened to be the last allocated)
 */
struct digsig_hash_line {
	seqlock_t sequence;
	struct digsig_hash_entry entry[ENTRIES_PER_BUCKET];
	short next_evicted;
};

static struct digsig_hash_line *sig_cache;
static int digsig_hash_bits;

#define hash(inode) hash_long((unsigned long)inode, digsig_hash_bits)

/******************************************************************************
Description : does the cache validation entry describe this inode?
	If the inode * is the same value, but i_ino or i_sb has changed, then
	the inode has been unloaded since we saved the validation, so we must
	clear the entry.
Parameters  : 
	@p: a cached signature validation entry
	@inode: an inode
Return value: 1 if the sig entry is for the given inode, 0 otherwise 
******************************************************************************/
static inline int
is_same_inode(struct digsig_hash_entry *e, struct inode *inode)
{
	if (e->inode != inode)
		return 0;
	if (e->i_ino != inode->i_ino || e->i_sb != inode->i_sb) {
		e->inode = NULL;
		return 0;
	}

	return 1;
}

/******************************************************************************
Description : Define if the inode is already in the list.  
Parameters  : @inode the one we search for 
Return value: 1 if found, 0 otherwise 
******************************************************************************/
int is_cached_signature(struct inode *inode)
{
	struct digsig_hash_line *l;
	unsigned seq;
	int i, h, found;

	h = hash(inode);
	l = &sig_cache[h];
	do {
		found = 0;
		seq = read_seqbegin(&l->sequence);
		for (i=0; i<ENTRIES_PER_BUCKET && !found; i++)
			if (is_same_inode(&l->entry[i], inode))
				found = 1;
	} while (read_seqretry(&l->sequence, seq));

	return found;
}

/******************************************************************************
Description : remove_signature
Parameters  : @inode to be removed 
Return value: none
******************************************************************************/
void remove_signature(struct inode *inode)
{
	struct digsig_hash_line *l;
	int i, h;

	h = hash(inode);
	l = &sig_cache[h];
	write_seqlock(&l->sequence);
	for (i=0; i<ENTRIES_PER_BUCKET; i++)
		if (is_same_inode(&l->entry[i], inode))
			l->entry[i].inode = 0;
	write_sequnlock(&l->sequence);
}

static inline short inc_evicted(struct digsig_hash_line *l)
{
	short ret = l->next_evicted++;
	if (l->next_evicted == ENTRIES_PER_BUCKET)
		l->next_evicted = 0;
	return ret;
}

/******************************************************************************
Description : 
 * We've validated the signature on inode.  Cache that decision.
 * If the hash bucket is full, we pick the next evicted entry in a round-robin
 * fashion.  Otherwise, we make sure that the next evicted entry will not be
 * the one we just inserted.
Parameters  : 
	@inode: inode whose signature validation to cache
Return value: none
******************************************************************************/
void digsig_cache_signature(struct inode *inode)
{
	struct digsig_hash_line *l;
	int i, h;

	if (!inode)
		panic("digsig:%s:asked to cache null inode\n", __FUNCTION__);

	h = hash(inode);

	l = &sig_cache[h];

	DSM_PRINT(DEBUG_SIGN,
		"%s: adding cache entry at %d\n", __FUNCTION__, h);

	if (!write_tryseqlock(&l->sequence))
		return;

	for (i=0; i<ENTRIES_PER_BUCKET && l->entry[i].inode; i++);


	if (i == ENTRIES_PER_BUCKET)
		i = inc_evicted(l);
	else if (i == l->next_evicted)
		inc_evicted(l);

	l->entry[i].inode = inode;
	l->entry[i].i_ino = inode->i_ino;
	l->entry[i].i_sb = inode->i_sb;
	write_sequnlock(&l->sequence);
}

/******************************************************************************
Description : Initialize caching 
Parameters  : none
Return value: 0 on success, 1 on failure.
******************************************************************************/
int __init digsig_init_caching(void)
{
	int i, j;

	/* dsi_cache_buckets must be a power of two */
	digsig_hash_bits = long_log2(dsi_cache_buckets);
	if (dsi_cache_buckets != (1 << digsig_hash_bits)) {
		digsig_hash_bits++;
		dsi_cache_buckets = 1 << digsig_hash_bits;
		DSM_PRINT (DEBUG_INIT,
				"%s: dsi_cache_buckets set to %d (bits %d)\n",
				__FUNCTION__, dsi_cache_buckets, digsig_hash_bits);
	}

	sig_cache = kmalloc(dsi_cache_buckets * 
			sizeof(struct digsig_hash_line), GFP_KERNEL);


	if (!sig_cache) {
		DSM_PRINT(DEBUG_ERROR, "No memory to initialize digsig cache.\n");
		return 1;
	}

	for (i=0; i<dsi_cache_buckets; i++) {
		seqlock_init(&sig_cache[i].sequence);
		sig_cache[i].next_evicted = 0;
		for (j=0; j<ENTRIES_PER_BUCKET; j++)
			sig_cache[i].entry[j].inode = NULL;
	}

	return 0; 
}

/*
 * Called at digsig unload to clean up
 */
void digsig_cache_cleanup(void)
{
	kfree(sig_cache);
	sig_cache = NULL;
}
