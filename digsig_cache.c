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

#ifdef DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#define DIGSIG_BENCH 1
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#define DIGSIG_BENCH 0
#endif

extern int digsig_max_cached_sigs;
/* Number of signature validations cached so far */
static int digsig_num_cached_sigs;

/*
 * digsig_hash_table:
 * A hash table to implement caching of validated signatures.  When the
 * signature on an ELF file has been validated, the inode and superblock
 * are added to this cache.  Future loads of the file will not need to be
 * revalidated unless the file has been written to.
 *
 * We create an array of digsig_max_cached_sigs such structs.  On
 * collisions, we simply allocate a new struct, and point existing
 * entry's ->next to the newly allocated struct.  This means we may
 * end up with more than digsig_max_cached_sigs structs allocated.  (But
 * we will only use digsig_max_cached_sigs of them).
 */
struct digsig_hash_table {
	short orig;  /* did this come from the original array, or malloc'ed? */
	short initialized;  /* in use? */
	struct list_head lru;  /* least recently used list of all actives */

	/* If the inode address, inode number, and superblock address
	 * are all the same, we assume it's the same inode.  Using i_ino
	 * as well just in case the inode struct was quickly re-used. */
	struct inode *inode;
	unsigned long i_ino;
	struct super_block *i_sb;

	/*
	 * link collisions in doubly linked list headed at the static
	 * array
	 */
	struct digsig_hash_table *next;
	struct digsig_hash_table *prev;  /* only set if dynamically alloced */
};

static struct digsig_hash_table *sig_cache;
static LIST_HEAD(sig_cache_lru);
static spinlock_t sig_cache_spinlock = SPIN_LOCK_UNLOCKED;

/******************************************************************************
Description : 
haha...  Well, it actually works pretty well.
Parameters  :  @inode to hash
Return value: Return the hash value. 
******************************************************************************/
static inline int
hash(struct inode *inode)
{
	return ((unsigned long)inode) % digsig_max_cached_sigs;
}

/******************************************************************************
Description : is_same_inode?
Parameters  : 
	@p: a cached signature validation entry
	@inode: an inode
Return value: 1 if the sig entry is for the given inode, 0 otherwise 
******************************************************************************/
static inline int
is_same_inode(struct digsig_hash_table *p, struct inode *inode)
{
	if (p->inode != inode)
		return 0;
	if (p->i_ino != inode->i_ino || p->i_sb != inode->i_sb)
		return 0;

	return 1;
}

/******************************************************************************
Description : Define if the inode is already in the list.  
Parameters  : @inode the one we search for 
Return value: 1 if found, 0 otherwise 
******************************************************************************/
int is_cached_signature(struct inode *inode)
{
	struct digsig_hash_table *p;

	if (!digsig_num_cached_sigs)
		return 0;

	p = &sig_cache[hash(inode)];
	while (p && p->initialized && !is_same_inode(p, inode))
		p = p->next;

	if (p && p->initialized && is_same_inode(p, inode)) {
		/* renew sig validation in lru list */
		spin_lock(&sig_cache_spinlock);
		list_move_tail(&p->lru, &sig_cache_lru);
		spin_unlock(&sig_cache_spinlock);
		return 1;
	}

	return 0;
}

/******************************************************************************
Description : remove_signature
Parameters  : @inode to be removed 
Return value: none
******************************************************************************/
void remove_signature(struct inode *inode)
{
	struct digsig_hash_table *p;

	if (!digsig_num_cached_sigs)
		return;

	spin_lock(&sig_cache_spinlock);
	p = &sig_cache[hash(inode)];
	while (p && p->initialized && !is_same_inode(p, inode))
		p = p->next;
	if (p && p->initialized && is_same_inode(p, inode)) {
		if (!p->orig) {
			p->prev->next = p->next;
			if (p->next)
				p->next->prev = p->prev;
			list_del(&p->lru);
			kfree(p);
			digsig_num_cached_sigs--;
			goto out_unlock;
		}
		p->initialized = 0;
		p->next = 0;
		p->inode = NULL;
		list_del_init(&p->lru);
		digsig_num_cached_sigs--;
	}
out_unlock:
	spin_unlock(&sig_cache_spinlock);
}


/******************************************************************************
Description : 
 * digsig_purge_cache(num): clear out num sig validations from the end of the
 * lru list.  Must be called with sig_cache_spinlock held.  Returns the
 * number actually deleted.
Parameters  : @num: number of cached sig validation entries to clear.
Return value: number of entries actually deleted.
******************************************************************************/
static int digsig_purge_cache(int num)
{			
	int i=0;
	struct digsig_hash_table *tmph, *del;

	while (i < digsig_max_cached_sigs && i<num) {
		i++;
		tmph = list_entry(sig_cache_lru.next,
				struct digsig_hash_table, lru);

		if (!tmph->orig) {
			tmph->prev->next = tmph->next;
			if (tmph->next)
				tmph->next->prev = tmph->prev;
			list_del(&tmph->lru);

			kfree(tmph);
			continue;
		}

		/* this came off the original array */
		if (tmph->next) {
			/* It has a next->, so we delete that one */
			del = tmph->next;
			tmph->inode = del->inode;

			tmph->next = del->next; 

			if (del->next)
				del->next->prev = tmph; 

			list_del(&del->lru);

			kfree(del);
			continue;
		}
		tmph->initialized = 0;
		tmph->next = 0;
		tmph->inode = NULL;
		list_del_init(&tmph->lru);
	}
	digsig_num_cached_sigs -= i;

	return i;
}

/******************************************************************************
Description : 
 * Allocate a new digsig_hash_table.  (We had a hash collision)
 * Called with sig_cache_spinlock held.
Parameters  : 
	@inode whose sig validation should be cached
	@next: entry in front of which we're entering the new one.
Return value: the newly allocated entry.
******************************************************************************/
static struct digsig_hash_table *
alloc_digsig_hash(struct inode *inode, struct digsig_hash_table *next)
{
	struct digsig_hash_table *new;

	new = kmalloc(sizeof(struct digsig_hash_table), GFP_ATOMIC);
	if (!new)
		return ERR_PTR(-ENOMEM);

	memset(new, 0, sizeof(struct digsig_hash_table));
	new->inode = inode;
	new->i_ino = inode->i_ino;
	new->i_sb = inode->i_sb;
	new->initialized = 1;
	
	if (next) {
		new->next = next;
		next->prev = new;
	}
	
	return new;
}

/******************************************************************************
Description : 
 * We've validated the signature on inode.  Cache that decision.
 * We only store digsig_max_cached_sigs decision.  If we're breaking that
 * number, then delete one third of the cached decisions at random.
Parameters  : 
	@inode: inode whose signature validation to cache
Return value: none
******************************************************************************/
void digsig_cache_signature(struct inode *inode)
{
	int h;
	struct digsig_hash_table *new;
	
	if (!inode)
		return;

	spin_lock(&sig_cache_spinlock);
	if (digsig_num_cached_sigs >= digsig_max_cached_sigs) {
	        if (!digsig_purge_cache(4)) {
			DSM_PRINT(DEBUG_SIGN,
				"%s: unable to clear cache entries\n",
				__FUNCTION__);
			goto out_unlock;
		}
	}

	h = hash(inode);
	if (!sig_cache[h].initialized) {
		/* hash(inode) was an empty slot */
		sig_cache[h].inode = inode;
		sig_cache[h].i_ino = inode->i_ino;
		sig_cache[h].i_sb = inode->i_sb;
		sig_cache[h].initialized = 1;
		sig_cache[h].next = NULL;
		digsig_num_cached_sigs++;
		list_add_tail(&sig_cache[h].lru, &sig_cache_lru);
		goto out_unlock;
	}

	/* allocate new structure */
	new = alloc_digsig_hash(inode, sig_cache[h].next);
	if (IS_ERR(new))
		goto out_unlock;
	sig_cache[h].next = new;
	new->prev = &sig_cache[h];
	list_add_tail(&new->lru, &sig_cache_lru);
	digsig_num_cached_sigs++;

out_unlock:
	spin_unlock(&sig_cache_spinlock);
}

/******************************************************************************
Description : Initialize caching 
Parameters  : none
Return value: 0 on success, 1 on failure.
******************************************************************************/
int __init digsig_init_caching(void)
{
        int tmp;
        
	sig_cache = kmalloc(digsig_max_cached_sigs * 
				sizeof(struct digsig_hash_table), GFP_ATOMIC); 
				/* GFP_KERNEL); */ 
	
	if (!sig_cache) {
	  DSM_PRINT(DEBUG_ERROR, "No memory to initialize digsig cache.\n");
		return 1;
	}

	memset(sig_cache, 0,
		digsig_max_cached_sigs * sizeof(struct digsig_hash_table));

	for (tmp=0; tmp<digsig_max_cached_sigs; tmp++) {
		sig_cache[tmp].orig = 1;
	}

	return 0; 
}

/*
 * Called at digsig unload to clean up
 */
void digsig_cache_cleanup(void)
{
	digsig_purge_cache(digsig_num_cached_sigs);
	kfree(sig_cache);
}
