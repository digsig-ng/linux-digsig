/*
 * Distributed Security Module (DSM)
 *
 * This file contains the digsig hook to the kernel.
 * The set of function was defined by the LSM interface.
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: David Gordon Aug 2003 
 * modifs: Makan Pourzandi Sep 2003 - Nov 2003 
 *         Vincent Roy Sep 2003 - Nov 2003, add functionality for mmap  
 *         Serge Hallyn Nov 2003, Jan 2004: add caching of signature validation
 */

#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/kobject.h>
#include "dsi.h"

#ifdef DSI_DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#define DIGSIG_BENCH 1
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#define DIGSIG_BENCH 0
#endif

extern int DSIDebugLevel;

extern int dsi_max_hashed_sigs, dsi_num_hashed_sigs;
extern int g_init;

/*
 * A hash(inode) points into a static array of these structs.  On
 * collisions, we point the next-> to a newly alloced digsig_hash_struct
 */
struct digsig_hash_struct {
	short orig;  /* did this come from the original array, or malloc'ed? */
	short initialized;  /* in use? */
	struct list_head lru;  /* least recently used list of all actives */

	/* If the inode address, inode number, and superblock address
	 * are all the same, we assume it's the same inode */
	struct inode *inode;
	unsigned long i_ino;
	struct super_block *i_sb;

	/*
	 * link collisions in doubly linked list headed at the static
	 * array
	 */
	struct digsig_hash_struct *next;
	struct digsig_hash_struct *prev;  /* only set if dynamically alloced */
};

struct digsig_hash_struct *digsig_hashes = NULL;
static struct list_head digsig_hash_lru;
spinlock_t digsig_hash_lock = SPIN_LOCK_UNLOCKED;

/******************************************************************************
Description : 
haha...  Well, it actually works pretty well.
Parameters  :  @inode to hash
Return value: Return the hash value. 
******************************************************************************/
static inline int
hash(struct inode *inode)
{
	return ((unsigned long)inode) % dsi_max_hashed_sigs;
}

/******************************************************************************
Description : is_same_inode?
Parameters  : 
	@p: a cached signature validation entry
	@inode: an inode
Return value: 1 if the sig entry is for the given inode, 0 otherwise 
******************************************************************************/
static inline int
is_same_inode(struct digsig_hash_struct *p, struct inode *inode)
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
int is_hashed_signature(struct inode *inode)
{
	struct digsig_hash_struct *p;

	if (!g_init)
		return 0;

	if (!dsi_num_hashed_sigs)
		return 0;

	p = &digsig_hashes[hash(inode)];
	while (p && p->initialized && !is_same_inode(p, inode))
		p = p->next;

	if (p && p->initialized && is_same_inode(p, inode)) {
		/* renew sig validation in lru list */
		spin_lock(&digsig_hash_lock);
		list_move_tail(&p->lru, &digsig_hash_lru);
		spin_unlock(&digsig_hash_lock);
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
	struct digsig_hash_struct *p;

	if (!dsi_num_hashed_sigs)
		return;

	spin_lock(&digsig_hash_lock);
	p = &digsig_hashes[hash(inode)];
	while (p && p->initialized && !is_same_inode(p, inode))
		p = p->next;
	if (p && p->initialized && is_same_inode(p, inode)) {
		if (!p->orig) {
			p->prev->next = p->next;
			if (p->next)
				p->next->prev = p->prev;
			list_del(&p->lru);
			kfree(p);
			dsi_num_hashed_sigs--;
			goto out_unlock;
		}
		p->initialized = 0;
		p->next = 0;
		p->inode = NULL;
		list_del_init(&p->lru);
		dsi_num_hashed_sigs--;
	}
out_unlock:
	spin_unlock(&digsig_hash_lock);
}


/******************************************************************************
Description : 
 * del_hashes(num): clear out num hash validations from the end of the
 * lru list.  Must be called with digsig_hash_lock held.  Returns the
 * number actually deleted.
Parameters  : @num: number of cached sig validation entries to clear.
Return value: number of entries actually deleted.
******************************************************************************/
int del_hashes(int num)
{			
	int i=0;
	struct digsig_hash_struct *tmph, *del;

	DSM_PRINT(DEBUG_SIGN,	"del_hashes: num deleted %d\n", num); 

	while (i < dsi_max_hashed_sigs && i<num) {
		i++;
		tmph = list_entry(digsig_hash_lru.next, struct digsig_hash_struct, lru);

		if (!tmph->orig) {

			DSM_PRINT(DEBUG_SIGN,	"del_hashes: deleted tmph->orig=%d\n", (int) tmph->orig); 
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

		  DSM_PRINT(DEBUG_SIGN,	"del_hashes: deleted tmph->next=%d\n", (int) tmph->next); 
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
	dsi_num_hashed_sigs -= i;

	DSM_PRINT(DEBUG_SIGN,	"del_hashes: deleted i=%d\n", i); 
	return i;
}

/******************************************************************************
Description : 
 * Allocate a new digsig_hash_struct.  (We had a hash collision)
 * Called with digsig_hash_lock held.
Parameters  : 
	@inode whose sig validation should be cached
	@next: entry in front of which we're entering the new one.
Return value: the newly allocated entry.
******************************************************************************/
static struct digsig_hash_struct *
alloc_digsig_hash(struct inode *inode, struct digsig_hash_struct *next)
{
	struct digsig_hash_struct *new;

	new = kmalloc(sizeof(struct digsig_hash_struct), GFP_ATOMIC); /* GFP_KERNEL); */ 
	if (!new)
		return ERR_PTR(-ENOMEM);

	memset(new, 0, sizeof(struct digsig_hash_struct));
	new->inode = inode;
	new->i_ino = inode->i_ino;
	new->i_sb = inode->i_sb;
	new->initialized = 1;
	
	if (next) {
		new->next = next;
		next->prev = new;
	}
	
	/* makan debug: it is going to be added to the list in add_signature  
	   list_add_tail(&new->lru, &digsig_hash_lru);
	*/ 
	DSM_PRINT(DEBUG_SIGN,	"alloc_digsig_hash: alloc digsig hash for inode %d\n", (int) inode); 
	return new;
}

/******************************************************************************
Description : 
 * We've validated the signature on inode.  Cache that decision.
 * We only store dsi_max_hashed_sigs decision.  If we're breaking that
 * number, then delete one third of the cached decisions at random.
Parameters  : 
	@inode: inode whose signature validation to cache
Return value: none
******************************************************************************/
void add_signature_hash(struct inode *inode)
{
	int h;
	struct digsig_hash_struct *new;
	
	DSM_PRINT(DEBUG_SIGN,	"add_signature_hash: inode %d hash %d\n", (int) inode, (int) hash(inode) ); 

	if (!inode)
		return;

	spin_lock(&digsig_hash_lock);
	if (dsi_num_hashed_sigs >= dsi_max_hashed_sigs) {
	        if (!del_hashes(4)) {
			DSM_PRINT(DEBUG_SIGN,
				"digsig: unable to clear cache entries\n");
			goto out_unlock;
		}
	}

	h = hash(inode);
	if (!digsig_hashes[h].initialized) {
		/* hash(inode) was an empty slot */
		digsig_hashes[h].inode = inode;
		digsig_hashes[h].i_ino = inode->i_ino;
		digsig_hashes[h].i_sb = inode->i_sb;
		digsig_hashes[h].initialized = 1;
		digsig_hashes[h].next = NULL;
		dsi_num_hashed_sigs++;
		list_add_tail(&digsig_hashes[h].lru, &digsig_hash_lru);
		DSM_PRINT(DEBUG_SIGN,	"add_signature_hash: in !digsig_hashes[h].initialized num hashed sigs %d\n", dsi_num_hashed_sigs); 
		goto out_unlock;
	}

	/* allocate new structure */
	new = alloc_digsig_hash(inode, digsig_hashes[h].next);
	if (IS_ERR(new))
		goto out_unlock;
	digsig_hashes[h].next = new;
	new->prev = &digsig_hashes[h];
	list_add_tail(&new->lru, &digsig_hash_lru);
	dsi_num_hashed_sigs++;
	DSM_PRINT(DEBUG_SIGN,	"add_signature_hash: num hashed sigs %d new %d \n", dsi_num_hashed_sigs, (int) new); 

out_unlock:
	spin_unlock(&digsig_hash_lock);
}

/******************************************************************************
Description : Initialize caching 
Parameters  : none
Return value: 0 on success, 1 on failure.
******************************************************************************/
int dsi_init_caching(void)
{
        int tmp;
        
	digsig_hashes = kmalloc(dsi_max_hashed_sigs * 
				sizeof(struct digsig_hash_struct), GFP_ATOMIC); 
				/* GFP_KERNEL); */ 
	
	if (IS_ERR(digsig_hashes)) {
	  DSM_PRINT(DEBUG_ERROR, "No memory to initialize digsig hash!\n");
		return 1;
	}

	memset(digsig_hashes, 0,
		dsi_max_hashed_sigs * sizeof(struct digsig_hash_struct));

	for (tmp=0; tmp<dsi_max_hashed_sigs; tmp++) {
		digsig_hashes[tmp].orig = 1;
	}

	INIT_LIST_HEAD(&digsig_hash_lru);

	return 0; 

}

/*
 * Called at digsig unload to clean up
 */
void dsi_cache_cleanup(void)
{
	del_hashes(dsi_num_hashed_sigs);
	kfree(digsig_hashes);
}
