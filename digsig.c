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


#include <linux/init.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/personality.h>
#include <linux/elf.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/security.h>
#include <linux/dcache.h>
#include <linux/kobject.h>
#include <linux/mman.h>

#include "dsi_sig_verify.h"
#include "dsi_debug.h"
#include "dsi.h"
#include "dsi_sysfs.h"

#include "gnupg/mpi/mpi.h"
#include "gnupg/cipher/rsa-verify.h"

#ifdef DSI_DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#define DIGSIG_BENCH 1
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#define DIGSIG_BENCH 0
#endif

#ifdef MP_LOW_MEM
#define TAB_SIZE 32
#else
#define TAB_SIZE 256
#endif

extern MPI *dsi_public_key[2]; /* dsi_sig_verify.c */

unsigned long int total_jiffies = 0;

/* Allocate and free functions for each kind of security blob. */
static struct semaphore dsi_digsig_sem;

/* Indicate if module as key or not */
int g_init = 0;

#ifdef DIGSIG_LOG
int DSIDebugLevel = DEBUG_INIT | DEBUG_SIGN  ;
#else
int DSIDebugLevel = DEBUG_INIT;
#endif

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

static struct digsig_hash_struct *digsig_hashes = NULL;
static struct list_head digsig_hash_lru;
static int max_hashed_sigs = 128, num_hashed_sigs = 0;
MODULE_PARM(max_hashed_sigs, "i");
MODULE_PARM_DESC(max_hashed_sigs, "Number of signatures to keep hashed\n");
spinlock_t digsig_hash_lock = SPIN_LOCK_UNLOCKED;


/******************************************************************************
   CACHING
makan: to be moved to a new file: dsi_cache.c?  
******************************************************************************/

/******************************************************************************
Description : 
haha...  Well, it actually works pretty well.
Parameters  : 
Return value: Return the hash value. 
******************************************************************************/
static inline int
hash(struct inode *inode)
{
	return ((unsigned long)inode) % max_hashed_sigs;
}

/******************************************************************************
Description : is_same_inode?
Parameters  : 
Return value: 1 if the same node, 0 otherwise 
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
static int
is_hashed_signature(struct inode *inode)
{
	struct digsig_hash_struct *p;

	if (!num_hashed_sigs)
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
Return value: 
******************************************************************************/
static void
remove_signature(struct inode *inode)
{
	struct digsig_hash_struct *p;

	if (!num_hashed_sigs)
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
			num_hashed_sigs--;
			goto out_unlock;
		}
		p->initialized = 0;
		p->next = 0;
		p->inode = NULL;
		list_del_init(&p->lru);
		num_hashed_sigs--;
	}
out_unlock:
	spin_unlock(&digsig_hash_lock);
}


/******************************************************************************
Description : 
 * del_hashes(num): clear out num hash validations from the end of the
 * lru list.  Must be called with digsig_hash_lock held.  Returns the
 * number actually deleted.
Parameters  : 
Return value: 
******************************************************************************/
static int
del_hashes(int num)
{
	int i=0;
	struct digsig_hash_struct *tmph, *del;

	while (i < max_hashed_sigs && i<num) {
		i++;
		tmph = list_entry(digsig_hash_lru.next, struct digsig_hash_struct, lru);

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
			tmph->next = tmph->next->next;
			if (tmph->next)
				tmph->next->prev = tmph;
			list_del(&del->lru);
			kfree(del);
			continue;
		}
		tmph->initialized = 0;
		tmph->next = 0;
		tmph->inode = NULL;
		list_del_init(&tmph->lru);
	}
	num_hashed_sigs -= i;
	return i;
}

/******************************************************************************
Description : 
 * Allocate a new digsig_hash_struct.  (We had a hash collision)
 * Called with digsig_hash_lock held.
Parameters  : 
Return value: 
******************************************************************************/
static struct digsig_hash_struct *
alloc_digsig_hash(struct inode *inode, struct digsig_hash_struct *next)
{
	struct digsig_hash_struct *new;

	new = kmalloc(sizeof(struct digsig_hash_struct), GFP_KERNEL);
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
	list_add_tail(&new->lru, &digsig_hash_lru);

	return new;
}

/******************************************************************************
Description : 
 * We've validated the signature on inode.  Cache that decision.
 * We only store max_hashed_sigs decision.  If we're breaking that
 * number, then delete one third of the cached decisions at random.
Parameters  : 
Return value: 
******************************************************************************/
static void
add_signature_hash(struct inode *inode)
{
	int h;
	struct digsig_hash_struct *new;

	if (!inode)
		return;

	spin_lock(&digsig_hash_lock);
	if (num_hashed_sigs >= max_hashed_sigs) {
	  /* if (!del_hashes(num_hashed_sigs/3 + 1)) { */ 
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
		num_hashed_sigs++;
		list_add_tail(&digsig_hashes[h].lru, &digsig_hash_lru);
		goto out_unlock;
	}

	/* allocate new structure */
	new = alloc_digsig_hash(inode, digsig_hashes[h].next);
	if (IS_ERR(new))
		goto out_unlock;
	digsig_hashes[h].next = new;
	new->prev = &digsig_hashes[h];
	list_add_tail(&new->lru, &digsig_hash_lru);
	num_hashed_sigs++;

out_unlock:
	spin_unlock(&digsig_hash_lock);
}

/******************************************************************************
Description : Initialize caching 
Parameters  : 
Return value: 
******************************************************************************/
static int 
init_caching(void){

        int tmp;
        
	digsig_hashes = kmalloc(max_hashed_sigs * 
			sizeof(struct digsig_hash_struct),
			GFP_KERNEL);
	
	if (IS_ERR(digsig_hashes)) {
	  DSM_PRINT(DEBUG_ERROR, "No memory to initialize digsig hash!\n");
		return 1;
	}

	memset(digsig_hashes, 0,
		max_hashed_sigs * sizeof(struct digsig_hash_struct));

	for (tmp=0; tmp<max_hashed_sigs; tmp++) {
		digsig_hashes[tmp].orig = 1;
	}

	INIT_LIST_HEAD(&digsig_hash_lru);

	return 0; 

}

/******************************************************************************
Description : 
 * Check for an attempt to write an executable for which a signature
 * validation was cached.
 *
 * We the write to happen and check the signature when loading to
 * decide about the validity of the action.  Not because the hacker
 * can modify the file that he could compromise the system.  Because,
 * the new library needs to have a valid signature (i.e. the admin
 * must use the right private key to sign his library) to get loaded.
Parameters  : 
Return value: 
******************************************************************************/
static int
dsi_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
/* 	if (mask & MAY_WRITE) */
/* 		if (is_hashed_signature(inode)) */
/* 			return -EPERM; */


  if (mask & MAY_WRITE)
    if (is_hashed_signature(inode))
      remove_signature(inode);

  return 0;
}

/******************************************************************************
Description : 
 * If an inode is unlinked, we don't want to hang onto it's
 * signature validation ticket
Parameters  : 
Return value: 
******************************************************************************/
static int
dsi_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if (!is_hashed_signature(dentry->d_inode))
		return 0;

	remove_signature(dentry->d_inode);
	return 0;
}

struct security_operations dsi_security_ops;

#define set_dsi_ops(ops, function)				\
		if (!ops->function) {				\
			ops->function = dsi_##function;		\
                }

static char *dsi_find_signature(struct elfhdr *elf_ex,
				Elf32_Shdr * elf_shdata,
				struct file *file, int *sh_offset);

static int
dsi_verify_signature(Elf32_Shdr * elf_shdata,
		     char *sig_orig, struct file *file, int sh_offset);


/******************************************************************************
Description : find signature section in elf binary
              caller is responsible for deallocating memory of buffer returned
Parameters  : 
   elf_ex  is elf header
   elf_shdata is all entries in section header table of elf
   file contains file handle of binary
   sh_offset is offset of signature section in elf. sh_offset is set to offset 
      of signature section in elf
Return value: Upon suscess: buffer containing signature (size of signature is fixed 
              depending on algorithm used)
              Failure: null pointer 
******************************************************************************/
static char *dsi_find_signature(struct elfhdr *elf_ex,
				Elf32_Shdr * elf_shdata, struct file *file,
				int *sh_offset)
{
	int i = 0;
	int retval;
	char *buffer = NULL;

	i = 0;


	while (i < elf_ex->e_shnum
	       && elf_shdata[i].sh_type != DSI_ELF_SIG_SECTION) {
		i++;
	}

	if (elf_shdata[i].sh_type == DSI_ELF_SIG_SECTION) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_find_signature: Found signature section\n");

		/* Now get DSI_ELF_SIG_SIZE bytes of signature section */

		if (elf_shdata[i].sh_size != DSI_ELF_SIG_SIZE) {
			DSM_PRINT(DEBUG_SIGN,
				  "dsi_find_signature: Signature section is not %u bytes\n",
				  DSI_ELF_SIG_SECTION);
			return NULL;
		}

		buffer = (char *) kmalloc(DSI_ELF_SIG_SIZE, DSI_SAFE_ALLOC);
		if (!buffer) {
			DSM_ERROR ("kmalloc failed in dsi_find_signature for buffer.\n");
			return NULL;
		}

		retval = kernel_read(file, elf_shdata[i].sh_offset,
				     (char *) buffer, DSI_ELF_SIG_SIZE);
		if ((retval < 0) || (retval != DSI_ELF_SIG_SIZE)) {
			DSM_PRINT(DEBUG_SIGN,
				  "dsi_find_signature: Unable to read signature: %d\n",
				  retval);
			kfree(buffer);
			return NULL;
		}

		*sh_offset = elf_shdata[i].sh_offset;
	}

	return buffer;
}

/******************************************************************************
Description : verify if signature matches binary's signature
Parameters  : 
   filename of elf executable
   elf_shdata is the data of the signature section
   sig_orig is the original signature of the binary
   file is the file handle of the binary
   sh_offset is offset of signature section in elf
Return value: 0 for false or 1 for true or -1 for error
******************************************************************************/
static int
dsi_verify_signature(Elf32_Shdr * elf_shdata,
		     char *sig_orig, struct file *file, int sh_offset)
{
	char *sig_result, *read_blocks;
	int retval, offset;
	unsigned int size;
	unsigned int lower, upper;
	SIGCTX *ctx;

	down (&dsi_digsig_sem);
	if ((ctx = dsi_sign_verify_init(HASH_SHA1, SIGN_RSA)) == NULL) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_verify_signature Cannot allocate crypto context.\n");
		up (&dsi_digsig_sem);
		return -ENOMEM;
	}

	sig_result = (char *) kmalloc(DSI_ELF_SIG_SIZE, DSI_SAFE_ALLOC);
	read_blocks = (char *) kmalloc(DSI_ELF_READ_BLOCK_SIZE, DSI_SAFE_ALLOC);
	if (!sig_result) {
		DSM_ERROR ("kmalloc failed in dsi_verify_signature for sig_result.\n");
		up (&dsi_digsig_sem);
		return -ENOMEM;
	}
	if (!read_blocks) {
		DSM_ERROR ("kmalloc failed in dsi_verify_signature for read_block.\n");
		up (&dsi_digsig_sem);
		return -ENOMEM;
	}

	memset(sig_result, 0, DSI_ELF_SIG_SIZE);

	for (offset = 0; offset < file->f_dentry->d_inode->i_size;
	     offset += DSI_ELF_READ_BLOCK_SIZE) {

		size = kernel_read(file, offset, (char *) read_blocks,
				   DSI_ELF_READ_BLOCK_SIZE);
		if (size <= 0) {
			DSM_PRINT(DEBUG_SIGN,
				  "dsi_verify_signature: Unable to read signature in blocks: %d\n",
				  size);
			kfree(sig_result);
			kfree(read_blocks);
			up (&dsi_digsig_sem);
			return -1;
		}

		/* Makan: This is in order to avoid building a buffer
		   inside the kernel. At each read we check to be sure
		   that the parts of the signature read are set to 0 */ 
		/* Must zero out signature section to match bsign mechanism */
		lower = sh_offset;	/* lower bound of memset */
		upper = sh_offset + DSI_ELF_SIG_SIZE;	/* upper bound */

		if ((lower < offset + DSI_ELF_READ_BLOCK_SIZE) &&
		    (offset < upper)) {
			lower = (offset > lower) ? offset : lower;
			upper =	(offset + DSI_ELF_READ_BLOCK_SIZE <
				 upper) ? offset +
				DSI_ELF_READ_BLOCK_SIZE : upper;

			memset(read_blocks + (lower - offset), 0,
			       upper - lower);
		}

		/* continue verification loop */
		if (dsi_sign_verify_update(ctx, read_blocks, size) != 0) {
			DSM_PRINT(DEBUG_SIGN,
				  "dsi_verify_signature Error updating crypto verification\n");
			kfree(sig_result);
			kfree(read_blocks);
			up (&dsi_digsig_sem);
			return -1;
		}
	}

	/* A bit of bsign formatting else hashes won't match, works with bsign v0.4.4 */
	if ((retval = dsi_sign_verify_final(ctx, sig_result, DSI_ELF_SIG_SIZE,
					    sig_orig + DSI_BSIGN_INFOS)) < 0) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_verify_signature Error calculating final crypto verification\n");
		kfree(sig_result);
		kfree(read_blocks);
		up (&dsi_digsig_sem);
		return -1;
	}

	kfree(sig_result);
	kfree(read_blocks);
	up (&dsi_digsig_sem);
	return retval;
}
#ifndef DSI_EXEC_ONLY
int dsi_file_mmap(struct file * file, unsigned long prot, unsigned long flags)
{
	struct elfhdr elf_ex;
	int retval, sh_offset;
	unsigned int size;
	Elf32_Shdr *elf_shdata;
	char *sig_orig;
	long exec_time = 0;
	char *buf;

	if (!file)
		return 0;

	/*
	 * Sorry, if anyone is doing a shared exec mmapping of a signed
	 * binary, the executable could be changed right under them.
	 * That's no good!
	 */
	if (prot & PROT_WRITE)
		if ((flags & MAP_TYPE) == MAP_SHARED)
			return -EPERM;

	if (!(prot & VM_EXEC))
		return 0;
	if (!file->f_dentry)
		return 0;
	if (!file->f_dentry->d_name.name)
		return 0;

	if (!g_init)
		return 0;

	buf = kmalloc (BINPRM_BUF_SIZE, DSI_SAFE_ALLOC);
	if (!buf) {
		DSM_ERROR ("kmalloc failed in dsi_file_mmap for buf\n");
		return 0;
	}

	if (DIGSIG_BENCH)	/* measure exec time only on DEBUG mode. */
		exec_time = jiffies;

	DSM_PRINT(DEBUG_SIGN, "binary is %s\n", file->f_dentry->d_name.name);

	if (is_hashed_signature(file->f_dentry->d_inode)) {
		DSM_PRINT(DEBUG_SIGN, "Binary %s had a hashed signature validation.\n", file->f_dentry->d_name.name);
		retval = 0;
		goto out_file;
	}

	/* Get the exec-header, the original bprm->buf is no longer reliable at this point */
	kernel_read(file, 0, buf, BINPRM_BUF_SIZE);
	elf_ex = *((struct elfhdr *) buf);

	if (memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_file_mmap: Binary is not elf format\n");
		retval = 0;
		/* ToDO: Makan, we decide to let go the not elf binaries.
		   ?? This is not obvious, we cannot sign a non-elf binary, should
		   we only check elf files and not execute the non-elf
		   binaries???? */
		goto out_file;
	}

	if (elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) {
		DSM_PRINT(DEBUG_SIGN, "dsi_file_mmap: Binary is not executable\n");
		retval = 0;	/* ToDO: Makan, we decide to let go the not executable binaries. */
		goto out_file;
	}

	/* Now read in all of the section header entries */
	if (!elf_ex.e_shoff) {
		DSM_ERROR("dsi_file_mmap: No section header!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	if (elf_ex.e_shentsize != sizeof(Elf32_Shdr)) {
		DSM_ERROR ("dsi_file_mmap: Section header is wrong size!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	if (elf_ex.e_shnum > 65536U / sizeof(Elf32_Shdr)) {
		DSM_ERROR ("dsi_file_mmap: Too many entries in Section Header!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	size = elf_ex.e_shnum * sizeof(Elf32_Shdr);

	elf_shdata = (Elf32_Shdr *) kmalloc(size, DSI_SAFE_ALLOC);
	if (!elf_shdata) {
		DSM_ERROR ("dsi_file_mmap: Cannot allocate memory to read Section Header\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	retval = kernel_read (file, elf_ex.e_shoff, (char *) elf_shdata, size);

	if (retval < 0 || retval != size) {
		DSM_ERROR ("dsi_file_mmap: Unable to read binary %s: %d\n",
			   file->f_dentry->d_name.name, retval);
		kfree (elf_shdata);
		retval = DIGSIG_MODE;
		goto out_file;
	}

	/* Find signature section */
	if ((sig_orig = dsi_find_signature (&elf_ex, elf_shdata, file,
					    &sh_offset)) == NULL) {
		retval = DIGSIG_MODE;
		DSM_PRINT(DEBUG_SIGN,"dsi_file_mmap: Signature not found for the binary: %s !\n", 
			  file->f_dentry->d_name.name);
		goto out_file;
	}

	/* Verify binary's signature */
	retval = dsi_verify_signature (elf_shdata, sig_orig, file, sh_offset);

	if (!retval) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_file_mmap: Signature verification successful\n");
		add_signature_hash(file->f_dentry->d_inode);
	} else if (retval > 0) {
		DSM_ERROR("dsi_file_mmap: Signature do not match for %s\n", file->f_dentry->d_name.name);
		retval = -EPERM;
	} else {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_file_mmap: Signature verification failed because of errors: %d for %s\n",
			  retval, file->f_dentry->d_name.name);
		retval = -EPERM;
	}

	kfree(sig_orig);

 out_file:
	if (DIGSIG_BENCH) {	/* measure exec time only on DEBUG mode. */
		exec_time = jiffies - exec_time;
		total_jiffies += exec_time;
		DSM_PRINT(DEBUG_TIME, "Time to execute dsi_file_mmap on %s is %li\n", file->f_dentry->d_name.name, exec_time);
	}
	kfree (buf);
	return retval;

}
#endif /* DSI_EXEC_ONLY for dsi_file_mmap */
/******************************************************************************
Description :
We don't have to check if file is regular, exists, or is zero
size. This hook follows many tests concerning this. However, since we
only support ELF files, we need a simple check to make sure the file
is an ELF. Remember, this hook is called after the kernel fct
search_binary_handlers which in itself does extensive verification of
the binary to determine its format.

We do not need to verify ELF header, since it has been done in
load_elf_binary(). We must determine if this is an ELF, because this
hook might be called for other binary formats. We *do* need to verify
the ELF's integrity, because only header integrity is checked by
kernel.

We need to open file, bprm->file handle is not reliable at this point.

Careful!!! endian type is platform dependent, big endian is assumed for i386

Parameters  : 
Return value: 
******************************************************************************/
#ifdef DSI_EXEC_ONLY
int dsi_file_mmap(struct file * file, unsigned long prot, unsigned long flags)
{
	/*
	 * Sorry, if anyone is doing a shared exec mmapping of a signed
	 * binary, the executable could be changed right under them.
	 * That's no good!
	 */
	if (prot & PROT_WRITE)
		if ((flags & MAP_TYPE) == MAP_SHARED)
			return -EPERM;

	return 0;
}

int dsi_bprm_check_security(struct linux_binprm *bprm)
{
	struct elfhdr elf_ex;
	int retval, sh_offset;
	unsigned int size;
	Elf32_Shdr *elf_shdata;
	struct file *file;
	char *sig_orig;
	long exec_time = 0;

	if (!g_init)
		return 0;

	if (DIGSIG_BENCH)	/* measure exec time only on DEBUG mode. */
		exec_time = jiffies;

	DSM_PRINT(DEBUG_SIGN, "binary is %s\n", bprm->filename);

	file = filp_open(bprm->filename, O_RDONLY, 0);
	if (!file && IS_ERR(file)) {
		DSM_ERROR ("dsi_bprm_check_security: Problem opening file %s!\n", bprm->filename);
		retval = DIGSIG_MODE;
		goto out_file;
	}

	if (is_hashed_signature(file->f_dentry->d_inode)) {
		DSM_PRINT(DEBUG_SIGN, "Binary %s had a hashed signature validation.\n", bprm->filename);
		retval = 0;
		goto out_file;
	}

	if (!file->f_op || !file->f_op->mmap) {
		DSM_ERROR ("dsi_bprm_compute_creds: Not allowed to read file %s\n", bprm->filename);
		retval = DIGSIG_MODE;
		goto out_file;
	}

	/* Get the exec-header, the original bprm->buf is no longer reliable at this point */
	kernel_read(file, 0, bprm->buf, BINPRM_BUF_SIZE);
	elf_ex = *((struct elfhdr *) bprm->buf);

	if (memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_bprm_compute_creds: Binary is not elf format\n");
		retval = 0;
		/* ToDO: Makan, we decide to let go the not elf binaries.
		   ?? This is not obvious, we cannot sign a non-elf binary, should
		   we only check elf files and not execute the non-elf
		   binaries???? */
		goto out_file;
	}

	if (elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) {
		DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds: Binary is not executable\n");
		retval = 0;	/* ToDO: Makan, we decide to let go the not executable binaries. */
		goto out_file;
	}

	/* Now read in all of the section header entries */
	if (!elf_ex.e_shoff) {
		DSM_ERROR("dsi_bprm_compute_creds: No section header!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	if (elf_ex.e_shentsize != sizeof(Elf32_Shdr)) {
		DSM_ERROR ("dsi_bprm_compute_creds: Section header is wrong size!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	if (elf_ex.e_shnum > 65536U / sizeof(Elf32_Shdr)) {
		DSM_ERROR ("dsi_bprm_compute_creds: Too many entries in Section Header!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	size = elf_ex.e_shnum * sizeof(Elf32_Shdr);

	elf_shdata = (Elf32_Shdr *) kmalloc(size, DSI_SAFE_ALLOC);
	if (!elf_shdata) {
		DSM_ERROR ("dsi_bprm_compute_creds: Cannot allocate memory to read Section Header\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	retval = kernel_read(file, elf_ex.e_shoff, (char *) elf_shdata, size);

	if (retval < 0 || retval != size) {
		DSM_ERROR ("dsi_bprm_compute_creds: Unable to read binary %s: %d\n",
			   bprm->filename, retval);
		kfree(elf_shdata);
		retval = DIGSIG_MODE;
		goto out_file;
	}

	/* Find signature section */
	if ((sig_orig = dsi_find_signature(&elf_ex, elf_shdata, file,
					   &sh_offset)) == NULL) {
		retval = DIGSIG_MODE;
		goto out_file;
	}

	/* Verify binary's signature */
	retval = dsi_verify_signature (elf_shdata, sig_orig, file, sh_offset);

	if (!retval) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_bprm_compute_creds: Signature verification successful for %s\n", bprm->filename);
		add_signature_hash(file->f_dentry->d_inode);
	} else if (retval > 0) {
		DSM_ERROR("dsi_bprm_compute_creds: Signature do not match for %s\n", bprm->filename);
		retval = -EPERM;
	} else {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_bprm_compute_creds: Signature verification failed because of errors: %d for %s\n",
			  retval, bprm->filename);
		retval = -EPERM;
	}

	kfree(sig_orig);

 out_file:
	filp_close(file, 0);

	if (DIGSIG_BENCH) {	/* measure exec time only on DEBUG mode. */
		exec_time = jiffies - exec_time;
		total_jiffies += exec_time;
		DSM_PRINT(DEBUG_TIME, "Time to execute dsi_bprm_check_security on %s is %li\n", bprm->filename, exec_time);
	}
	return retval;
}
#endif /* DSI_EXEC_ONLY for dsi_bprm_check_security */

void security_set_operations(struct security_operations *ops)
{
	set_dsi_ops (ops, file_mmap);
#ifdef DSI_EXEC_ONLY
	set_dsi_ops(ops, bprm_check_security);
#endif
	set_dsi_ops(ops, inode_permission);
	set_dsi_ops(ops, inode_unlink);

}

char digsig_file_name[] = "digsig_interface";
static struct attribute digsig_attribute = {
	.name = digsig_file_name,
	.mode = S_IRUSR | S_IWUSR
};
static struct sysfs_ops digsig_sysfs_ops = {
	.show = digsig_show,
	.store = digsig_store
};
static struct kobj_type digsig_kobj_type = {
	.sysfs_ops = &digsig_sysfs_ops,
};
static struct kobject digsig_kobject = {
	.name = "digsig",
	.ktype = &digsig_kobj_type
};


static int __init digsig_init_module(void)
{
	int err = 0;
	int tmp; 

	DSM_PRINT(DEBUG_INIT, "Initializing module\n");

	/* initialize caching mechanisms */ 

	if (init_caching()){
	  return -ENOMEM;
	}

	/* initialize DSI's hooks */
	security_set_operations(&dsi_security_ops);

	/* register */
	if ((err = register_security(&dsi_security_ops))) {
		DSM_ERROR ("< dsi_init_module():Wrong security parameter\n");
		return err;
	}

	init_MUTEX (&dsi_digsig_sem);

	if (kobject_register (&digsig_kobject) != 0) {
		DSM_ERROR ("Digsig key failed to register properly\n");
		return -1;
	}
	if ((tmp = sysfs_create_file (&digsig_kobject, &digsig_attribute)) != 0) {
		DSM_ERROR ("Create file failed\n");
		return -1;
	}
	return 0;
}

static void __exit digsig_exit_module(void)
{
	DSM_PRINT(DEBUG_INIT, "Deinitializing module\n");
	dsi_sign_verify_free();
	unregister_security(&dsi_security_ops);
	del_hashes(num_hashed_sigs);
	kfree(digsig_hashes);
	sysfs_remove_file (&digsig_kobject, &digsig_attribute);
	kobject_unregister (&digsig_kobject);
}

module_init(digsig_init_module);
module_exit(digsig_exit_module);

/* see linux/module.h */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Distributed Security Infrastructure Module");
MODULE_AUTHOR("DSI Team sourceforge.net/projects/disec");
MODULE_SUPPORTED_DEVICE("DSI_module");
