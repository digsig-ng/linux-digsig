/*
 * Digital Signature (DigSig)
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
 * modifs: Makan Pourzandi Nov 2003 - Sept 2004: fixes - Feb 2005: bug fix 
 *         Vincent Roy  Nov 2003: add functionality for mmap  
 *         Serge Hallyn Jan 2004: add caching of signature validation
 *         Chris Wright Sept 2004: many fixes 
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
#include "digsig_cache.h"
#include "digsig_revocation.h"

#include "gnupg/mpi/mpi.h"
#include "gnupg/cipher/rsa-verify.h"

#ifdef DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#define DIGSIG_BENCH 1
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#define DIGSIG_BENCH 0
#endif

#define get_inode_security(ino) ((unsigned long)(ino->i_security))
#define set_inode_security(ino,val) (ino->i_security = (void *)val)

#define get_file_security(file) ((unsigned long)(file->f_security))
#define set_file_security(file,val) (file->f_security = (void *)val)

unsigned long int total_jiffies = 0;

/* Allocate and free functions for each kind of security blob. */
static DECLARE_MUTEX(digsig_sem);

/* Indicate if module as key or not */
int g_init = 0;

/* Keep track of how we are registered */
static int secondary;

#ifdef DIGSIG_LOG
int DigsigDebugLevel = DEBUG_INIT | DEBUG_SIGN;
#else
int DigsigDebugLevel = DEBUG_INIT;
#endif

int dsi_cache_buckets = 128;
module_param(dsi_cache_buckets, int, 0);
MODULE_PARM_DESC(dsi_cache_buckets, "Number of cache buckets for signatures validations.\n");


/******************************************************************************
Description : 
 * For a file being opened for write, check:
 * 1. whether it is a library currently being dlopen'ed.  If it is, then
 *    inode->i_security > 0.
 * 2. whether the file being opened is an executable or library with a
 *    cached signature validation.  If it is, remove the signature validation
 *    entry so that on the next load, the signature will be recomputed.
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
digsig_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	if (!g_init)
		return 0;

	if (inode && mask & MAY_WRITE) {
		unsigned long isec = get_inode_security(inode);
		if (isec > 0)
			return -EPERM;
		if (is_cached_signature(inode))
			remove_signature(inode);
	}

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
digsig_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if (!g_init)
		return 0;

	if (!is_cached_signature(dentry->d_inode))
		return 0;

	remove_signature(dentry->d_inode);
	return 0;
}

static char *digsig_read_signature(struct file *file, unsigned long offset)
{
	int retval;
	char *buffer = kmalloc(DIGSIG_ELF_SIG_SIZE, DIGSIG_SAFE_ALLOC);

	if (!buffer) {
		DSM_ERROR ("kmalloc failed in %s for buffer.\n", __FUNCTION__);
		return NULL;
	}
	retval = kernel_read(file, offset, (char *) buffer,
					 DIGSIG_ELF_SIG_SIZE);
	if (retval != DIGSIG_ELF_SIG_SIZE) {
		DSM_PRINT(DEBUG_SIGN, "%s: Unable to read signature: %d\n",
			  __FUNCTION__, retval);
		kfree(buffer);
		buffer = NULL;
	}

	return buffer;
}

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
static char *digsig_find_signature32(struct elf32_hdr *elf_ex,
				Elf32_Shdr * elf_shdata, struct file *file,
				unsigned long *sh_offset)
{
	int i = 0;
	char *buffer;

	while (i < elf_ex->e_shnum
	       && elf_shdata[i].sh_type != DIGSIG_ELF_SIG_SECTION) {
		i++;
	}

	if (i == elf_ex->e_shnum)
		return NULL;
	if (elf_shdata[i].sh_type != DIGSIG_ELF_SIG_SECTION)
		return NULL;
	if (elf_shdata[i].sh_size != DIGSIG_ELF_SIG_SIZE)
		return NULL;

	buffer = digsig_read_signature(file, elf_shdata[i].sh_offset);
	if (!buffer)
		return NULL;

	*sh_offset = elf_shdata[i].sh_offset;

	return buffer;
}

static char *digsig_find_signature64(struct elf64_hdr *elf_ex,
				Elf64_Shdr * elf_shdata, struct file *file,
				unsigned long *sh_offset)
{
	int i = 0;
	char *buffer;

	while (i < elf_ex->e_shnum
	       && elf_shdata[i].sh_type != DIGSIG_ELF_SIG_SECTION) {
		i++;
	}

	if (i == elf_ex->e_shnum)
		return NULL;
	if (elf_shdata[i].sh_type != DIGSIG_ELF_SIG_SECTION)
		return NULL;
	if (elf_shdata[i].sh_size != DIGSIG_ELF_SIG_SIZE)
		return NULL;

	buffer = digsig_read_signature(file, elf_shdata[i].sh_offset);
	if (!buffer)
		return NULL;

	*sh_offset = elf_shdata[i].sh_offset;

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
digsig_verify_signature(char *sig_orig, struct file *file,
		 unsigned long sh_offset)
{
	char *sig_result = NULL, *read_blocks = NULL;
	int retval = -EPERM;
	unsigned int lower, upper, offset;
	loff_t i_size;
	SIGCTX *ctx = NULL;

	down (&digsig_sem);
	if (digsig_is_revoked_sig(sig_orig)) {
		DSM_ERROR("%s: Refusing attempt to load an ELF file with"
			  " a revoked signature.\n", __FUNCTION__);
		goto out;
	}

	retval = -ENOMEM;
	ctx = digsig_sign_verify_init(HASH_SHA1, SIGN_RSA);
	if (!ctx ) {
		DSM_PRINT(DEBUG_SIGN,
			  "%s: Cannot allocate crypto context.\n", __FUNCTION__);
		goto out;
	}

	sig_result = kmalloc(DIGSIG_ELF_SIG_SIZE, DIGSIG_SAFE_ALLOC);
	if (!sig_result) {
		DSM_ERROR ("kmalloc failed in %s for sig_result.\n", __FUNCTION__);
		goto out;
	}
	read_blocks = kmalloc(DIGSIG_ELF_READ_BLOCK_SIZE, DIGSIG_SAFE_ALLOC);
	if (!read_blocks) {
		DSM_ERROR ("kmalloc failed in %s for read_block.\n", __FUNCTION__);
		goto out;
	}

	memset(sig_result, 0, DIGSIG_ELF_SIG_SIZE);

	i_size = i_size_read(file->f_dentry->d_inode);
	for (offset = 0; offset < i_size; offset += DIGSIG_ELF_READ_BLOCK_SIZE){

		retval = kernel_read(file, offset, (char *) read_blocks,
				   DIGSIG_ELF_READ_BLOCK_SIZE);
		if (retval <= 0) {
			DSM_PRINT(DEBUG_SIGN,
				  "%s: Unable to read signature in blocks: %d\n",
				  __FUNCTION__, retval);
			goto out;
		}

		/* Makan: This is in order to avoid building a buffer
		   inside the kernel. At each read we check to be sure
		   that the parts of the signature read are set to 0 */ 
		/* Must zero out signature section to match bsign mechanism */
		lower = sh_offset;	/* lower bound of memset */
		upper = sh_offset + DIGSIG_ELF_SIG_SIZE;	/* upper bound */

		if ((lower < offset + DIGSIG_ELF_READ_BLOCK_SIZE) &&
		    (offset < upper)) {
			lower = (offset > lower) ? offset : lower;
			upper =	(offset + DIGSIG_ELF_READ_BLOCK_SIZE <
				 upper) ? offset +
				DIGSIG_ELF_READ_BLOCK_SIZE : upper;

			memset(read_blocks + (lower - offset), 0,
			       upper - lower);
		}

		/* continue verification loop */
		retval = digsig_sign_verify_update(ctx, read_blocks, retval);
		if (retval < 0) {
			DSM_PRINT(DEBUG_SIGN,
				  "%s: Error updating crypto verification\n", __FUNCTION__);
			goto out;
		}
	}

	/* A bit of bsign formatting else hashes won't match, works with bsign v0.4.4 */
	retval = digsig_sign_verify_final(ctx, sig_result, DIGSIG_ELF_SIG_SIZE,
					    sig_orig + DIGSIG_BSIGN_INFOS);
	if (retval != 0) {
		DSM_PRINT(DEBUG_SIGN,
			  "%s: Error calculating final crypto verification\n", __FUNCTION__);
	        retval = -EPERM;
		goto out;
	}

	// retval = 0;

out:
	kfree(sig_result);
	kfree(read_blocks);
	if (ctx) {
		kfree(ctx->tvmem);
		kfree(ctx);
	}
	up (&digsig_sem);
	return retval;
}

/*
 * If the file is opened for writing, deny mmap(PROT_EXEC) access.
 * Otherwise, increment the inode->i_security, which is our own
 * writecount.  When the file is closed, f->f_security will be 1,
 * and so we will decrement the inode->i_security.
 * Just to be clear:  file->f_security is 1 or 0.  inode->i_security
 * is the *number* of processes which have this file mmapped(PROT_EXEC),
 * so it can be >1.
 */
static int digsig_deny_write_access(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	unsigned long isec;

	spin_lock(&inode->i_lock);
	isec = get_inode_security(inode);
	if (atomic_read(&inode->i_writecount) > 0) {
		spin_unlock(&inode->i_lock);
		return -ETXTBSY;
	}
	set_inode_security(inode, (isec+1));
	set_file_security(file, 1);
	spin_unlock(&inode->i_lock);

	return 0;
}

/*
 * decrement our writer count on the inode.  When it hits 0, we will
 * again allow opening the inode for writing.
 */
static void digsig_allow_write_access(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	unsigned long isec;

	spin_lock(&inode->i_lock);
	isec = get_inode_security(inode);
	set_inode_security(inode, (isec-1));
	set_file_security(file, 0);
	spin_unlock(&inode->i_lock);
}

/*
 * the file is being closed.  If we ever mmaped it for exec, then
 * file->f_security>0, and we decrement the inode usage count to
 * show that we are done with it.
 */
static void digsig_file_free_security(struct file *file)
{
	if (file->f_security) {
		digsig_allow_write_access(file);
	}
}

/**
 * Basic verification of an ELF header
 * 
 * @param elf_hdr pointer to an elfhdr
 * @return 0 if header ok, -2 if non-elf, -1 otherwise
 */
static inline int elf_sanity_check32(struct elf32_hdr *elf_hdr)
{
	if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
		DSM_PRINT(DEBUG_SIGN, "%s: Binary is not elf format\n",
			  __FUNCTION__);
		return -2;
	}

	if (!elf_hdr->e_shoff) {
		DSM_ERROR("%s: No section header!\n", __FUNCTION__);
		return -1;
	}

	if (elf_hdr->e_shentsize != sizeof(Elf32_Shdr)) {
		DSM_ERROR("%s: Section header is wrong size!\n", __FUNCTION__);
		return -1;
	}

	if (elf_hdr->e_shnum > 65536U / sizeof(Elf32_Shdr)) {
		DSM_ERROR("%s: Too many entries in Section Header!\n",
			  __FUNCTION__);
		return -1;
	}

	return 0;
}

static inline int elf_sanity_check64(struct elf64_hdr *elf_hdr)
{
	if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
		DSM_PRINT(DEBUG_SIGN, "%s: Binary is not elf format\n",
			  __FUNCTION__);
		return -2;
	}

	if (!elf_hdr->e_shoff) {
		DSM_ERROR("%s: No section header!\n", __FUNCTION__);
		return -1;
	}

	if (elf_hdr->e_shentsize != sizeof(Elf64_Shdr)) {
		DSM_ERROR("%s: Section header is wrong size!\n", __FUNCTION__);
		return -1;
	}

	if (elf_hdr->e_shnum > 65536U / sizeof(Elf64_Shdr)) {
		DSM_ERROR("%s: Too many entries in Section Header!\n",
			  __FUNCTION__);
		return -1;
	}

	return 0;
}

/*
 * If we decide mmap of nonelf is bad, we can make this -EPERM.
 * However, note that bsign does mmap of SYSV shmem, so we can't
 * run bsign under digsig...  that's just funny :)
 */
#define NONELF_PERM NULL

static inline struct elf64_hdr *read_elf_header(struct file *file)
{
	struct elf64_hdr *elf_ex;
	int retval;

	elf_ex = kmalloc(sizeof(struct elf64_hdr), DIGSIG_SAFE_ALLOC);
	if (!elf_ex) {
		DSM_ERROR ("%s: kmalloc failed for elf_ex\n", __FUNCTION__);
		return ERR_PTR(-ENOMEM);
	}

	kernel_read(file, 0, (char *)elf_ex, sizeof(struct elf64_hdr));

	if (elf_ex->e_ident[EI_CLASS] == ELFCLASS32)
		retval = elf_sanity_check32((struct elf32_hdr *) elf_ex);
	else
		retval = elf_sanity_check64(elf_ex);
	if (retval) {
		kfree(elf_ex);
		if (retval == -1)
			return ERR_PTR(-EINVAL);
		else
			return NONELF_PERM;
	}

	return elf_ex;
}

static inline Elf64_Shdr *
read_section_header(struct file *file, unsigned long sh_size,
					unsigned long sh_off)
{
	Elf64_Shdr *elf_shdata;
	int retval;
	
	elf_shdata = kmalloc(sh_size, DIGSIG_SAFE_ALLOC);
	if (!elf_shdata) {
		DSM_ERROR("%s: Cannot allocate memory to read Section Header\n",
			  __FUNCTION__);
		return ERR_PTR(-ENOMEM);
	}

	retval = kernel_read(file, sh_off, (char *)elf_shdata, sh_size);

	if (retval < 0 || (unsigned long)retval != sh_size) {
		DSM_ERROR("%s: Unable to read binary %s (offset %lu size %lu): %d\n", __FUNCTION__,
			  file->f_dentry->d_name.name, sh_off, sh_size, retval);
		kfree(elf_shdata);
		return ERR_PTR(-EINVAL);
	}
	return elf_shdata;
}

/**
 * We don't want to validate files which can be written while they are
 * being executed.
 * This means NFS.
 */
static inline int is_unprotected_file(struct file *file)
{
	if (strcmp(file->f_dentry->d_inode->i_sb->s_type->name, "nfs") == 0)
		return 1;
	return 0;
}


#define start_digsig_bench \
	if (DIGSIG_BENCH) \
		exec_time = jiffies;

#define end_digsig_bench \
	if (DIGSIG_BENCH) { \
		exec_time = jiffies - exec_time; \
		total_jiffies += exec_time; \
		DSM_PRINT(DEBUG_TIME, \
			"Time to execute %s on %s is %li\n", \
			__FUNCTION__, file->f_dentry->d_name.name, exec_time); \
	}
	
static int digsig_file_mmap(struct file * file, unsigned long prot, unsigned long flags)
{
	struct elf64_hdr *elf64_ex;
	struct elf32_hdr *elf32_ex;
	int retval, die_if_elf = 0;
	/* allow_write_on_exit: 1 if we've revoked write access, but the
	 * signature ended up bad (ie we won't allow execute access anyway) */
	int allow_write_on_exit = 0;
	unsigned long size, sh_offset;
	Elf64_Shdr *elf64_shdata;
	char *sig_orig;
	long exec_time = 0;
	int arch32 = 0;

	if (!g_init)
		return 0;

	if (!(prot & VM_EXEC))
		return 0;
	if (!file)
		return 0;
	if (!file->f_dentry)
		return 0;
	if (!file->f_dentry->d_name.name)
		return 0;

	if (strcmp(file->f_dentry->d_name.name, "rmmod") == 0)
		return 0;
	if (strcmp(file->f_dentry->d_name.name, "libc.so.6") == 0)
		return 0;
	if (strcmp(file->f_dentry->d_name.name, "ld.so.1") == 0)
		return 0;

	if (is_unprotected_file(file))
		return DIGSIG_MODE;

	start_digsig_bench;

	DSM_PRINT(DEBUG_SIGN, "binary is %s\n", file->f_dentry->d_name.name);
 
	/*
	 * if file_security is set, then this process has already
	 * incremented the writer count on this inode, don't do
	 * it again.
	 */
	if (get_file_security(file) == 0) {
		allow_write_on_exit = 1;
		retval = digsig_deny_write_access(file); 
		if (retval) {
			die_if_elf = retval;
			allow_write_on_exit = 0;
		}
	}

	retval = 0;
	if (is_cached_signature(file->f_dentry->d_inode)) {
		DSM_PRINT(DEBUG_SIGN, "Binary %s had a cached signature validation.\n", 
			  file->f_dentry->d_name.name);
		allow_write_on_exit = 0;
		goto out_file_no_buf;
	}

	elf64_ex = read_elf_header(file);
	if (elf64_ex == NULL) /* non-ELF, perhaps SYSV shmem */
		goto out_file_no_buf;
	if (IS_ERR(elf64_ex)) {
		retval = PTR_ERR(elf64_ex);
		goto out_file_no_buf;
	}
	if (die_if_elf) {
		/* this ELF file is being written to, can't mmap(EXEC) it! */
		retval = die_if_elf;
		goto out_with_file;
	}

	retval = DIGSIG_MODE;

	arch32 = (elf64_ex->e_ident[EI_CLASS] == ELFCLASS32);

	elf32_ex = (struct elf32_hdr *) elf64_ex;
	if (arch32) {
		size = elf32_ex->e_shnum * sizeof(Elf32_Shdr);
		elf64_shdata = read_section_header(file, size, 
			elf32_ex->e_shoff);
	} else {
		size = elf64_ex->e_shnum * sizeof(Elf64_Shdr);
		elf64_shdata = read_section_header(file, size, elf64_ex->e_shoff);
	}

	if (IS_ERR(elf64_shdata)) {
		retval = -EINVAL;
		goto out_with_file;
	}

	/* Find signature section */
	if (arch32)
		sig_orig = digsig_find_signature32(
				elf32_ex, (struct Elf32_Shdr *) elf64_shdata,
				file, &sh_offset);
	else
		sig_orig = digsig_find_signature64(
				elf64_ex, elf64_shdata, file, &sh_offset);

	if (sig_orig == NULL) {
		DSM_PRINT(DEBUG_SIGN,
		"%s: Signature not found for the binary: %s !\n", 
			  __FUNCTION__, file->f_dentry->d_name.name);
		goto out_free_shdata;
	}

	/* Verify binary's signature */
	retval = digsig_verify_signature(sig_orig, file, sh_offset);

	if (!retval) {
		DSM_PRINT(DEBUG_SIGN,
			  "%s: Signature verification successful\n", __FUNCTION__);
		digsig_cache_signature(file->f_dentry->d_inode);
		allow_write_on_exit = 0;
	} else if (retval > 0) {
		DSM_ERROR("%s: Signature do not match for %s\n",
			  __FUNCTION__, file->f_dentry->d_name.name);
		retval = -EPERM;
	} else {
		DSM_PRINT(DEBUG_SIGN,
			  "%s: Signature verification failed because of errors: %d for %s\n",
			  __FUNCTION__, retval, file->f_dentry->d_name.name);
		retval = -EPERM;
	}

	kfree (sig_orig);
 out_free_shdata:
	kfree (elf64_shdata);
 out_with_file:
	kfree (elf64_ex);
 out_file_no_buf:
 	if (allow_write_on_exit)
		digsig_allow_write_access(file);

	end_digsig_bench;

	return retval;
}

static struct security_operations digsig_security_ops = {
	.file_mmap		= digsig_file_mmap,
	.file_free_security	= digsig_file_free_security,
	.inode_permission	= digsig_inode_permission,
	.inode_unlink		= digsig_inode_unlink,
};

static int __init digsig_init_module(void)
{
	int ret = -ENOMEM;
	DSM_PRINT(DEBUG_INIT, "Initializing module\n");

	/* initialize caching mechanisms */ 

	if (digsig_init_caching())
		goto out;

	ret = -EINVAL;
	if (digsig_init_sysfs()) {
		DSM_ERROR("Error setting up sysfs for DigSig\n");
		goto out_cache;
	}

	/* register */
	if (register_security(&digsig_security_ops)) {
		DSM_ERROR("%s: Failure registering DigSig as primairy security module\n", __FUNCTION__);
		if (mod_reg_security("digsig_verif", &digsig_security_ops)) {
			DSM_ERROR("%s: Failure registering DigSig as secondary module\n", __FUNCTION__);
			goto out_sysfs;
		}
		DSM_PRINT(DEBUG_INIT, "Registered as secondary module\n");
		secondary = 1;
	}
	return 0;
out_sysfs:
	digsig_cleanup_sysfs();
out_cache:
	digsig_cache_cleanup();
out:
	return ret;
}

static void __exit digsig_exit_module(void)
{
	DSM_PRINT (DEBUG_INIT, "Deinitializing module\n");
	g_init = 0;
	if (secondary) {
		DSM_PRINT (DEBUG_INIT, "Attempting to unregister from primary module\n");
		if (mod_unreg_security ("digsig_verif", &digsig_security_ops)) {
		DSM_ERROR (KERN_INFO "Failure unregistering DigSig with primary module\n");
		}
	} else {
		if (unregister_security (&digsig_security_ops)) {
		DSM_ERROR (KERN_INFO "Failure unregistering DigSig with the kernel\n");
		}
	}

	digsig_sign_verify_free();
	digsig_cleanup_sysfs();
	digsig_cleanup_revocation();
	digsig_cache_cleanup();
	mpi_free(digsig_public_key[0]);
	mpi_free(digsig_public_key[1]);
}

security_initcall(digsig_init_module);
module_exit(digsig_exit_module);

/* see linux/module.h */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Distributed Security Infrastructure Module");
MODULE_AUTHOR("DIGSIG Team sourceforge.net/projects/disec");
MODULE_SUPPORTED_DEVICE("DIGSIG_module");
