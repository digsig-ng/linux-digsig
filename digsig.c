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
#include "digsig_cache.h"
#include "digsig_revocation.h"

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

#define get_inode_security(ino) ((unsigned long)(ino->i_security))
#define set_inode_security(ino,val) (ino->i_security = (void *)val)

#define get_file_security(file) ((unsigned long)(file->f_security))
#define set_file_security(file,val) (file->f_security = (void *)val)

extern MPI *dsi_public_key[2]; /* dsi_sig_verify.c */

unsigned long int total_jiffies = 0;

/* Allocate and free functions for each kind of security blob. */
static struct semaphore dsi_digsig_sem;

/* Indicate if module as key or not */
int g_init = 0;

/* Keep track of how we are registered */
int secondary = 0;

#ifdef DIGSIG_LOG
int DSIDebugLevel = DEBUG_INIT | DEBUG_SIGN  ;
#else
int DSIDebugLevel = DEBUG_INIT;
#endif

/* Maximum number of signature validations which will be cached */
int dsi_max_cached_sigs = 512;
module_param(dsi_max_cached_sigs, int, 0);
MODULE_PARM_DESC(dsi_max_cached_sigs, "Number of signatures to keep cached\n");

/* Number of signature validations cached so far */
int dsi_num_cached_sigs = 0;

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
dsi_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	if (!g_init)
		return 0;

	if (inode && mask & MAY_WRITE) {
#ifndef DSI_EXEC_ONLY
		unsigned long isec = get_inode_security(inode);
		if (isec > 0)
			return -EPERM;
#endif
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
dsi_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if (!g_init)
		return 0;

	if (!is_cached_signature(dentry->d_inode))
		return 0;

	remove_signature(dentry->d_inode);
	return 0;
}

struct security_operations dsi_security_ops;

#define set_dsi_ops(ops, function)				\
		if (!ops->function) {				\
			ops->function = dsi_##function;		\
                }

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
	if (dsi_is_revoked_sig(sig_orig)) {
		DSM_ERROR("dsi_verify_signature: Refusing attempt to load an ELF"
			"file with a revoked signature.\n");
		up (&dsi_digsig_sem);
		return -EPERM;
	}

	if ((ctx = dsi_sign_verify_init(HASH_SHA1, SIGN_RSA)) == NULL) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_verify_signature Cannot allocate crypto context.\n");
		up (&dsi_digsig_sem);
		return -ENOMEM;
	}

	sig_result = (char *) kmalloc(DSI_ELF_SIG_SIZE, DSI_SAFE_ALLOC);
	if (!sig_result) {
		DSM_ERROR ("kmalloc failed in dsi_verify_signature for sig_result.\n");
		kfree (ctx->tvmem);
		kfree (ctx);
		up (&dsi_digsig_sem);
		return -ENOMEM;
	}
	read_blocks = (char *) kmalloc(DSI_ELF_READ_BLOCK_SIZE, DSI_SAFE_ALLOC);
	if (!read_blocks) {
		DSM_ERROR ("kmalloc failed in dsi_verify_signature for read_block.\n");
		kfree (ctx->tvmem);
		kfree (ctx);
		kfree (sig_result);
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
			kfree(ctx->tvmem);
			kfree(ctx);
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
			kfree(ctx->tvmem);
			kfree(ctx);
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
/*
 * If the file is opened for writing, deny mmap(PROT_EXEC) access.
 * Otherwise, increment the inode->i_security, which is our own
 * writecount.  When the file is closed, f->f_security will be 1,
 * and so we will decrement the inode->i_security.
 * Just to be clear:  file->f_security is 1 or 0.  inode->i_security
 * is the *number* of processes which have this file mmapped(PROT_EXEC),
 * so it can be >1.
 */
static int dsi_deny_write_access(struct file *file)
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
static void dsi_allow_write_access(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	unsigned long isec = get_inode_security(inode);

	set_inode_security(inode, (isec-1));
	set_file_security(file, 0);
}

/*
 * the file is being closed.  If we ever mmaped it for exec, then
 * file->f_security>0, and we decrement the inode usage count to
 * show that we are done with it.
 */
void dsi_file_free_security(struct file *file)
{
	if (file->f_security) {
		dsi_allow_write_access(file);
	}
}

int dsi_file_mmap(struct file * file, unsigned long prot, unsigned long flags)
{
	struct elfhdr *elf_ex;
	int retval, sh_offset;
	/* allow_write_on_exit: 1 if we've revoked write access, but the
	 * signature ended up bad (ie we won't allow execute access anyway) */
	int allow_write_on_exit = 0;
	unsigned int size;
	Elf32_Shdr *elf_shdata;
	char *sig_orig;
	long exec_time = 0;
	char *buf;

	if (!g_init)
		return 0;

	if (!file)
		return 0;
	if (!(prot & VM_EXEC))
		return 0;
	if (!file->f_dentry)
		return 0;
	if (!file->f_dentry->d_name.name)
		return 0;
 
	/*
	 * if file_security is set, then this process has already
	 * incremented the writer count on this inode, don't do
	 * it again.
	 */
	if (get_file_security(file) == 0) {
		allow_write_on_exit = 1;
		retval = dsi_deny_write_access(file); 
		if (retval)
			return retval;
	}

	if (DIGSIG_BENCH)	/* measure exec time only on DEBUG mode. */
		exec_time = jiffies;

	DSM_PRINT(DEBUG_SIGN, "binary is %s\n", file->f_dentry->d_name.name);

	if (is_cached_signature(file->f_dentry->d_inode)) {
		DSM_PRINT(DEBUG_SIGN, "Binary %s had a cached signature validation.\n", file->f_dentry->d_name.name);
		retval = 0;
		allow_write_on_exit = 0;
		goto out_file_no_buf;
	}

	buf = kmalloc (BINPRM_BUF_SIZE, DSI_SAFE_ALLOC);
	if (!buf) {
		DSM_ERROR ("kmalloc failed in dsi_file_mmap for buf\n");
		retval = 0;
		goto out_file_no_buf;
	}

	/* Get the exec-header, the original bprm->buf is no longer reliable at this point */
	kernel_read(file, 0, buf, BINPRM_BUF_SIZE);
	elf_ex = (struct elfhdr *) buf;

	if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_file_mmap: Binary is not elf format\n");
		retval = 0;
		/* ToDO: Makan, we decide to let go the not elf binaries.
		   ?? This is not obvious, we cannot sign a non-elf binary, should
		   we only check elf files and not execute the non-elf
		   binaries???? */
		goto out_file;
	}

	if (elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN) {
		DSM_PRINT(DEBUG_SIGN, "dsi_file_mmap: Binary is not executable\n");
		retval = 0;	/* ToDO: Makan, we decide to let go the not executable binaries. */
		goto out_file;
	}

	/* Now read in all of the section header entries */
	if (!elf_ex->e_shoff) {
		DSM_ERROR("dsi_file_mmap: No section header!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	if (elf_ex->e_shentsize != sizeof(Elf32_Shdr)) {
		DSM_ERROR ("dsi_file_mmap: Section header is wrong size!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	if (elf_ex->e_shnum > 65536U / sizeof(Elf32_Shdr)) {
		DSM_ERROR ("dsi_file_mmap: Too many entries in Section Header!\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	size = elf_ex->e_shnum * sizeof(Elf32_Shdr);

	elf_shdata = (Elf32_Shdr *) kmalloc(size, DSI_SAFE_ALLOC);
	if (!elf_shdata) {
		DSM_ERROR ("dsi_file_mmap: Cannot allocate memory to read Section Header\n");
		retval = DIGSIG_MODE;
		goto out_file;
	}

	retval = kernel_read (file, elf_ex->e_shoff, (char *) elf_shdata, size);

	if (retval < 0 || retval != size) {
		DSM_ERROR ("dsi_file_mmap: Unable to read binary %s: %d\n",
			   file->f_dentry->d_name.name, retval);
		kfree (elf_shdata);
		retval = DIGSIG_MODE;
		goto out_file;
	}

	/* Find signature section */
	if ((sig_orig = dsi_find_signature (elf_ex, elf_shdata, file,
					    &sh_offset)) == NULL) {
		retval = DIGSIG_MODE;
		DSM_PRINT(DEBUG_SIGN,"dsi_file_mmap: Signature not found for the binary: %s !\n", 
			  file->f_dentry->d_name.name);
		kfree (elf_shdata);
		goto out_file;
	}

	/* Verify binary's signature */
	retval = dsi_verify_signature (elf_shdata, sig_orig, file, sh_offset);

	if (!retval) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_file_mmap: Signature verification successful\n");
		if (!strcmp (file->f_dentry->d_inode->i_sb->s_type->name, "nfs")) {
			DSM_PRINT (DEBUG_SIGN, "File on NFS : no caching\n");
			kfree (sig_orig);
			kfree (elf_shdata);
			goto out_file;
		}
		dsi_cache_signature(file->f_dentry->d_inode);

		allow_write_on_exit = 0;
	} else if (retval > 0) {
		DSM_ERROR("dsi_file_mmap: Signature do not match for %s\n", file->f_dentry->d_name.name);
		retval = -EPERM;
	} else {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_file_mmap: Signature verification failed because of errors: %d for %s\n",
			  retval, file->f_dentry->d_name.name);
		retval = -EPERM;
	}

	kfree (sig_orig);
	kfree (elf_shdata);

 out_file:
	kfree (buf);
 out_file_no_buf:
 	if (allow_write_on_exit) {
		dsi_allow_write_access(file);
		file->f_security = NULL;
	}

	if (DIGSIG_BENCH) {	/* measure exec time only on DEBUG mode. */
		exec_time = jiffies - exec_time;
		total_jiffies += exec_time;
		DSM_PRINT(DEBUG_TIME, "Time to execute dsi_file_mmap on %s is %li\n", file->f_dentry->d_name.name, exec_time);
	}
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

	if (is_cached_signature(file->f_dentry->d_inode)) {
		DSM_PRINT(DEBUG_SIGN, "Binary %s had a cached signature validation.\n", bprm->filename);
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
		kfree (elf_shdata);
		goto out_file;
	}

	/* Verify binary's signature */
	retval = dsi_verify_signature (elf_shdata, sig_orig, file, sh_offset);

	if (!retval) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_bprm_compute_creds: Signature verification successful for %s\n", bprm->filename);
		if (!strcmp (file->f_dentry->d_inode->i_sb->s_type->name, "nfs")) {
			DSM_PRINT (DEBUG_SIGN, "File on NFS : no caching\n");
			kfree (sig_orig);
			kfree (elf_shdata);
			goto out_file;
		}
		dsi_cache_signature(file->f_dentry->d_inode);
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
	kfree (elf_shdata);

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
#ifdef DSI_EXEC_ONLY
	set_dsi_ops(ops, bprm_check_security);
#else
	set_dsi_ops (ops, file_mmap);
	set_dsi_ops (ops, file_free_security);
#endif
	set_dsi_ops(ops, inode_permission);
	set_dsi_ops(ops, inode_unlink);

}

static int __init digsig_init_module(void)
{
	DSM_PRINT(DEBUG_INIT, "Initializing module\n");

	/* initialize caching mechanisms */ 

	if (dsi_init_caching()){
	  return -ENOMEM;
	}
	dsi_init_revocation();

	/* initialize DSI's hooks */
	security_set_operations(&dsi_security_ops);

	/* register */
	if (register_security (&dsi_security_ops)) {
		DSM_ERROR ("< disig_init_module(): Failure registering DigSig as primairy security module\n");
		if (mod_reg_security ("digsig_verif", &dsi_security_ops)) {
			DSM_ERROR ("< digsig_init_module(): Failure registering DigSig as secondary module\n");
			return -EINVAL;
		}
		DSM_PRINT (DEBUG_INIT, "Registered as secondary module\n");
		secondary = 1;
	}

	init_MUTEX (&dsi_digsig_sem);

	if (dsi_init_sysfs()) {
		DSM_ERROR("Error setting up sysfs for dsi\n");
		return -EINVAL;
	}

	return 0;
}

static void __exit digsig_exit_module(void)
{
	DSM_PRINT (DEBUG_INIT, "Deinitializing module\n");
	g_init = 0;
	dsi_sign_verify_free ();
	dsi_cleanup_sysfs ();
	dsi_cleanup_revocation ();
	dsi_cache_cleanup ();
	if (secondary) {
		DSM_PRINT (DEBUG_INIT, "Attempting to unregister from primary module\n");
		if (mod_unreg_security ("digsig_verif", &dsi_security_ops)) {
		DSM_ERROR (KERN_INFO "Failure unregistering DigSig with primary module\n");
		}
	} else {
		if (unregister_security (&dsi_security_ops)) {
		DSM_ERROR (KERN_INFO "Failure unregistering DigSig with the kernel\n");
		}
	}
}

module_init(digsig_init_module);
module_exit(digsig_exit_module);

/* see linux/module.h */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Distributed Security Infrastructure Module");
MODULE_AUTHOR("DSI Team sourceforge.net/projects/disec");
MODULE_SUPPORTED_DEVICE("DSI_module");
