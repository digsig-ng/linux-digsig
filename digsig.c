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
 * modifs: Makan Pourzandi Sep 2003 
 *         Vincent Roy Sep 2003 
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

#include "dsi_sig_verify.h"
#include "dsi_debug.h"
#include "dsi.h"
#include "dsi_sysfs.h"

#ifdef DIGSIG_LTM
#include "ltm/tommath.h"
#else
#include "gnupg/mpi/mpi.h"
#include "gnupg/cipher/rsa-verify.h"
#endif


#ifdef DSI_DIGSIG_DEBUG
#define DIGSIG_MODE 0		/*permissive  mode */
#else
#define DIGSIG_MODE -EPERM	/*restrictive mode */
#endif

#ifdef MP_LOW_MEM
#define TAB_SIZE 32
#else
#define TAB_SIZE 256
#endif

#ifdef DIGSIG_LTM
extern mp_int dsi_public_key[2]; /* dsi_sig_verify.c */
unsigned char *packed;
mp_int *M, *W, *W2;
#else
extern MPI *dsi_public_key[2]; /* dsi_sig_verify.c */
#endif

unsigned long int total_jiffies = 0;

/* Allocate and free functions for each kind of security blob. */
static struct semaphore dsi_digsig_sem;

/* Indicate if module as key or not */
int g_init = 0;

int DSIDebugLevel = DEBUG_INIT | DEBUG_DEV | DEBUG_SIGN | DEBUG_TIME;

struct security_operations dsi_security_ops;

#define set_dsi_ops(ops, function)				\
		if (!ops->function) {				\
			ops->function = dsi_##function;		\
                }

static char *dsi_find_signature(struct elfhdr *elf_ex,
				Elf32_Shdr * elf_shdata,
				struct file *file, int *sh_offset);

static int
dsi_verify_signature(char *filename,
		     Elf32_Shdr * elf_shdata,
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
			  "dsi_bprm_compute_creds: Found signature section\n");

		/* Now get DSI_ELF_SIG_SIZE bytes of signature section */

		if (elf_shdata[i].sh_size != DSI_ELF_SIG_SIZE) {
			DSM_PRINT(DEBUG_SIGN,
				  "dsi_bprm_compute_creds: Signature section is not %u bytes\n",
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
				  "dsi_bprm_compute_creds: Unable to read signature: %d\n",
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
dsi_verify_signature(char *filename, Elf32_Shdr * elf_shdata,
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
			  "dsi_bprm_compute_creds Cannot allocate crypto context.\n");
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
				  "dsi_bprm_compute_creds Unable to read signature in blocks: %d\n",
				  size);
			kfree(sig_result);
			kfree(read_blocks);
			up (&dsi_digsig_sem);
			return -1;
		}

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
				  "dsi_bprm_compute_creds Error updating crypto verification\n");
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
			  "dsi_bprm_compute_creds Error calculating final crypto verification\n");
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

	if (DSIDebugLevel & DEBUG_TIME)	/* measure exec time only on DEBUG mode. */
		exec_time = jiffies;

	DSM_PRINT(DEBUG_SIGN, "binary is %s\n", bprm->filename);

	file = filp_open(bprm->filename, O_RDONLY, 0);
	if (!file && IS_ERR(file)) {
		DSM_ERROR ("dsi_bprm_check_security: Problem opening file %s!\n", bprm->filename);
		retval = DIGSIG_MODE;
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
	retval = dsi_verify_signature(bprm->filename, elf_shdata,
				      sig_orig, file, sh_offset);

	if (!retval) {
		DSM_PRINT(DEBUG_SIGN,
			  "dsi_bprm_compute_creds: Signature verification successful for %s\n", bprm->filename);
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

	if (DSIDebugLevel & DEBUG_TIME) {	/* measure exec time only on DEBUG mode. */
		exec_time = jiffies - exec_time;
		total_jiffies += exec_time;
		DSM_PRINT(DEBUG_TIME, "Time to execute dsi_bprm_check_security on %s is %li\n", bprm->filename, exec_time);
	}
	return retval;
}


void security_set_operations(struct security_operations *ops)
{
	set_dsi_ops(ops, bprm_check_security);

}

char digsig_file_name[] = "digsig_key_file";
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
static struct kobject digsig_key = {
	.name = "Digsig_key",
	.ktype = &digsig_kobj_type
};

static int __init digsig_init_module(void)
{
	int err = 0;
	int tmp;

	DSM_PRINT(DEBUG_INIT, "Initializing module\n");

	/* initialize DSI's hooks */
	security_set_operations(&dsi_security_ops);

	/* register */
	if ((err = register_security(&dsi_security_ops))) {
		DSM_ERROR ("< dsi_init_module():Wrong security parameter\n");
		return err;
	}

	init_MUTEX (&dsi_digsig_sem);

	if (kobject_register (&digsig_key) != 0) {
		DSM_ERROR ("Digsig key failed to register properly\n");
		return -1;
	}
	if ((tmp = sysfs_create_file (&digsig_key, &digsig_attribute)) != 0) {
		DSM_ERROR ("Create file failed\n");
		return -1;
	}

#ifdef DIGSIG_LTM
	DSM_PRINT(DEBUG_SIGN, "Initializing public key holder\n");
	mp_init(&dsi_public_key[0]);
	mp_init(&dsi_public_key[1]);
	packed = kmalloc (2048 * sizeof(unsigned char), DSI_SAFE_ALLOC);
	if (!packed) {
		DSM_ERROR ("kmalloc failed in digsig_init_module for packed\n");
		return -ENOMEM;
	}
	M = kmalloc (TAB_SIZE * sizeof (mp_int), DSI_SAFE_ALLOC);
	if (!M) {
		DSM_ERROR ("kmalloc failed in digsig_init_module for M\n");
		return -ENOMEM;
	}
	W = kmalloc (MP_WARRAY * sizeof (mp_word), DSI_SAFE_ALLOC);
	if (!W) {
		DSM_ERROR ("kmalloc failed in digsig_init_module for W\n");
		return -ENOMEM;
	}
	W2 = kmalloc (MP_WARRAY * sizeof(mp_word), DSI_SAFE_ALLOC);
	if (!W2) {
		DSM_ERROR ("kmalloc failed in digsig_init_module for W2\n");
		return -ENOMEM;
	}
#endif

	return 0;
}

static void __exit digsig_exit_module(void)
{
	DSM_PRINT(DEBUG_INIT, "Deinitializing module\n");
	dsi_sign_verify_free();
	unregister_security(&dsi_security_ops);
	sysfs_remove_file (&digsig_key, &digsig_attribute);
	kobject_unregister (&digsig_key);

#ifdef DIGSIG_LTM
	DSM_PRINT(DEBUG_SIGN, "Deinitializing public key holder\n");
	mp_clear(&dsi_public_key[0]);
	mp_clear(&dsi_public_key[1]);
	kfree (packed);
	kfree (M);
	kfree (W);
	kfree (W2);
#endif
}

module_init(digsig_init_module);
module_exit(digsig_exit_module);

/* see linux/module.h */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Distributed Security Infrastructure Module");
MODULE_AUTHOR("DSI Team sourceforge.net/projects/disec");
MODULE_SUPPORTED_DEVICE("DSI_module");
