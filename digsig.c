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
 * Author: David Gordon
 */


#include <linux/init.h>
#include <linux/config.h>
#include <linux/module.h>
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

#include "dsi_sig_verify.h"
#include "gnupg/mpi/mpi.h" 
#include "gnupg/cipher/rsa-verify.h" 
#include "dsi_debug.h"
#include "dsi.h"


#define RESTRICTIVE 0      /* CAREFUL: 0 for permissive mode, -ENOEXEC for restrictive mode */


/*
 * External variables
 */

extern MPI *dsi_public_key[2];

/* Allocate and free functions for each kind of security blob. */
static spinlock_t dsi_bprm_alloc_lock = SPIN_LOCK_UNLOCKED;

int DSIDebugLevel = DEBUG_SYS_SECURITY | DEBUG_INIT | DEBUG_SIGN;
struct security_operations dsi_security_ops;

#define set_dsi_ops(ops, function)				\
		if (!ops->function) {				\
			ops->function = dsi_##function;		\
                } 


/*
 * Internal functions
 */

static char *
internal_find_signature(struct elfhdr *elf_ex, 
			Elf32_Shdr *elf_shdata, 
			struct file *file, 
			int *sh_offset); 

static int
internal_verify_signature(char *filename, 
			  Elf32_Shdr * elf_shdata, 
			  char *sig_orig,
			  struct file *file, 
			  int sh_offset); 


/******************************************************************************
Description : find signature section in elf binary
              caller is responsible for deallocating memory of buffer returned
Parameters  : 
   elf_ex  is elf header
   elf_shdata is all entries in section header table of elf
   file contains file handle of binary
   sh_offset is offset of signature section in elf
Return value: buffer containing signature (size of signature is fixed 
              depending on algorithm used)
              sh_offset is set to offset of signature section in elf
******************************************************************************/
static char *
internal_find_signature(struct elfhdr *elf_ex, Elf32_Shdr *elf_shdata, struct file *file, int *sh_offset)
{
  int i = 0;
  int retval;
  unsigned long flags;
  char *buffer;

  i = 0;

  while (i < elf_ex->e_shnum) {
    if (elf_shdata[i].sh_type == DSI_ELF_SIG_SECTION) {
      DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Found signature section\n");

      /* Now get DSI_ELF_SIG_SIZE bytes of signature section */

      if (elf_shdata[i].sh_size != DSI_ELF_SIG_SIZE) {
	DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Signature section is not %u bytes\n",
		  DSI_ELF_SIG_SECTION);
	return NULL;
      }

      spin_lock_irqsave(&dsi_bprm_alloc_lock, flags);
      buffer = (char *) kmalloc(DSI_ELF_SIG_SIZE, DSI_SAFE_ALLOC);
      spin_unlock_irqrestore(&dsi_bprm_alloc_lock, flags);

      if (!buffer) {
	DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Cannot allocate memory for signature buffer.\n");
	return NULL;
      }

      retval = kernel_read(file, elf_shdata[i].sh_offset, (char *) buffer, DSI_ELF_SIG_SIZE);
      if (retval < 0 || retval != DSI_ELF_SIG_SIZE) {
	DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Unable to read signature: %d\n", retval);
	kfree(buffer);
	return NULL;
      }

      *sh_offset = elf_shdata[i].sh_offset;
      return buffer;
    }
    i++;
  }

  return NULL;
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
internal_verify_signature(char *filename, Elf32_Shdr * elf_shdata, char *sig_orig, struct file *file, int sh_offset)
{
  char *sig_result, *read_blocks;
  mm_segment_t old_fs;
  int retval, offset;
  struct kstat stat;
  unsigned int size;
  unsigned int lower, upper;
  unsigned long flags;
  SIGCTX *ctx;

  /* Get file size from file system */
  old_fs = get_fs();
  set_fs(get_ds());
  retval = vfs_lstat(filename, &stat);
  set_fs(old_fs);

  if (retval) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Unable to stat file %s: %d\n", filename, retval);
    return -1;
  }

  if ((ctx = dsi_sign_verify_init(HASH_SHA1,SIGN_RSA)) == NULL){
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Cannot allocate crypto context.\n");
    return -1;
  }

  spin_lock_irqsave(&dsi_bprm_alloc_lock, flags);
  sig_result = (char *) kmalloc(DSI_ELF_SIG_SIZE, DSI_SAFE_ALLOC);
  read_blocks = (char *) kmalloc(DSI_ELF_READ_BLOCK_SIZE, DSI_SAFE_ALLOC);
  spin_unlock_irqrestore(&dsi_bprm_alloc_lock, flags);

  if (!sig_result || !read_blocks) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Cannot allocate memory for buffers.\n");
    return -1;
  }

  memset(sig_result, 0, DSI_ELF_SIG_SIZE);

  for (offset = 0; offset < stat.size; offset += DSI_ELF_READ_BLOCK_SIZE) {

    size = kernel_read(file, offset, (char *) read_blocks, DSI_ELF_READ_BLOCK_SIZE);
    if (size <= 0) {
      DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Unable to read signature in blocks: %d\n", size);
      kfree(sig_result);
      kfree(read_blocks);
      return -1;
    }

    /* Must zero out signature section to match bsign mechanism */
    lower = sh_offset ;                     /* lower bound of memset */
    upper = sh_offset + DSI_ELF_SIG_SIZE;   /* upper bound */

    if ((lower < offset + DSI_ELF_READ_BLOCK_SIZE) &&
	(offset < upper)) {
      lower = (offset > lower) ? offset : lower;
      upper = (offset + DSI_ELF_READ_BLOCK_SIZE < upper) ? offset + DSI_ELF_READ_BLOCK_SIZE : upper;

      memset(read_blocks + (lower - offset), 0, upper - lower);
    }

    /* continue verification loop */
    if (dsi_sign_verify_update(ctx, read_blocks, size) != 0) {
      DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Error updating crypto verification\n");
      kfree(sig_result);
      kfree(read_blocks);
      return -1;
    }
  }

  /* A bit of bsign formatting else hashes won't match, works with bsign v0.4.4 */
  if ( (retval = dsi_sign_verify_final(ctx, sig_result, DSI_ELF_SIG_SIZE, sig_orig+DSI_BSIGN_INFOS)) < 0) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Error calculating final crypto verification\n");
    kfree(sig_result);
    kfree(read_blocks);
    return -1;
  }

  kfree(sig_result);
  kfree(read_blocks);
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

int
dsi_bprm_check_security(struct linux_binprm *bprm)
{
  struct elfhdr elf_ex;
  int retval, sh_offset;
  unsigned int size;
  Elf32_Shdr * elf_shdata;
  struct file * file;
  unsigned long flags;
  char *sig_orig;
		
  DSM_PRINT(DEBUG_SIGN, "binary is %s\n", bprm->filename);

  file = filp_open(bprm->filename, O_RDONLY, 0);
  if (!file && IS_ERR(file)) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Problem opening file\n");
    retval = RESTRICTIVE;
    goto out_file;
  }

  if (!file->f_op || !file->f_op->mmap) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Not allowed to read file\n");
    retval = RESTRICTIVE;
    goto out_file;
  }
  
  /* Get the exec-header, the original bprm->buf is no longer reliable at this point */
  kernel_read(file,0,bprm->buf,BINPRM_BUF_SIZE);
  elf_ex = *((struct elfhdr *) bprm->buf);
  
  if (memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Binary is not elf format\n");
    retval = RESTRICTIVE;
    goto out_file;
  }
  
  if (elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Binary is not executable\n");
    retval = RESTRICTIVE;
    goto out_file;
  }

  /* Now read in all of the section header entries */
  if (!elf_ex.e_shoff) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds No section header\n");
    retval = RESTRICTIVE;
    goto out_file;
  }

  if (elf_ex.e_shentsize != sizeof(Elf32_Shdr)) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Section header is wrong size\n");
    retval = RESTRICTIVE;
    goto out_file;
  }

  if (elf_ex.e_shnum > 65536U / sizeof(Elf32_Shdr)) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Too many entries in Section Header\n");
    retval = RESTRICTIVE;
    goto out_file;
  }

  size = elf_ex.e_shnum * sizeof(Elf32_Shdr);

  spin_lock_irqsave(&dsi_bprm_alloc_lock, flags);
  elf_shdata = (Elf32_Shdr *) kmalloc(size, DSI_SAFE_ALLOC);
  spin_unlock_irqrestore(&dsi_bprm_alloc_lock, flags);

  if (!elf_shdata) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Cannot allocate memory to read Section Header\n");
    retval = RESTRICTIVE;
    goto out_file;
  }

  retval = kernel_read(file, elf_ex.e_shoff, (char *) elf_shdata, size);

  if (retval < 0 || retval != size) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Unable to read binary %s: %d\n", bprm->filename, retval);
    kfree(elf_shdata);
    retval = RESTRICTIVE;
    goto out_file;
  }

  /* Find signature section */
  if ((sig_orig = internal_find_signature(&elf_ex, elf_shdata, file, &sh_offset)) == NULL) {
    kfree(sig_orig);     /* sig_orig now points to allocated memory after internal_find_signature */
    retval = RESTRICTIVE;
    goto out_file;
  }

  /* Verify binary's signature */
  retval = internal_verify_signature(bprm->filename, elf_shdata, sig_orig, file, sh_offset);

  if (!retval) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Signature verification successful\n");
  } else if (retval > 0) {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Signatures do not match\n");
    retval = RESTRICTIVE;
  } else {
    DSM_PRINT(DEBUG_SIGN, "dsi_bprm_compute_creds Signature verification failed because of errors: %d\n", retval);
    retval = RESTRICTIVE;
  }

  kfree(sig_orig);

 out_file:
  filp_close(file, 0); 
  return retval;
}



void security_set_operations(struct security_operations *ops)
{
  set_dsi_ops(ops, bprm_check_security);
}


static int __init digsig_init_module(void)
{
  int err = 0;

  DSM_PRINT(DEBUG_INIT, "Initializing module\n");
  /* Initialize public key */
  dsi_init_pkey();

  /* initialize DSI's hooks */
  security_set_operations(&dsi_security_ops);

  /* register */
  if ((err = register_security(&dsi_security_ops))) {
    DSM_ERROR("< dsi_init_module():Wrong security parameter\n");
    return err;
  }
	
  return 0;
}

static void __exit digsig_exit_module(void)
{
  DSM_PRINT(DEBUG_INIT, "Deinitializing module\n");
  dsi_sign_verify_free();
  
  unregister_security(&dsi_security_ops);
}

module_init (digsig_init_module);
module_exit (digsig_exit_module);

/* see linux/module.h */
MODULE_LICENSE("GPL"); 
MODULE_DESCRIPTION("Distributed Security Infrastructure Module");
MODULE_AUTHOR("DSI Team sourceforge.net/projects/disec");
MODULE_SUPPORTED_DEVICE("DSI_module");


