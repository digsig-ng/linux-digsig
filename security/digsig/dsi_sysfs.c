/*
 * Digital Signature (DigSig)
 *
 * dsi_sysfs.c
 *
 * This file contains the sysfs interface to userspace.
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 * Copyright (c) 2003-2004 International Business Machines <serue@us.ibm.com> 
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: Vincent Roy
 * modifs: Serge Hallyn Mar 2003: separate into own file, add revocation
 *	interface.
 *         Chris Wright Sept 2004: change names of sysfs files 
 *         digsig_interface -> key,  digsig_revoke -> revoke
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/elf.h>
#include <linux/slab.h>

#include "dsi.h"
#include "dsi_debug.h"
#include "dsi_sig_verify.h"
#include "digsig_cache.h"
#include "digsig_revocation.h"

/* For use with LTM, we copy everything except the first three bytes
   which are 'n' or 'e' + size.
   For use with GnuPG, we should copy everything except the first byte
*/
#ifdef DIGSIG_LTM
#define DIGSIG_KEY_OFFSET 3
#else
#define DIGSIG_KEY_OFFSET 1
#endif

extern long int total_jiffies; /* digsig.c */

struct digsig_attribute  {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct attribute *attr, char *);
	ssize_t (*store)(struct kobject *, struct attribute *attr, const char *, size_t);
};

#ifndef __ATTR
#define __ATTR(_name,_mode,_show,_store) { \
        .attr = {.name = __stringify(_name), .mode = _mode, .owner = THIS_MODULE },     \
        .show   = _show,                                        \
        .store  = _store,                                       \
}
#endif 

#define DIGSIG_ATTR(_name, _mode, _show, _store)	\
struct digsig_attribute digsig_attr_##_name = __ATTR(_name,_mode,_show,_store)

/*
 * These are the show/hide prototypes and attribute for the
 * /sys/digsig/key file, which is used to tell digsig the
 * public key to use to verify ELF file signatures.
 */
static ssize_t digsig_key_show (struct kobject *obj, struct attribute *attr,
	char *buff);
static ssize_t digsig_key_store (struct kobject *obj, struct attribute *attr,
	const char *buff, size_t count);
/*
 * For the curious, notice what's going on:  We create a structure which
 * contains  .attr .  This  .attr  is what we pass into  sysfs_create_file
 * in  digsig_init_sysfs .  In turn, sysfs will pass this back to us for read and
 * write operations ( digsig_key_store  and  digsig_key_show  above).  We can
 * then get our  digsig_attribute  variable, which contains the  .attr  whose
 * address we are sent, back by calculating the offset of  .attr  and
 * subtracting that from the address we were sent, which is what container_of
 * in  digsig_store  and  digsig_show  (just a few definitions below) do.
 */
static DIGSIG_ATTR(key, 0600, digsig_key_show, digsig_key_store);

/*
 * These are the show/hide prototypes and attribute for the
 * /sys/digsig/revoke file, which is used to tell digsig the
 * ELF file signatures which are revoked.  Digsig will not allow
 * loading any files which carry one of these signatures.
 */
static ssize_t digsig_revoked_show (struct kobject *obj,
	struct attribute *attr, char *buff);
static ssize_t digsig_revoked_store (struct kobject *obj,
	struct attribute *attr, const char *buff, size_t count);
static DIGSIG_ATTR(revoke, 0600, digsig_revoked_show, digsig_revoked_store);

/*
 * Next are the digsig sysfs file operations.  These are assigned to
 * the files under /sys/digsig.  They will use the digsig_attribute
 * struct defined above to find the function which should actually be
 * called for read/write.  The attr argument to these functions is a
 * member of the digsig_attribute struct we defined, so we use its
 * offset to find our structure, which in turn contains the read and
 * write operations we actually want to perform.
 */
static ssize_t
digsig_store(struct kobject *kobj, struct attribute *attr, const char *buf,
	size_t len)
{
	struct digsig_attribute *attribute = container_of(attr,
		struct digsig_attribute, attr);

	return attribute->store ? attribute->store(kobj, attr, buf, len) : 0;
}

static ssize_t
digsig_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct digsig_attribute *attribute = container_of(attr,
		struct digsig_attribute, attr);

	return attribute->show ? attribute->show(kobj, attr, buf) : 0;
}

/*
 * digsig_sysfs_ops: The operations structure (containing file read/write
 * functions) for our sysfs files
 */
static struct sysfs_ops digsig_sysfs_ops = {
	.show = digsig_show,
	.store = digsig_store
};

/* digsig_kobj_type: A kobject to attach to our sysfs directory */
static struct kobj_type digsig_kobj_type = {
	.sysfs_ops = &digsig_sysfs_ops,
};

/* digsig_kobject: a kobject for our /sys/digsig directory */
static struct kobject digsig_kobject = {
	.name = "digsig",
	.ktype = &digsig_kobj_type
};


/*
 * init and cleanup functions for the /sys/digsig directory.
 */
int __init digsig_init_sysfs(void)
{
	if (kobject_register (&digsig_kobject) != 0) {
		DSM_ERROR ("Digsig key failed to register properly\n");
		goto err;
	}
	if (sysfs_create_file(&digsig_kobject, &digsig_attr_key.attr) != 0) {
		DSM_ERROR ("Create file failed\n");
		goto create_key;
	}
	if (sysfs_create_file(&digsig_kobject, &digsig_attr_revoke.attr) != 0) {
		DSM_ERROR ("Create revocation file failed\n");
		goto create_revoke;
	}
	return 0;

create_revoke:
	sysfs_remove_file (&digsig_kobject, &digsig_attr_key.attr);
create_key:
	kobject_unregister (&digsig_kobject);
err:
	return -1;
}

void digsig_cleanup_sysfs(void)
{
	sysfs_remove_file (&digsig_kobject, &digsig_attr_key.attr);
	sysfs_remove_file (&digsig_kobject, &digsig_attr_revoke.attr);
	kobject_unregister (&digsig_kobject);
}

/********************************************************************************
Description : This function reads the public key parts
We receive first n (the modulus) and then e (public exponent). They follow
this format:
 - 1 byte : character 'n' or 'e'
 - 2 bytes: length of MPI in BITS
 - MPI
Parameters  : 
Return value: 
*********************************************************************************/
static ssize_t
digsig_key_store (struct kobject *obj, struct attribute *attr, const char *buff, size_t count)
{
	unsigned char *raw_public_key;
	int mpi_size;

	switch (buff[0]) {
	case 'i':
		total_jiffies = 0;
		break;
	case 'p':
		printk ("total jiffies = %li\n", total_jiffies);
		break;
	}

	/* do not accept to re-initialize the module with
	   new public key. This avoids many coherency
	   problem when updating keys while checking the
	   signatures.*/
	if (g_init)
		return -1;

	switch (buff[0]) {
	case 'n':
	case 'e':
		raw_public_key =
			kmalloc(count - DIGSIG_KEY_OFFSET, DIGSIG_SAFE_ALLOC);
		if (!raw_public_key) {
			DSM_ERROR("kmalloc fail for %c in %s\n", buff[0], __FUNCTION__);
			return -ENOMEM;
		}
		memcpy(raw_public_key, &buff[DIGSIG_KEY_OFFSET], count - DIGSIG_KEY_OFFSET);
		mpi_size = count - DIGSIG_KEY_OFFSET;
		DSM_PRINT(DEBUG_DEV, "pkey->%c size is %i\n", buff[0], mpi_size);
		break;
	default:
		return -EINVAL;
	}

	digsig_init_pkey(buff[0], raw_public_key, mpi_size);

	if (digsig_public_key[0] && digsig_public_key[1]) {
		g_init = 1;
	}
	kfree(raw_public_key);

	return count;
}


static ssize_t
digsig_key_show (struct kobject *obj, struct attribute *attr, char *buff)
{

	return 0;
}

/*
 * callbacks for read/write to /sys/digsig/revoke file
 */
static ssize_t
digsig_revoked_store (struct kobject *obj, struct attribute *attr, const char *buff, size_t count)
{
        if (g_init)
                return -EPERM;

        if (count != DIGSIG_ELF_SIG_SIZE) {
                DSM_ERROR("digsig_revoked_list_store: Oops - count=%d, "
                          "sig size is %d\n", count, DIGSIG_ELF_SIG_SIZE);
                return -EINVAL;
        }

	digsig_add_revoked_sig(buff);

        DSM_PRINT(DEBUG_SIGN, "Added a revoked sig.\n");
        return count;
}

static ssize_t
digsig_revoked_show (struct kobject *obj, struct attribute *attr, char *buff)
{

        return 0;
}
