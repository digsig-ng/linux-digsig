/*
 * Distributed Security Module (DSM)
 *
 * dsi_sysfs.c
 *
 * This file contains the sysfs interface to userspace.
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: Vincent Roy
 * modifs: Serge Hallyn Mar 2003: separate into own file, add revocation
 *	interface.
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
#define DSI_KEY_OFFSET 3
#else
#define DSI_KEY_OFFSET 1
#endif

extern int g_init; /* digsig.c */
extern long int total_jiffies; /* digsig.c */
extern MPI dsi_public_key[2]; /* dsi_sig_verify.c */

extern struct list_head dsi_revoked_sigs; /* dsi_cache.c */

struct dsi_attribute  {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct attribute *attr, char *);
	ssize_t (*store)(struct kobject *, struct attribute *attr, const char *, size_t);
};

/* from digsig_cache.c */
extern struct list_head dsi_revoked_sigs;

/*
 * These are the show/hide prototypes and attribute for the
 * /sys/digsig/digsig_interface file, which is used to tell digsig the
 * public key to use to verify ELF file signatures.
 */
static ssize_t digsig_key_show (struct kobject *obj, struct attribute *attr,
	char *buff);
static ssize_t digsig_key_store (struct kobject *obj, struct attribute *attr,
	const char *buff, size_t count);
char digsig_file_name[] = "digsig_interface";
/*
 * For the curious, notice what's going on:  We create a structure which
 * contains  .attr .  This  .attr  is what we pass into  sysfs_create_file
 * in  dsi_init_sysfs .  In turn, sysfs will pass this back to us for read and
 * write operations ( digsig_key_store  and  digsig_key_show  above).  We can
 * then get our  digsig_attribute  variable, which contains the  .attr  whose
 * address we are sent, back by calculating the offset of  .attr  and
 * subtracting that from the address we were sent, which is what container_of
 * in  digsig_store  and  digsig_show  (just a few definitions below) do.
 */
static struct dsi_attribute digsig_attribute = {
	.attr = {.name = digsig_file_name,
		 .owner = THIS_MODULE,
		 .mode = S_IRUSR | S_IWUSR},
	.show = digsig_key_show,
	.store = digsig_key_store
};

/*
 * These are the show/hide prototypes and attribute for the
 * /sys/digsig/digsig_revoke file, which is used to tell digsig the
 * ELF file signatures which are revoked.  Digsig will not allow
 * loading any files which carry one of these signatures.
 */
static ssize_t digsig_revoked_list_show (struct kobject *obj,
	struct attribute *attr, char *buff);
static ssize_t digsig_revoked_list_store (struct kobject *obj,
	struct attribute *attr, const char *buff, size_t count);
char digsig_r_file_name[] = "digsig_revoke";
static struct dsi_attribute digsig_r_attribute = {
	.attr = {.name = digsig_r_file_name,
		 .owner = THIS_MODULE,
		 .mode = S_IRUSR | S_IWUSR},
	.show = digsig_revoked_list_show,
	.store = digsig_revoked_list_store
};

/*
 * Next are the digsig sysfs file operations.  These are assigned to
 * the files under /sys/digsig.  They will use the dsi_attribute struct
 * defined above to find the function which should actually be called
 * for read/write.  The attr argument to these functions is a member of
 * the dsi_attribute struct we defined, so we use its offset to find our
 * structure, which in turn contains the read and write operations we
 * actually want to perform.
 */
static ssize_t
digsig_store(struct kobject *kobj, struct attribute *attr, const char *buf,
	size_t len)
{
	struct dsi_attribute *attribute = container_of(attr,
		struct dsi_attribute, attr);

	return attribute->store ? attribute->store(kobj, attr, buf, len) : 0;
}

static ssize_t
digsig_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct dsi_attribute *attribute = container_of(attr,
		struct dsi_attribute, attr);

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
int dsi_init_sysfs(void)
{
	if (kobject_register (&digsig_kobject) != 0) {
		DSM_ERROR ("Digsig key failed to register properly\n");
		return -1;
	}
	if (sysfs_create_file(&digsig_kobject, &digsig_attribute.attr) != 0) {
		DSM_ERROR ("Create file failed\n");
		return -1;
	}
	if (sysfs_create_file(&digsig_kobject, &digsig_r_attribute.attr) != 0) {
		DSM_ERROR ("Create revocation file failed\n");
		return -1;
	}

	return 0;
}

void dsi_cleanup_sysfs(void)
{
	sysfs_remove_file (&digsig_kobject, &digsig_attribute.attr);
	sysfs_remove_file (&digsig_kobject, &digsig_r_attribute.attr);
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
		raw_public_key =
			(unsigned char *) kmalloc(count - DSI_KEY_OFFSET, DSI_SAFE_ALLOC);
		if (!raw_public_key) {
			DSM_ERROR("kmalloc fail for n in dsi_write\n");
			return -ENOMEM;
		}
		memcpy(raw_public_key, &buff[DSI_KEY_OFFSET], count - DSI_KEY_OFFSET);
		mpi_size = count - DSI_KEY_OFFSET;
		DSM_PRINT(DEBUG_DEV, "pkey->n size is %i\n", mpi_size);
		break;
	case 'e':
		raw_public_key =
			(unsigned char *) kmalloc(count - DSI_KEY_OFFSET, DSI_SAFE_ALLOC);
		if (!raw_public_key) {
			DSM_ERROR("kmalloc fail for e in dsi_write\n");
			return -ENOMEM;
		}
		memcpy(raw_public_key, &buff[DSI_KEY_OFFSET], count - DSI_KEY_OFFSET);
		mpi_size = count - DSI_KEY_OFFSET;
		DSM_PRINT(DEBUG_DEV, "pkey->e size is %i\n", mpi_size);
		break;
	default:
		return -EINVAL;
	}

	dsi_init_pkey(buff[0], raw_public_key, mpi_size);

	if (dsi_public_key[0] && dsi_public_key[1]) {
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
 * callbacks for read/write to /sys/digsig/digsig_revoke file
 */
static ssize_t
digsig_revoked_list_store (struct kobject *obj, struct attribute *attr, const char *buff, size_t count)
{
        struct revoked_sig *tmp;
        int rcount;
                                                                                
        if (g_init)
                return -EPERM;
                                                                                
        if (count != DSI_ELF_SIG_SIZE) {
                DSM_ERROR("digsig_revoked_list_store: Oops - count=%d, "
                          "sig size is %d\n", count, DSI_ELF_SIG_SIZE);
                return -EINVAL;
        }
                                                                                
        tmp = kmalloc(sizeof(struct revoked_sig), GFP_KERNEL);
        if (!tmp)
                return -ENOMEM;
        memset(tmp, 0, sizeof(struct revoked_sig));
        tmp->sig = mpi_read_from_buffer(
		buff + DSI_BSIGN_INFOS + DSI_RSA_DATA_OFFSET,
		&rcount, 0);
                                                                                
        list_add_tail(&tmp->next, &dsi_revoked_sigs);
                                                                                
        DSM_PRINT(DEBUG_SIGN, "Added a revoked sig.\n");
        return count;
}
                                                                                
static ssize_t
digsig_revoked_list_show (struct kobject *obj, struct attribute *attr, char *buff)
{
                                                                                
        return 0;
}
