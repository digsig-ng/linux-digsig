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
 * Author: Serge Hallyn Jan 2004
 *         
 */

#ifndef _DSI_CACHE_H
#define _DSI_CACHE_H

#include <linux/fs.h>
#include "gnupg/mpi/mpi.h"

int is_cached_signature(struct inode *inode);
void remove_signature(struct inode *inode);
void digsig_cache_signature(struct inode *inode);
int digsig_init_caching(void);
void digsig_cache_cleanup(void);

#endif /* _DSI_CACHE_H */

