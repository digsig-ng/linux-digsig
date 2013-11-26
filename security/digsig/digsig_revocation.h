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
 * Author: Serge Hallyn Mar 2004 
 *         
 */

#ifndef _DSI_REVOKE_H
#define _DSI_REVOKE_H

#include <linux/fs.h>
#include "gnupg/mpi/mpi.h"

/*
 * A linear array of revoked signatures.
 *
 * If performance is a concern, this could be changed to a hash
 * table.
 */
struct revoked_sig {
	struct hlist_node next;
	MPI sig;
};

void digsig_init_revocation(void);
void digsig_cleanup_revocation(void);
int digsig_add_revoked_sig(const char *buffer);
#ifdef DIGSIG_REVOCATION
int digsig_is_revoked_sig(char *buffer);
#else
#define digsig_is_revoked_sig(x) 0
#endif

#endif /* _DSI_REVOKE_H */
