#ifndef __DSI_REVOKE_H

#include <linux/fs.h>
#include "gnupg/mpi/mpi.h"

void dsi_init_revocation(void);
void dsi_cleanup_revocation(void);
#ifdef DSI_REVOCATION
int dsi_is_revoked_sig(char *buffer);
#else
#define dsi_is_revoked_sig(x) 0
#endif

/*
 * A linear array of revoked signatures.
 *
 * If performance is a concern, this could be changed to a hash
 * table.
 */
struct revoked_sig {
	struct list_head next;
	MPI sig;
};

#endif
