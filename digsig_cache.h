#ifndef __DSI_CACHE_H

#include <linux/fs.h>
#include "gnupg/mpi/mpi.h"

int is_cached_signature(struct inode *inode);
void remove_signature(struct inode *inode);
int dsi_purge_cache(int num);
void dsi_cache_signature(struct inode *inode);
int dsi_init_caching(void);
void dsi_cache_cleanup(void);

#endif
