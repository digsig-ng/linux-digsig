/*
 * Distributed Security Module (DSM)
 *
 * dsi_sig_verify.h
 *	
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 * 
 * Author: Axelle Apvrille <axelle.apvrille@ericsson.ca>
 *         David Gordon
 */

#ifndef _DSI_SIG_VERIFY_H_
#define _DSI_SIG_VERIFY_H_

#include <linux/crypto.h>
#include <asm/scatterlist.h>
#include "gnupg/mpi/mpi.h"


#define DSI_ELF_SIG_SECTION 0x80736967	/* ((0x80 << 24)|('s' << 16)|('i' << 8)|'g') */
#define DSI_ELF_SIG_SIZE 512	/* Total signature size */
#define DSI_ELF_READ_BLOCK_SIZE 1024	/* Signature will be done in chunks of n bytes */

/* 
 * Format of digital signature done by bsign:
 * - "#1; bsign v%s\n"
 * - hash of file with sig section zerod (crypto class and timestamp not added to hash)
 * - length of digsig (2 bytes)
 * - digsig
 */

#define DSI_BSIGN_VERSION    "0.4.5"
#define DSI_BSIGN_STRING     "#1; bsign v" DSI_BSIGN_VERSION "\n"
#define DSI_BSIGN_GREET_SIZE sizeof(DSI_BSIGN_STRING)-1
#define DSI_BSIGN_HASH       20	/* sha1 hash */
#define DSI_BSIGN_LEN_OFFSET 2	/* length of digsig added by bsign */
#define DSI_BSIGN_INFOS      DSI_BSIGN_GREET_SIZE+DSI_BSIGN_HASH+DSI_BSIGN_LEN_OFFSET

/* GPG .sig file/section structure:
 * 89     00 95 03          05      00    3F293CEB  
 * hdrlen       sig version md5 len class timestamp 
 * 
 * D39C2077 C307562E 01          02          29
 * keyid[0] keyid[1] pubkey algo digest algo digest start[0]
 * 
 * C2              03FF         Rest of .sig
 * digest start[1] nbits of MPI MPI (as read by mpi_read)
 */

#define DSI_RSA_CLASS_OFFSET     5
#define DSI_RSA_TIMESTAMP_OFFSET 6
#define DSI_RSA_DATA_OFFSET      22


/*ToDO: makan: this is a constraint, we suppose that the max size of a
  big integer is 1024 bytes. This needs to be modified in order to
  have a dynamic way of allocating memory. */

#define DSI_MPI_MAX_SIZE_N 1024
#define DSI_MPI_MAX_SIZE_E 128

/**
 * Supported algorithms
 */
#define HASH_SHA1 0
#define SIGN_RSA 0

typedef struct sig_ctx_st {
	struct crypto_tfm *tfm;
	struct scatterlist sg[1];
	int digestAlgo;
	int signAlgo;
	char *tvmem;
} SIGCTX;

extern int gDigestLength[1];

SIGCTX *dsi_sign_verify_init(int hashalgo, int signalgo);
int dsi_sign_verify_update(SIGCTX * ctx, char *buf, int buflen);
int dsi_sign_verify_final(SIGCTX * ctx, char *sig,
			  int siglen /* PublicKey */ ,
			  unsigned char *signed_hash);
void dsi_sign_verify_free(void);
int dsi_init_pkey(const char read_par);



#endif
