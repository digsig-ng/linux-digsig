/*
 * Digital Signature (DigSig)
 *
 * dsi_sig_verify.c
 *
 * Copyright (C) 2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Authors: Axelle Apvrille
 *          David Gordon Aug 2003 
 * modifs:  Makan Pourzandi Sep 2003 
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/crypto.h>

#include "dsi.h"
#include "dsi_debug.h"
#include "dsi_sig_verify.h"
#include "gnupg/cipher/rsa-verify.h"

/*
 * Public key format: 2 MPIs
 * 2 bytes: length of 1st MPI (ie. 0x0400)
 * n bytes: MPI
 * 2 bytes: length of 2nd MPI (ie. 0x0006)
 * n bytes: MPI (ie. 0x29)
 */

#define TVMEMSIZE	4096

int gDigestLength[] = { /* SHA-1 */ 0x14 };
static struct crypto_tfm *sha1_tfm;
MPI digsig_public_key[] = {MPI_NULL, MPI_NULL};


/******************************************************************************
                             Internal functions 
******************************************************************************/

static int
digsig_rsa_bsign_verify(unsigned char *sha_cat, int length,
		     unsigned char *signed_hash);

static int digsig_sha1_init(SIGCTX * ctx);

static void digsig_sha1_update(SIGCTX * ctx, char *buf, int buflen);

static int digsig_sha1_final(SIGCTX * ctx, char *digest);


/******************************************************************************
Description : 
Parameters  : 
  hashalgo the identifier of the hash algorithm to use (HASH_SHA1 for instance)
  signalgo sign algorithm identifier. Ex. SIGN_RSA
Return value: a signature context valid for this signature only
******************************************************************************/

SIGCTX *digsig_sign_verify_init(int hashalgo, int signalgo)
{
	SIGCTX *ctx;

	/* allocating signature context */
	ctx = kmalloc(sizeof(SIGCTX), GFP_KERNEL);
	if (!ctx) {
		DSM_ERROR("Cannot allocate ctx\n");
		goto err;
	}

	ctx->tvmem = kmalloc(TVMEMSIZE, GFP_KERNEL);
	if (!ctx->tvmem) {
		DSM_ERROR("Cannot allocate plaintext buffer\n");
		goto err;
	}

	/* checking hash algorithm is known */
	switch (hashalgo) {
	case HASH_SHA1:
		if (digsig_sha1_init(ctx)) {
			DSM_ERROR("Initializing SHA1 failed\n");
			goto err;
		}
		break;
	default:
		DSM_ERROR("Unknown hash algo\n");
		goto err;
	}

	/* checking sign algo is known */
	switch (signalgo) {
	case SIGN_RSA:
		break;
	default:
		DSM_ERROR("Unknown sign algo\n");
		goto err;
	}
	ctx->digestAlgo = hashalgo;
	ctx->signAlgo = signalgo;
	return ctx;

err:
	if (ctx) {
		kfree(ctx->tvmem);
		kfree(ctx);
	}
	return NULL;
}

/******************************************************************************
Description : 
Parameters  : 
  ctx
  buf data to sign (part of a bigger buffer)
  buflen length of buf
Return value: 0 normally
******************************************************************************/
int digsig_sign_verify_update(SIGCTX * ctx, char *buf, int buflen)
{
	if (ctx == NULL)
		return -EINVAL;

	switch (ctx->digestAlgo) {
	case HASH_SHA1:
		digsig_sha1_update(ctx, buf, buflen);
		break;
	default:
		DSM_ERROR("%s: Unknown hash algo\n", __FUNCTION__);
		return -EINVAL;
	}

	return 0;
}

/******************************************************************************
Description : This is where the RSA signature verification actually takes place
Parameters  : 
Return value: 
******************************************************************************/
int
digsig_sign_verify_final(SIGCTX * ctx, char *sig, int siglen /* PublicKey */ ,
		      unsigned char *signed_hash)
{
	char *digest;
	int rc = -ENOMEM;

	digest = kmalloc (gDigestLength[ctx->digestAlgo], DIGSIG_SAFE_ALLOC);
	if (!digest) {
		DSM_ERROR ("kmalloc failed in %s for digest\n", __FUNCTION__);
		goto err;
	}
	/* TO DO: check the length of the signature: it should be equal to the length
	   of the modulus */
	if ((rc = digsig_sha1_final(ctx, digest)) < 0) {
		DSM_ERROR
		    ("%s: Cannot finalize hash algorithm\n", __FUNCTION__);
		goto err;
	}

	rc = -EINVAL;
	if (siglen < gDigestLength[ctx->digestAlgo])
		goto err;
	memcpy(sig, digest, gDigestLength[ctx->digestAlgo]);

	switch (ctx->digestAlgo) {
	case SIGN_RSA:
		rc = digsig_rsa_bsign_verify(digest,
					  gDigestLength[ctx->digestAlgo],
					  signed_hash);
		break;
	default:
		DSM_ERROR
		    ("Unsupported cipher algorithm in binary digital signature verification\n");
	}

	/* free everything */
	/* do not free SHA1-TFM. For optimization, we choose always to use the same one */
err:
	kfree (digest);
	return rc;
}

/******************************************************************************
Description : 
   Call this only at the end of the whole program when you do not want to use 
   signature verification again.
Parameters  : 
Return value: 
******************************************************************************/
void digsig_sign_verify_free(void)
{
	if (sha1_tfm) {
		crypto_free_tfm(sha1_tfm);
		sha1_tfm = NULL;
	}
	/* this might cause unpredictable behavior if structures are refering to this,
	   their pointer might suddenly become NULL, might need a usage count associated */
}

/******************************************************************************
Description : 
   Initialize public key
Parameters  : 
Return value:
******************************************************************************/

int digsig_init_pkey(const char read_par, unsigned char *raw_public_key, int mpi_size)
{
	int nread;

	switch (read_par) {

	case 'n':
		DSM_PRINT(DEBUG_SIGN, "Reading raw_public_key_n!\n");
		nread = mpi_size;
		digsig_public_key[0] =
			mpi_read_from_buffer(raw_public_key, &nread, 0);
		break;
	case 'e':
		DSM_PRINT(DEBUG_SIGN, "Reading raw_public_key_e!\n");
		nread = mpi_size;
		digsig_public_key[1] =
			mpi_read_from_buffer(raw_public_key, &nread, 0);
		break;
	}

	return 0;
}

/******************************************************************************
Description : 
   Performs RSA verification of signature contained in binary
Parameters  : 
Return value: 0 - RSA signature is valid
              1 - RSA signature is invalid
              -1 - an error occured
******************************************************************************/

static int digsig_rsa_bsign_verify(unsigned char *hash_format, int length,
			 unsigned char *signed_hash)
{
	int rc = 0;
	MPI hash, data;
	unsigned nread = DIGSIG_ELF_SIG_SIZE;
	int nframe;
	unsigned char sig_class;
	unsigned char sig_timestamp[SIZEOF_UNSIGNED_INT];
	int i;
	SIGCTX *ctx = NULL;
	unsigned char *new_sig;

	new_sig = kmalloc(gDigestLength[HASH_SHA1], DIGSIG_SAFE_ALLOC);
	if (!new_sig) {
		DSM_ERROR ("kmalloc failed in %s for new_sig\n", __FUNCTION__);
		return -ENOMEM;
	}

	/* Get MPI of signed data from .sig file/section */
	nread = DIGSIG_ELF_SIG_SIZE;

	data = mpi_read_from_buffer(signed_hash + DIGSIG_RSA_DATA_OFFSET, 
				    &nread, 0);
	if (!data) {
		kfree(new_sig);
		return -EINVAL;
	}

	/* Get MPI for hash */
	/* bsign modif - file hash - gpg modif */
	/* bsign modif: add bsign greet at beginning */
	/* gpg modif:   add class and timestamp at end */

	ctx = kmalloc(sizeof(SIGCTX), GFP_KERNEL);
	if (!ctx) {
		DSM_ERROR("Cannot allocate ctx\n");
		mpi_free (data);
		kfree (new_sig);
		return -ENOMEM;
	}

	ctx->tvmem = kmalloc(TVMEMSIZE, GFP_KERNEL);
	if (!ctx->tvmem) {
		kfree (ctx);
		mpi_free(data);
		kfree (new_sig);
		DSM_ERROR("Cannot allocate plaintext buffer\n");
		return -ENOMEM;
	}

	digsig_sha1_init(ctx);

	sig_class = signed_hash[DIGSIG_RSA_CLASS_OFFSET];
	sig_class &= 0xff;

	for (i = 0; i < SIZEOF_UNSIGNED_INT; i++) {
		sig_timestamp[i] =
		    signed_hash[DIGSIG_RSA_TIMESTAMP_OFFSET + i] & 0xff;
	}

	digsig_sha1_update(ctx, DIGSIG_BSIGN_STRING, DIGSIG_BSIGN_GREET_SIZE);
	digsig_sha1_update(ctx, hash_format, SHA1_DIGEST_LENGTH);
	digsig_sha1_update(ctx, &sig_class, 1);
	digsig_sha1_update(ctx, sig_timestamp, SIZEOF_UNSIGNED_INT);

	if ((rc = digsig_sha1_final(ctx, new_sig)) < 0) {
		DSM_ERROR
		    ("internal_rsa_verify_final Cannot finalize hash algorithm\n");
		mpi_free(data);
		kfree(ctx->tvmem);
		kfree(ctx);
		return rc;
	}

	nframe = mpi_get_nbits(digsig_public_key[0]);
	hash = do_encode_md(new_sig, nframe);

	if (hash == MPI_NULL) {
		DSM_PRINT(DEBUG_SIGN, "mpi creation failed\\n");
	}

	/* Do RSA verification */
	rc = rsa_verify(hash, &data, digsig_public_key);

	mpi_free(hash);
	mpi_free(data);
	kfree(ctx->tvmem);
	kfree(ctx);
	kfree (new_sig);
	return rc;
}


/******************************************************************************
Description : 
   initialisation of hash with sha1
Parameters  : 
Return value: 0 for successful allocation, -1 for failed
******************************************************************************/

static int digsig_sha1_init(SIGCTX * ctx)
{
	if (ctx == NULL)
		return -1;

	if (sha1_tfm == NULL)
		sha1_tfm = crypto_alloc_tfm("sha1", 0);
	ctx->tfm = sha1_tfm;
	if (ctx->tfm == NULL) {
		DSM_ERROR("tfm allocation failed\n");
		return -1;
	}

	crypto_digest_init(ctx->tfm);
	return 0;
}


/******************************************************************************
Description : Portability layer function. 
Parameters  : 
Return value: void. 
******************************************************************************/

static void digsig_sha1_update(SIGCTX * ctx, char *buf, int buflen)
{
	char *plaintext;

	memcpy(ctx->tvmem, buf, buflen);
	plaintext = (void *) ctx->tvmem;

	ctx->sg[0].page = virt_to_page(plaintext);
	ctx->sg[0].offset = ((long) plaintext & ~PAGE_MASK);
	ctx->sg[0].length = buflen;

	crypto_digest_update(ctx->tfm, ctx->sg, 1);
}

/******************************************************************************
Description : Portability layer function. 
Parameters  : 
Return value: 0 for successful allocation, -EINVAL for failed
******************************************************************************/

static int digsig_sha1_final(SIGCTX * ctx, char *digest)
{
	/* TO DO: check the length of the signature: it should be equal to the length
	   of the modulus */

	if (ctx == NULL)
		return -EINVAL;

	crypto_digest_final(ctx->tfm, digest);
	return 0;
}
