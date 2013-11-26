/*
 * Distributed Security Module (DSM)
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
 *          AA - Sep 2003 - for integration with LTM
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/crypto.h>

#include "dsi.h"
#include "dsi_debug.h"
#include "dsi_sig_verify.h"
#include "ltm/tommath.h"	/* LTM */
#include "dsi_pkcs1.h"
#include "dsi_ltm_rsa.h"


extern int DigsigDebugLevel;
mp_int dsi_public_key[2];

/******************************************************************************
                             Local data
******************************************************************************/

unsigned char *raw_public_key_n = NULL;
unsigned char *raw_public_key_e = NULL;
int dsi_mpi_size_n = 0;
int dsi_mpi_size_e = 0;

int gDigestLength[] = { /* SHA-1 */ 0x14 };
static struct crypto_tfm *SHA1_TFM = NULL;

#define TVMEMSIZE	          4096
#define DIGSIG_MODULUS_INDEX         0
#define DIGSIG_PUBLIC_EXPONENT_INDEX 1

/*
 * When using MPIs (GnuPG) format of MPIs are :
 * 2 bytes: length of 1st MPI (ie. 0x0400)
 * n bytes: MPI
 * 2 bytes: length of 2nd MPI (ie. 0x0006)
 * n bytes: MPI (ie. 0x29)
 *
 * When using mp_ints (LTM) format is:
 * n bytes: mp_int
 * n bytes: mp_int
 */


/******************************************************************************
                             Internal functions 
******************************************************************************/

static int dsi_rsa_bsign_verify(unsigned char *sha_cat, int length,
				unsigned char *signed_hash);

static int dsi_sha1_init(SIGCTX * ctx);

static void dsi_sha1_update(SIGCTX * ctx, char *buf, int buflen);

static int dsi_sha1_final(SIGCTX * ctx, char *digest);


/******************************************************************************
Description : 
Parameters  : 
  hashalgo the identifier of the hash algorithm to use (HASH_SHA1 for instance)
  signalgo sign algorithm identifier. Ex. SIGN_RSA
Return value: a signature context valid for this signature only
******************************************************************************/

SIGCTX *dsi_sign_verify_init(int hashalgo, int signalgo)
{
	SIGCTX *ctx;

	/* allocating signature context */
	ctx = (SIGCTX *) kmalloc(sizeof(SIGCTX), GFP_KERNEL);
	if (ctx == NULL) {
		DSM_ERROR("dsi_sign_verify_init(): cannot allocate ctx\n");
		return NULL;
	}

	ctx->tvmem = kmalloc(TVMEMSIZE, GFP_KERNEL);
	if (ctx->tvmem == NULL) {
		kfree(ctx);
		DSM_ERROR
		    ("dsi_sign_verify_init(): Cannot allocate plaintext buffer\n");
		return NULL;
	}

	/* checking hash algorithm is known */
	switch (hashalgo) {
	case HASH_SHA1:
		if (dsi_sha1_init(ctx)) {
			DSM_ERROR("Initializing SHA1 failed\n");
			kfree(ctx->tvmem);
			kfree(ctx);
			return NULL;
		}
		break;
	default:
		DSM_ERROR("Unknown hash algo\n");
		kfree(ctx->tvmem);
		kfree(ctx);
		return NULL;
	}

	/* checking sign algo is known */
	switch (signalgo) {
	case SIGN_RSA:
		break;
	default:
		DSM_ERROR("Unknown sign algo\n");
		kfree(ctx->tvmem);
		kfree(ctx);
		return NULL;
	}

	ctx->digestAlgo = hashalgo;
	ctx->signAlgo = signalgo;
	return ctx;
}

/******************************************************************************
Description : 
Parameters  : 
  ctx
  buf data to sign (part of a bigger buffer)
  buflen length of buf
Return value: 0 normally
******************************************************************************/
int dsi_sign_verify_update(SIGCTX * ctx, char *buf, int buflen)
{
	switch (ctx->digestAlgo) {
	case HASH_SHA1:
		if (ctx == NULL)
			return -1;

		dsi_sha1_update(ctx, buf, buflen);
		break;
	default:
		DSM_ERROR("dsi_sign_verify_update(): Unknown hash algo\n");
		return -1;
	}

	return 0;
}

/******************************************************************************
Description : This is where the RSA signature verification actually takes place
Parameters  : 
Return value: 
******************************************************************************/
int
dsi_sign_verify_final(SIGCTX * ctx, char *sig, int siglen /* PublicKey */ ,
		      unsigned char *signed_hash)
{
	char *digest;
	int rc = -1;

	digest = kmalloc (gDigestLength[ctx->digestAlgo], DIGSIG_SAFE_ALLOC);
	if (!digest) {
		DSM_ERROR ("kmalloc failed in dsi_sign_verify_final for digest\n");
		return -ENOMEM;
	}
	/* TO DO: check the length of the signature: it should be equal to the length
	   of the modulus */

	if ((rc = dsi_sha1_final(ctx, digest)) < 0) {
		DSM_ERROR
		    ("dsi_sign_verify_final(): Cannot finalize hash algorithm\n");
		kfree(ctx->tvmem);
		kfree(ctx);
		kfree (digest);
		return rc;
	}

	if (siglen < gDigestLength[ctx->digestAlgo]) {
		DSM_ERROR ("dsi_sign_verify_final siglen < gDigestLenght\n");
		kfree(ctx->tvmem);
		kfree(ctx);
		kfree (digest);
		return -2;
	}
	memcpy(sig, digest, gDigestLength[ctx->digestAlgo]);

	switch (ctx->digestAlgo) {
	case SIGN_RSA:
		rc = dsi_rsa_bsign_verify(digest,
					  gDigestLength[ctx->digestAlgo],
					  signed_hash);
		break;
	default:
		DSM_ERROR
		    ("Unsupported cipher algorithm in binary digital signature verification\n");
	}

	/* free everything */
	/* do not free SHA1-TFM. For optimization, we choose always to use the same one */
	kfree(ctx->tvmem);
	kfree(ctx);
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
void dsi_sign_verify_free()
{
	if (SHA1_TFM) {
		crypto_free_tfm(SHA1_TFM);
		SHA1_TFM = NULL;
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

int dsi_init_pkey(const char read_par)
{
	switch (read_par) {

	case 'n':
		DSM_PRINT(DEBUG_SIGN,
			  "Reading raw_public_key_n (%d bytes)!\n",
			  dsi_mpi_size_n);
		mp_read_unsigned_bin(&dsi_public_key[DIGSIG_MODULUS_INDEX],
				     raw_public_key_n, dsi_mpi_size_n);
		break;
	case 'e':
		DSM_PRINT(DEBUG_SIGN,
			  "Reading raw_public_key_e (%d bytes)!\n",
			  dsi_mpi_size_e);
		mp_read_unsigned_bin(&dsi_public_key
				     [DIGSIG_PUBLIC_EXPONENT_INDEX],
				     raw_public_key_e, dsi_mpi_size_e);
		break;
	}

	return 0;
}

/******************************************************************************
Description : 
   Performs RSA verification of signature contained in binary
Parameters  : 
   hash-format : 
   length      : expected length of a hash
   signed-hash : signature contained in the binary
Return value: 0 - RSA signature is valid
              1 - RSA signature is invalid
              -1 - an error occured
******************************************************************************/

int
dsi_rsa_bsign_verify(unsigned char *hash_format, int length,
		     unsigned char *signed_hash)
{
	int rc = 0;
	mp_int hash, data;
	unsigned nread = DIGSIG_ELF_SIG_SIZE;
	int nframe;
	unsigned char sig_class;
	unsigned char sig_timestamp[SIZEOF_UNSIGNED_INT];
	int i;
	SIGCTX *ctx = NULL; 
	unsigned char *new_sig;
	extern unsigned char *packed;

	/* initialize */
	mp_init(&hash);
	mp_init(&data);

	new_sig = kmalloc (gDigestLength[HASH_SHA1], DIGSIG_SAFE_ALLOC);
	if (!new_sig) {
		DSM_ERROR ("kmalloc failed in dsi_rsa_bsign_verify for new_sig\n");
		return -ENOMEM;
	}
	/* The signature contained in a Bsign executable is actually a MPI.
	   As MPIs (GnuPG) start with their length in bits (2 bytes), we retrieve first
	   the length of the MPI, and then read the content
	 */
	nread = *(signed_hash + DIGSIG_RSA_DATA_OFFSET) << 8;
	nread |= *(signed_hash + DIGSIG_RSA_DATA_OFFSET + 1);
	nread = (nread + 7) / 8;	/* round up operation */

	if (nread < 0 || nread > DIGSIG_ELF_SIG_SIZE) {
		DSM_ERROR
		    ("dsi_rsa_bsign_verify(): cannot retrieve signed data size: nread=%d\n",
		     nread);
		DSM_PRINT(DEBUG_SIGN, "Length: %x %x\n",
			  *(signed_hash + DIGSIG_RSA_DATA_OFFSET),
			  *(signed_hash + DIGSIG_RSA_DATA_OFFSET + 1));
		kfree (new_sig);
		return -1;
	}

	DSM_PRINT(DEBUG_SIGN,
		  "reading signed data from signed binary (%d bytes)\n",
		  nread);
	if (mp_read_unsigned_bin
	    (&data, signed_hash + DIGSIG_RSA_DATA_OFFSET + 2,
	     nread) != MP_OKAY) {
		DSM_ERROR
		    ("dsi_rsa_bsign_verify(): cannot read signed data\n");
		kfree (new_sig);
		return -1;
	}


	/* Get mp_int for hash */
	/* bsign modif - file hash - gpg modif */
	/* bsign modif: add bsign greet at beginning */
	/* gpg modif:   add class and timestamp at end */
	/* TO DO: use the algorithm specified by signed data */
	ctx = dsi_sign_verify_init(HASH_SHA1, SIGN_RSA);
	if (ctx == NULL) {
		kfree (new_sig);
		return -1;
	}

	sig_class = signed_hash[DIGSIG_RSA_CLASS_OFFSET];
	sig_class &= 0xff;

	for (i = 0; i < SIZEOF_UNSIGNED_INT; i++) {
		sig_timestamp[i] =
		    signed_hash[DIGSIG_RSA_TIMESTAMP_OFFSET + i] & 0xff;
	}

	dsi_sign_verify_update(ctx, DIGSIG_BSIGN_STRING,
			       DIGSIG_BSIGN_GREET_SIZE);
	dsi_sign_verify_update(ctx, hash_format, SHA1_DIGEST_LENGTH);
	dsi_sign_verify_update(ctx, &sig_class, 1);
	dsi_sign_verify_update(ctx, sig_timestamp, SIZEOF_UNSIGNED_INT);

	/*
	   Beware: do not call dsi_sign_verify_final or we'll loop ! 
	   after this step, new_sig contains the hash of the binary
	 */
	if ((rc = dsi_sha1_final(ctx, new_sig)) < 0) {
		DSM_ERROR
		    ("dsi_rsa_bsign_verify(): cannot finalize hash algorithm\n");
		kfree (new_sig);
		return rc;
	}

	/* Perform PKCSv1.5 encoding */
	nframe = mp_unsigned_bin_size(&dsi_public_key[0]);	/* size in bytes */
	DSM_PRINT(DEBUG_SIGN, "Performing PKCSv1.5 encoding (size=%d)\n",
		  nframe);

	EMSA_PKCS1_V1_5_encode(&packed[0], nframe, &new_sig[0], HASH_SHA1);
	if (mp_read_unsigned_bin(&hash, &packed[0], nframe) != MP_OKAY) {
		DSM_ERROR
		    ("dsi_rsa_bsign_verify(): cannot convert packed to mp_int\n");
		kfree (new_sig);
		return -1;
	}

	/* Do RSA verification */
	DSM_PRINT(DEBUG_SIGN, "Verifying the signature\n");
	rc = dsi_ltm_rsa_verify(&hash, &data,
				&dsi_public_key[DIGSIG_PUBLIC_EXPONENT_INDEX],
				&dsi_public_key[DIGSIG_MODULUS_INDEX]);

	mp_clear(&hash);
	mp_clear(&data);
	kfree (new_sig);
	return rc;
}


/******************************************************************************
Description : 
   initialisation of hash with sha1
Parameters  : 
Return value: 0 for successful allocation, -1 for failed
******************************************************************************/

static int dsi_sha1_init(SIGCTX * ctx)
{
	if (ctx == NULL)
		return -1;

	if (SHA1_TFM == NULL)
		SHA1_TFM = crypto_alloc_tfm("sha1", 0);

	ctx->tfm = SHA1_TFM;
	if (ctx->tfm == NULL) {
		DSM_ERROR("dsi_sha1_int(): SHA1_TFM allocation failed\n");
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

static void dsi_sha1_update(SIGCTX * ctx, char *buf, int buflen)
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
Return value: 0 for successful allocation, -1 for failed
******************************************************************************/

static int dsi_sha1_final(SIGCTX * ctx, char *digest)
{
	/* TO DO: check the length of the signature: it should be equal to the length
	   of the modulus */

	if (ctx == NULL)
		return -1;

	crypto_digest_final(ctx->tfm, digest);
	return 0;
}
