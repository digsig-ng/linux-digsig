/*
 * Distributed Security Module (DSM)
 *
 * dsi_verify.c
 *
 * Copyright (C) 2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Authors: Axelle Apvrille
 *          David Gordon
 */

#include <linux/string.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/crypto.h>

#include "dsi.h"
#include "dsi_debug.h"
#include "gnupg/cipher/rsa-verify.h"
#include "dsi_sig_verify.h"


/*
 * Public key format: 2 MPIs
 * 2 bytes: length of 1st MPI (ie. 0x0400)
 * n bytes: MPI
 * 2 bytes: length of 2nd MPI (ie. 0x0006)
 * n bytes: MPI (ie. 0x29)
 */

unsigned char raw_public_key_n[] = {
  0x04, 0x00, 0xAC, 0x2F,  0x50, 0xF1, 0x96, 0x77,
  0x74, 0xE6, 0x04, 0x0B, 0x98, 0xCB, 0x18, 0xC6, 0xE6, 0xE5, 0xE5, 0x37, 0x2E, 0x62, 0x5A, 0xBE,
  0x35, 0x4A, 0xD7, 0x07, 0x59, 0xBF, 0xAF, 0x92, 0xB5, 0x1B, 0x45, 0xE7, 0x62, 0x58, 0xD2, 0xF4,
  0x5A, 0xD5, 0xBC, 0xC3, 0xC5, 0x59, 0x80, 0x06, 0xFC, 0xD5, 0xA9, 0xAF, 0xFB, 0xC0, 0x95, 0xE9,
  0x75, 0x99, 0x64, 0xDA, 0x37, 0x72, 0xC7, 0x95, 0xBA, 0x00, 0xB4, 0xBF, 0x11, 0x54, 0xF0, 0x76,
  0x2A, 0x32, 0x60, 0x2A, 0x72, 0xFF, 0x1E, 0x81, 0x87, 0x38, 0x25, 0x6A, 0xC0, 0x71, 0xFE, 0x57,
  0x31, 0xE0, 0x9C, 0x0B, 0xA0, 0xB7, 0xD0, 0xEA, 0x71, 0xBC, 0x7A, 0xA5, 0xED, 0xBC, 0xB8, 0x31,
  0x04, 0x9A, 0x96, 0x98, 0xA9, 0xBA, 0xE6, 0x21, 0xC6, 0x7C, 0x4D, 0x22, 0xBF, 0xB0, 0xC5, 0x78,
  0x93, 0x11, 0xA8, 0xD5, 0x38, 0x43, 0x34, 0xD7, 0x6E, 0x95};

unsigned char raw_public_key_e[] = {0x00, 0x06, 0x29};


extern int DSIDebugLevel;

#define TVMEMSIZE	4096

int gDigestLength[] = { /* SHA-1 */ 0x14 };
static struct crypto_tfm *SHA1_TFM = NULL;
static MPI dsi_public_key[2];


/******************************************************************************
                             Internal functions 
******************************************************************************/

static int
internal_rsa_bsign_verify(unsigned char *sha_cat, int length, unsigned char *signed_hash);

static int 
internal_sha1_init(SIGCTX *ctx);

static void 
internal_sha1_update(SIGCTX *ctx, char *buf, int buflen);

static int
internal_sha1_final(SIGCTX *ctx, char *digest);


/******************************************************************************
Description : 
Parameters  : 
  hashalgo the identifier of the hash algorithm to use (HASH_SHA1 for instance)
  signalgo sign algorithm identifier. Ex. SIGN_RSA
Return value: a signature context valid for this signature only
******************************************************************************/

static spinlock_t dsi_crypto_alloc_lock = SPIN_LOCK_UNLOCKED;

SIGCTX *dsi_sign_verify_init(int hashalgo, int signalgo)
{
  SIGCTX *ctx;
  unsigned long flags;

  /* allocating signature context */
  spin_lock_irqsave(&dsi_crypto_alloc_lock, flags);
  ctx = (SIGCTX *)kmalloc(sizeof(SIGCTX),GFP_KERNEL);
  spin_unlock_irqrestore(&dsi_crypto_alloc_lock, flags);

  if (ctx == NULL){
    DSM_ERROR("Cannot allocate ctx\n");
    return NULL;
  }

  spin_lock_irqsave(&dsi_crypto_alloc_lock, flags);
  ctx->tvmem = kmalloc(TVMEMSIZE, GFP_KERNEL);
  spin_unlock_irqrestore(&dsi_crypto_alloc_lock, flags);

  if (ctx->tvmem == NULL) {
    kfree(ctx);
    DSM_ERROR("Cannot allocate plaintext buffer\n");
    return NULL;
  }

  /* checking hash algorithm is known */
  switch (hashalgo) {
  case HASH_SHA1:
    if (internal_sha1_init(ctx)) {
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
int
dsi_sign_verify_update(SIGCTX *ctx, char *buf, int buflen)
{
  switch (ctx->digestAlgo) {
  case HASH_SHA1:
    if (ctx == NULL)
      return -1;

    internal_sha1_update(ctx, buf, buflen);
    break;
  default:
    DSM_ERROR("dsi_sign_verify_update Unknown hash algo\n");
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
dsi_sign_verify_final(SIGCTX *ctx, char *sig, int siglen /* PublicKey */, unsigned char *signed_hash )
{
  char digest[gDigestLength[ctx->digestAlgo]];
  int rc = -1;

  /* TO DO: check the length of the signature: it should be equal to the length
     of the modulus */

  if ((rc = internal_sha1_final(ctx, digest)) < 0) {
    DSM_ERROR("dsi_sign_verify_final Cannot finalize hash algorithm\n");
    return rc;
  }

  if (siglen < gDigestLength[ctx->digestAlgo])
    return -2;
  memcpy(sig,digest,gDigestLength[ctx->digestAlgo]);

  switch (ctx->digestAlgo) {
  case SIGN_RSA:
    rc = internal_rsa_bsign_verify(digest, gDigestLength[ctx->digestAlgo], signed_hash);
    break;
  default:
    DSM_ERROR("Unsupported cipher algorithm in binary digital signature verification\n");
  }

  /* free everything */
  /* do not free SHA1-TFM. For optimization, we choose always to use the same one */
  kfree(ctx->tvmem);
  kfree(ctx);
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

void
dsi_init_pkey()
{
  int nread;

  nread = DSI_ELF_SIG_SIZE;
  dsi_public_key[0] = mpi_read_from_buffer(raw_public_key_n, &nread, 0);

  nread = DSI_ELF_SIG_SIZE;
  dsi_public_key[1] = mpi_read_from_buffer(raw_public_key_e, &nread, 0);
}

/******************************************************************************
Description : 
   Performs RSA verification of signature contained in binary
Parameters  : 
Return value: 0 - RSA signature is valid
              1 - RSA signature is invalid
              -1 - an error occured
******************************************************************************/

int internal_rsa_bsign_verify(unsigned char *hash_format, int length, unsigned char *signed_hash)
{
  int rc = 0;
  MPI hash, data;
  unsigned nread = DSI_ELF_SIG_SIZE;
  int nframe;
  unsigned char sig_class;
  unsigned char sig_timestamp[SIZEOF_UNSIGNED_INT];
  unsigned long flags;
  int i;
  SIGCTX *ctx = NULL;
  unsigned char new_sig[gDigestLength[HASH_SHA1]];

  /* Get MPI of signed data from .sig file/section */
  nread = DSI_ELF_SIG_SIZE;

  data = mpi_read_from_buffer(signed_hash+DSI_RSA_DATA_OFFSET, &nread, 0);

  /* Get MPI for hash */
  /* bsign modif - file hash - gpg modif */
  /* bsign modif: add bsign greet at beginning */
  /* gpg modif:   add class and timestamp at end */

  spin_lock_irqsave(&dsi_crypto_alloc_lock, flags);
  ctx = (SIGCTX *)kmalloc(sizeof(SIGCTX),GFP_KERNEL);
  spin_unlock_irqrestore(&dsi_crypto_alloc_lock, flags);

  if (ctx == NULL){
    DSM_ERROR("Cannot allocate ctx\n");
    return -1;
  }

  spin_lock_irqsave(&dsi_crypto_alloc_lock, flags);
  ctx->tvmem = kmalloc(TVMEMSIZE, GFP_KERNEL);
  spin_unlock_irqrestore(&dsi_crypto_alloc_lock, flags);

  if (ctx->tvmem == NULL) {
    kfree(ctx);
    DSM_ERROR("Cannot allocate plaintext buffer\n");
    return -1;
  }

  internal_sha1_init(ctx);

  sig_class = signed_hash[DSI_RSA_CLASS_OFFSET];
  sig_class &= 0xff;

  for (i = 0; i < SIZEOF_UNSIGNED_INT; i++) {
    sig_timestamp[i] = signed_hash[DSI_RSA_TIMESTAMP_OFFSET + i] & 0xff;
  }

  if (ctx == NULL)
    return -1;

  internal_sha1_update(ctx, DSI_BSIGN_STRING, DSI_BSIGN_GREET_SIZE);
  internal_sha1_update(ctx, hash_format, SHA1_DIGEST_LENGTH);
  internal_sha1_update(ctx, &sig_class, 1);
  internal_sha1_update(ctx, sig_timestamp, SIZEOF_UNSIGNED_INT);

  if ((rc = internal_sha1_final(ctx, new_sig)) < 0) {
    DSM_ERROR("internal_rsa_verify_final Cannot finalize hash algorithm\n");
    return rc;
  }

  nframe = mpi_get_nbits(dsi_public_key[0]);
  hash = do_encode_md(new_sig, nframe);

  if (hash == MPI_NULL) {
    DSM_PRINT(DEBUG_SIGN, "mpi creation failed\\n");
  }

  /* Do RSA verification */
  rc = rsa_verify(hash, &data, dsi_public_key);

  m_free(hash);
  m_free(data);

  return rc;
}


/******************************************************************************
Description : 
   initialisation of hash with sha1
Parameters  : 
Return value: 0 for successful allocation, -1 for failed
******************************************************************************/

static int 
internal_sha1_init(SIGCTX *ctx)
{
  if (ctx == NULL)
    return -1;

  if (SHA1_TFM == NULL)
    SHA1_TFM = crypto_alloc_tfm("sha1",0);
  ctx->tfm = SHA1_TFM;
  if (ctx->tfm == NULL) {
    DSM_ERROR("tfm allocation failed\n");
    return -1;
  }

  crypto_digest_init(ctx->tfm);
  return 0;
}


/******************************************************************************
Description : 
Parameters  : 
Return value:
******************************************************************************/

static void 
internal_sha1_update(SIGCTX *ctx, char *buf, int buflen)
{
  char *plaintext;

  memcpy(ctx->tvmem, buf, buflen);
  plaintext = (void *)ctx->tvmem;

  ctx->sg[0].page = virt_to_page(plaintext);
  ctx->sg[0].offset = ((long) plaintext & ~PAGE_MASK);
  ctx->sg[0].length = buflen;

  crypto_digest_update(ctx->tfm,ctx->sg,1);
}

/******************************************************************************
Description : 
Parameters  : 
Return value:
******************************************************************************/

static int
internal_sha1_final(SIGCTX *ctx, char *digest)
{
  /* TO DO: check the length of the signature: it should be equal to the length
     of the modulus */

  if (ctx == NULL)
    return -1;

  crypto_digest_final(ctx->tfm, digest);
  return 0;
}
