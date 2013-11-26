/*
 * Digital Signature (DigSig)
 *
 * pkcs1.c
 *
 * This file contains the PKCS#1 encoding for RSA signature verification
 * 
 * Copyright (C) 2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Author: Axelle Apvrille <axelle.apvrille@ericsson.ca>
 *        
 */

#include "dsi_pkcs1.h"
#include "dsi_sig_verify.h"	/* for definition of HASH_SHA1 */

struct hashinfo_st {
	int hash_len;		/* expected length of a hash of a given algorithm */
	int digestinfo_len;	/* length of the hardcoded part of the DigestInfo for that algo */
	char digestinfo[20];	/* hard coded DigestInfo for the algo. May be less than 20 bytes */
};

/* internal variable containing hardcoded parts for DigestInfo value of given algorithms */
static struct hashinfo_st gDigestAlgInfo[] = {
	{20, 15,
	 {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
	  0x05,
	  0x00, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00}}
};

/**
 * Performs PKCS1v1.5 padding (see PKCS#1v2.1 "RSA Cryptography Standard" June 14,2002, pp 37-38).
 * The only difference is that we expect input to be already hashed.
 *
 *    DigestInfo ::= SEQUENCE {
 *      digestAlgorithm AlgorithmIdentifier,
 *      digest OCTET STRING
 *    }
 *
 * @param out the buffer that will receive the padded data. This buffer should be allocated.
 * @param outlen size of the out buffer.
 * @param hashed the hash of the initial text.
 * @param hashalgo the identifier of the hash algo used to perform the hash.
 */
void
EMSA_PKCS1_V1_5_encode(char *out, int outlen, char *hashed, int hashalgo)
{
	int tlen =
		gDigestAlgInfo[hashalgo].digestinfo_len +
		gDigestAlgInfo[hashalgo].hash_len;
	if (outlen < tlen + 11) {
		return;
	}

	/* expected format is : 0x00 0x01 <--- 0xff ---> 0x00 DigestInfo in DER Hash */
	out[0] = 0x00;
	out[1] = 0x01;
	memset(out + 2, 0xff, outlen - tlen - 3);
	out[outlen - tlen - 1] = 0x00;
	memcpy(out + outlen - tlen, gDigestAlgInfo[hashalgo].digestinfo,
	       gDigestAlgInfo[hashalgo].digestinfo_len);
	memcpy(out + outlen - gDigestAlgInfo[hashalgo].hash_len, hashed,
	       gDigestAlgInfo[hashalgo].hash_len);
}
