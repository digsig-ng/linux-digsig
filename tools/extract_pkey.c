/*
 * Distributed Security Module (DSM)
 *
 * Simple extractor of MPIs for e and n in gpg exported keys (or pubrings
 * with only one key apparently)
 * Exported keys come from gpg --export.
 * Output is meant to be copy pasted into kernel code until better mechanism.
 *	
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 * 
 * Author: David Gordon Aug 2003 
 * Modifs: Vincent Roy  Sep 2003 
 *         Chris Wright Sep 2004
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DIGSIG_ELF_SIG_SIZE 512               /* this is a redefinition */
#define DIGSIG_PKEY_N_OFFSET        8         /* offset for pkey->n */
#define DIGSIG_MPI_MAX_SIZE_N 1024 
/* pkey->e MPI follows pkey->n MPI */


void usage();


int main(int argc, char **argv)
{
	int pkey_file, module_file, i;
	unsigned int len;
	unsigned char c;
	unsigned char *key;
	unsigned char *temp;
	int key_offset = 0;

	if (argc <= 1)
		usage();

	/* Get pkey MPIs, one for 'n' and the other for 'e' */
	pkey_file = open(argv[1], O_RDONLY);
	if (!pkey_file) {
		printf ("Unable to open pkey_file %s %s\n", argv[1], strerror(errno));
		return -1;
	}
	module_file = open ("/sys/digsig/key", O_WRONLY);
	if (!module_file) {
		printf ("Unable to open module char device %s\n", strerror(errno));
		return -1;
	}
  
	key = (unsigned char *)malloc (DIGSIG_MPI_MAX_SIZE_N+1);
	key[key_offset++] = 'n';
	/*
	 * Format of an MPI:
	 * - 2 bytes: length of MPI in BITS
	 * - MPI
	 */

	lseek(pkey_file, DIGSIG_PKEY_N_OFFSET, SEEK_SET);
	read(pkey_file, &c, 1);
	key[key_offset++] = c;
	len = c << 8;

	read(pkey_file, &c, 1);
	key[key_offset++] = c;
	len |= c;
	len = (len + 7) / 8;   /* round up */

	if (len > DIGSIG_ELF_SIG_SIZE) {
		printf("\nLength of 'n' MPI is too large %#x\n", len);
		return -1;
	}

	for (i = 0; i < len; i++) {
		read(pkey_file, &c, 1);
		key[key_offset++] = c;
		if (key_offset == DIGSIG_MPI_MAX_SIZE_N+2) {
			temp = (unsigned char *)malloc (DIGSIG_MPI_MAX_SIZE_N*2+1);
			memcpy (temp, key, key_offset-1);
			free (key);
			key = temp;
		}
	}
	/* 
	printf("pkey->n MPI:\n{ ");
	for (i = 0; i < key_offset; i++  ) {
		printf("%#x, ", key[i] & 0xff);
	}
	printf("}\n");
	*/ 
	if (write (module_file, key, key_offset) < 0) {
		printf ("Write problem %i %s\n", errno, strerror (errno));
		return -1;
	}

	key_offset = 0;
	key[key_offset++] = 'e';
	read(pkey_file, &c, 1);
	key[key_offset++] = c;
	len = c << 8;

	read(pkey_file, &c, 1);
	key[key_offset++] = c;
	len |= c;
	len = (len + 7) / 8;   /* round up */

	if (len > DIGSIG_ELF_SIG_SIZE) {
		printf("\nLength of 'e' MPI is too large %#x\n", len);
		return -1;
	}

	for (i = 0; i < len; i++) {
		read(pkey_file, &c, 1);
		key[key_offset++] = c;
	}

	/* 
	printf("pkey->n MPI:\n{ ");
	for (i = 0; i < key_offset; i++  ) {
		printf("%#x, ", key[i] & 0xff);
	}
	printf("}\n");
	*/ 
	if (write (module_file, key, key_offset) < 0) {
		printf ("Write problem %i %s\n", errno, strerror (errno));
		return -1;
	}

	return 0;
}


void usage() 
{
	printf("Usage: extract_pkey gpgkey\nYou can export a key with gpg --export\n");
}


