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
 *         Axelle Apvrille Feb 2005
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DIGSIG_ELF_SIG_SIZE       512               /* this is a redefinition */
#define DIGSIG_PKEY_N_OFFSET        8               /* offset for pkey->n */
#define DIGSIG_MPI_MAX_SIZE       512               /* maximum MPI size in BYTES */

/* Prototype definition */
void usage();
int check_pubkey(int pkey_file);
int getMPI(int pkey_file, int module_file, char tag);

/**
 * One argument expected: GPG public key file
 */
int main(int argc, char **argv)
{
  int pkey_file, module_file;

  int ret=-1;

  if (argc <= 1)
    usage();

  pkey_file = open(argv[1], O_RDONLY);
  if (pkey_file < 0) {
    printf ("Unable to open pkey_file %s %s\n", argv[1], strerror(errno));
    return -1;
  }
  module_file = open ("/sys/digsig/key", O_WRONLY);
  if (module_file < 0) {
    printf ("Unable to open module char device %s\n", strerror(errno));
    close(pkey_file);
    return -1;
  }
  
  if (check_pubkey(pkey_file) == -1) {
    goto do_end;
  }

	
  /* read MPI n */
  if (getMPI(pkey_file, module_file, 'n') != 0){
    goto do_end;
  }
  
  /* read MPI e */
  if (getMPI(pkey_file, module_file, 'e') != 0){
    goto do_end;
  }
  
  ret = 0; /* OK */

do_end:
  close(module_file);
  close(pkey_file);
  return ret;
}

/**
 * Checks public key file format. This should be an OpenPGP message containing an RSA public
 * key.
 *
 * TODO: check all errors
 *
 * @param pkey_file the public key file descriptor (file must be readable)
 *
 * @return -1 if error
 *         0  if successful, the file pointer has moved just at the beginning of the first MPI.
 */
int check_pubkey(int pkey_file)
{
  unsigned char c;
  unsigned int header_len;
  const int RSA_ENCRYPT_OR_SIGN = 1;
  const int RSA_SIGN = 3;
  const int CREATION_TIME_LENGTH = 4;

  /* reading packet tag byte: a public key should be : 100110xx */
  read(pkey_file, &c, 1);
  if (! (c & 0x80) ){
    printf("Bad packet tag byte: this is not an OpenPGP message.\n");
    return -1;
  }
  if (c & 0x40){
    printf("Packet tag: new packet headers are not supported\n");
    return -1;
  }
  if (! (c & 0x18)){
    printf("Packet tag: this is not a public key\n");
    return -1;
  }

  switch (c & 0x03){
  case 0: header_len = 2; break;
  case 1: header_len = 3; break;
  case 2: header_len = 5; break;
  case 3: 
  default:
    printf("Packet tag: indefinite length headers are not supported\n");
    return -1;
  }

  /* skip the rest of the header */
  /*printf("Header len:%d\n",header_len); */
  header_len--;
  lseek(pkey_file, header_len, SEEK_CUR);

  /* Version 4 public key message formats contain:
     1 byte for the version
     4 bytes for key creation time
     1 byte for public key algorithm id
     MPI n
     MPI e
  */
  read(pkey_file, &c, 1);
  /*printf("Version %d\n",c);*/
  if (c != 4){
    printf("Public key message: unsupported version\n");
    return -1;
  }

  lseek(pkey_file, CREATION_TIME_LENGTH, SEEK_CUR); /* skip packet creation time */
  read(pkey_file, &c, 1);
  if (c != RSA_ENCRYPT_OR_SIGN && c!=RSA_SIGN){
    printf("Public key message: this is not an RSA key, or signatures not allowed\n");
    return -1;
  }

  
  return 0; /* OK */
}

/**
 * Retrieves an MPI and sends it to DigSig kernel module. 
 * The file must be set at the beginning of the MPI.
 *
 * TO DO: test for read/write errors.
 *
 * @param pkey_file the public key file. Must be readable and pointing on the beginning
 * of an MPI.
 *
 * @param module_file the sys file to communicate with the DigSig kernel module. Must
 * be open and writable.
 *
 * @param tag a character identifying what we read. This character is prefixed to the MPI
 * and sent to the kernel module.
 *
 * @return 0 if successful, and then the file points just after the MPI.
 */
int getMPI(int pkey_file, int module_file, char tag)
{
  unsigned char c;
  unsigned int len;
  unsigned char *key;
  int i;
  int key_offset = 0;

  key = (unsigned char *)malloc (DIGSIG_MPI_MAX_SIZE+1);
  if (key == NULL) {
    printf("Cannot allocate key buffer\n");
    return -1;
  }

  /* buffers we send to digsig module are prefixed by a character */
  key[key_offset++] = tag;

  /* first two bytes represent MPI's length in BITS */
  read(pkey_file, &c, 1);
  key[key_offset++] = c;
  len = c << 8;

  read(pkey_file, &c, 1);
  key[key_offset++] = c;
  len |= c;
  len = (len + 7) / 8;   /* Bit to Byte conversion */

  /* read the MPI */
  read(pkey_file, &key[key_offset], len);
  key_offset += len;

  /* send MPI to kernel module */
  if (write (module_file, key, key_offset) < 0) {
    printf ("Write problem %i %s\n", errno, strerror (errno));
    return -1;
  }
  
  printf("MPI: %c (len=%d)\n{ ",tag, len);
  for (i = 0; i < key_offset; i++  ) {
    printf("0x%02X, ", key[i] & 0xff);
  }
  printf("}\n");

  return 0; /* OK */
}

void usage() 
{
	printf("Usage: extract_pkey <gpg_pub_key>\n");
	printf("You can export a key with gpg --export > gpg_pub_key\n");
}


