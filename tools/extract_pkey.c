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
 * Author: David Gordon
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DSI_ELF_SIG_SIZE 512               /* this is a redefinition */
#define DSI_PKEY_N_OFFSET        8         /* offset for pkey->n */
/* pkey->e MPI follows pkey->n MPI */


void usage();


int main(int argc, char **argv)
{
  int fd, nread, count, i;
  unsigned int num;
  unsigned int len;
  unsigned char c;

  if (argc <= 1)
    usage();

  /* Get pkey MPIs, one for 'n' and the other for 'e' */
  fd = open(argv[1], O_RDONLY);
  

  /*
   * Format of an MPI:
   * - 2 bytes: length of MPI in BITS
   * - MPI
   */

  printf("pkey->n MPI:\n{ ");
  lseek(fd, DSI_PKEY_N_OFFSET, SEEK_SET);
  read(fd, &c, 1);
  printf("%#x, ", c & 0xff);
  len = c << 8;

  read(fd, &c, 1);
  len |= c;
  printf("%#x, ", c & 0xff);
  len = (len + 7) / 8;   /* round up */

  if (len > DSI_ELF_SIG_SIZE) {
    printf("\nLength of 'n' MPI is too large %#x\n", len);
    return -1;
  }

  for (i = 0; i < len; i++) {
    read(fd, &c, 1);
    printf("%#x, ", c & 0xff);
  }
  printf("}\n");


  printf("pkey->e MPI:\n{ ");
  read(fd, &c, 1);
  printf("%#x, ", c & 0xff);
  len = c << 8;

  read(fd, &c, 1);
  len |= c;
  printf("%#x, ", c & 0xff);
  len = (len + 7) / 8;   /* round up */

  if (len > DSI_ELF_SIG_SIZE) {
    printf("\nLength of 'e' MPI is too large %#x\n", len);
    return -1;
  }

  for (i = 0; i < len; i++) {
    read(fd, &c, 1);
    printf("%#x, ", c & 0xff);
  }
  printf("}\n");

  return 0;
}


void usage() 
{
  printf("Usage: extract_pkey gpgkey\nYou can export a key with gpg --export\n");
}


