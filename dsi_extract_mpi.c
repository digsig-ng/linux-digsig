/*
 * Distributed Security Module (DSM)
 *
 * dsi_extract_mpi.c
 *
 * Copyright (C) 2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Authors: 
 *          David Gordon Aug 2003 
 *          Makan Pourzandi Sep 2003 
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "dsi.h"
#include "dsi_debug.h"
#include "dsi_extract_mpi.h"

/******************************************************************************
                             Internal functions 
******************************************************************************/

/******************************************************************************
Description : 
Parameters  : 
Return value: a signature context valid for this signature only
******************************************************************************/
int dsi_get_pkey(unsigned char* raw_public_key_n, unsigned char* raw_public_key_e, char* pkey_file){


  /*
   * Format of an MPI:
   * - 2 bytes: length of MPI in BITS
   * - MPI
   */


  /*   fd = open(argv[1], O_RDONLY);
  

  printf("pkey->n MPI:\n{ ");
  lseek(fd, DSI_PKEY_N_OFFSET, SEEK_SET);
  read(fd, &c, 1);
  printf("%#x, ", c & 0xff);
  len = c << 8;

  read(fd, &c, 1);
  len |= c;
  printf("%#x, ", c & 0xff);
  len = (len + 7) / 8;   

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
  len = (len + 7) / 8;   

  if (len > DSI_ELF_SIG_SIZE) {
    printf("\nLength of 'e' MPI is too large %#x\n", len);
    return -1;
  }

  for (i = 0; i < len; i++) {
    read(fd, &c, 1);
    printf("%#x, ", c & 0xff);
  }
  printf("}\n");
  */ 

    
  return -1; // TODO: makan: do nothing for now.

} 

