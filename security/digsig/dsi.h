/* 
 * Digital Security Module (DigSig)
 *
 * dsi.h
 *
 * The main header file for DSM
 *
 * Copyright (c) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 * Miroslaw Zakrzewski
 * David Gordon
 * Alain Patrick Medenou
 * Gabriel Ivascu 
 * Makan Pourzandi: modifs, fixes, march 2003, August 2004 
 */


#ifndef _DSI_H
#define _DSI_H

#ifdef MODULE
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/pid.h>
#include <linux/init.h>
#endif


/* DSM-DIGSIG error types */
#define DSM_SUCCESS             1
#define DSM_FAILURE             2


#ifdef MODULE			/* This prevents user programs that include dsi.h to inherit kernel stuff */

#define DIGSIG_SAFE_ALLOC (in_interrupt () ? GFP_ATOMIC : GFP_KERNEL)

/* This is a hack to avoid using va_lists */
#define DSM_ERROR(fmt,arg...) printk(DIGSIG_MODULE_NAME" Error - " fmt,##arg)


#include "dsi_debug.h"		/* Include this file first since it contains DSM_PRINT macro */


#endif				/* MODULE */

extern int g_init;

#endif /* _DSI_H */
