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


#ifndef __DSI_H
#define __DSI_H

#ifdef MODULE
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/pid.h>
#include <linux/init.h>
#endif


/* DSM-DSI error types */
#define DSM_SUCCESS             1
#define DSM_FAILURE             2


#ifdef MODULE			/* This prevents user programs that include dsi.h to inherit kernel stuff */

#define DSI_SAFE_ALLOC (in_interrupt () ? GFP_ATOMIC : GFP_KERNEL)

/* This is a hack to avoid using va_lists */
#define DSM_ERROR(fmt,arg...) printk(DSI_MODULE_NAME" Error - " fmt,##arg)


#include "dsi_debug.h"		/* Include this file first since it contains DSM_PRINT macro */


#endif				/* MODULE */

#endif
