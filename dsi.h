/* 
 * Distributed Security Module (DSM)
 *
 * dsi.h
 *
 * The main header file for DSM
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
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
 * Makan Pourzandi: added test_dsm, fixes, march 2003 
 */


#ifndef __DSI_H
#define __DSI_H

#ifdef MODULE
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/pid.h>
#include <linux/init.h>
#endif


/* Security system calls */
#define DSI_SET_NODE_ID         1
#define DSI_SET_TASK_SECURITY   2
#define DSI_SET_POLICY		3
#define DSI_ALARM_CHECK         4
#define DSI_SET_POLICY_DCI      5
#define DSI_SET_DEBUG_LEVEL     6
#define DSI_TEST_DSM            7
#define DSI_GET_TASK_SECURITY   8
#define DSI_PRINT_POLICY        9
#define DSI_DELETE_RULE         10

/* DSM-DSI error types */
#define DSM_SUCCESS             1
#define DSM_FAILURE             2

#define DSI_SID_LOW		1
#define DSI_SID_NORMAL		2
#define DSI_SID_HIGH		3
#define DSI_SID_TEST            12


/* for now we define only 3 classes */
#define DSI_CLASS_PROCESS	1
#define DSI_CLASS_SOCKET	2
#define DSI_CLASS_NETWORK	3
#define DSI_CLASS_SOCKET_INIT   4
#define DSI_CLASS_DCI           5
#define DSI_CLASS_TRANSITION	128

/* permission bits for process class */
#define PROCESS_FORK		0x00000001

/* permission bits for socket class */
#define SOCKET_CREATE		0x00000001
#define SOCKET_CONNECT		0x00000002
#define SOCKET_SEND		0x00000004
#define SOCKET_LISTEN           0x00000008
#define SOCKET_RECEIVE          0x00000010
#define SOCKET_SHUTDOWN         0x00000020
#define SOCKET_GET_OPTIONS      0x00000040
#define SOCKET_SET_OPTIONS      0x00000080
#define SOCKET_GET_SOCKNAME     0x00000100
#define SOCKET_GET_PEERNAME     0x00000200

/* permission bits for network */
#define NETWORK_RECEIVE         0x00000001

/* allarms types */
#define ALARM_NETWORK_RECEIVE       0x00000001
#define ALARM_PROCESS_CREATE        0x00000002
#define ALARM_SOCKET_CREATE         0x00000010
#define ALARM_SOCKET_CONNENT        0x00000020
#define ALARM_SOCKET_SEND           0x00000040
#define ALARM_SOCKET_LISTEN         0x00000080
#define ALARM_SOCKET_RECEIVE        0x00000100
#define ALARM_SOCKET_SHUTDOWN       0x00000200
#define ALARM_SOCKET_GET_OPTIONS    0x00000400
#define ALARM_SOCKET_SET_OPTIONS    0x00000800
#define ALARM_SOCKET_GET_SOCKNAME   0x00001000
#define ALARM_SOCKET_GET_PEERNAME   0x00002000


#define DSI_DEFAULT_PERM    0	/* permissive mode for structures with no security attached */
#define DSI_MAGIC       	0x7754ffa5
#define DSI_ELF_SID_POS 	7

#ifdef MODULE			/* This prevents user programs that include dsi.h to inherit kernel stuff */

#define DSI_SAFE_ALLOC (in_interrupt () ? GFP_ATOMIC : GFP_KERNEL)

/* This is a hack to avoid using va_lists */
#define DSM_ERROR(fmt,arg...) printk(DSI_MODULE_NAME" Error - " fmt,##arg)

/* int dsi_node_id; 
int dsi_alarm; */

typedef struct {
	int scid;
	int oscid;
	int magic;
	void *task;
} task_security_t;


typedef struct {		/*inode_security_struct */
	unsigned long magic;	/* magic number for this module */
	struct inode *inode;	/* back pointer to inode object */
	int scid;		/* ScID of creating task */
	int task_scid;
	unsigned int class;	/* security class of this object */
} inode_security_t;


typedef struct {
	unsigned long magic;	/* magic number for this module */
	struct sk_buff *skb;	/* back pointer */
	atomic_t use;		/* reference count */
	int scid;		/* Source ScID */
	int snid;
} sk_buff_security_t;

#include "dsi_debug.h"		/* Include this file first since it contains DSM_PRINT macro */

/* Not necessary for RSA verification
#include "dsi_cache.h"
#include "dsi_access_control.h"
*/

#endif				/* MODULE */

#endif
