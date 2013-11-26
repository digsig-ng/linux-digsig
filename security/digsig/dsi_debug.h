/*
 * Digital Signature (DigSig)
 *
 * dsi_debug.h
 *	
 * This file contains the DSM access control implementation
 *
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 * 
 * Author: David Gordon
 * Modifications: Axelle Apvrille - TRACEFUNC level.
 */


#ifndef _DSI_DEBUG_H
#define _DSI_DEBUG_H

#define DIGSIG_MODULE_NAME "DIGSIG MODULE"



#define DEBUG_ALL             0xFFFFFFFF
#define DEBUG_INIT            0x00000001	/* 1 */
#define DEBUG_BINPRM          0x00000002	/* 2 */
#define DEBUG_SUPER_BLOCK     0x00000004	/* 4 */
#define DEBUG_INODE           0x00000008	/* 8 */
#define DEBUG_FILE            0x00000010	/* 16 */
#define DEBUG_TASK            0x00000020	/* 32 */
#define DEBUG_SOCKET          0x00000040	/* 64 */
#define DEBUG_SOCKET_ANNOYING 0x00000080	/* 128 */
#define DEBUG_SKB             0x00000100	/* 256 */
#define DEBUG_IP              0x00000200	/* 512 */
#define DEBUG_NETDEV          0x00000400	/* 1024 */
#define DEBUG_IPC             0x00000800	/* 2048 */
#define DEBUG_MSG             0x00001000	/* 4096 */
#define DEBUG_SHM             0x00002000	/* 8192 */
#define DEBUG_SEM             0x00004000	/* 16384 */
#define DEBUG_ACCESS_CONTROL  0x00008000	/* 32768 */
#define DEBUG_CACHE           0x00010000	/* 65536 */
#define DEBUG_WARNING         0x00020000	/* 131072 */
#define DEBUG_ERROR           0x00040000	/* never used, use DSM_ERROR */
#define DEBUG_SYS_SECURITY    0x00080000	/* 524288 */
#define DEBUG_DCI             0x00100000	/* 1048576 */
#define DEBUG_CALL            0x00200000
#define DEBUG_DEV             0x00400000
#define DEBUG_TESTS           0x00800000
#define DEBUG_TRACEFUNC       0x01000000	/* 16777216 */
#define DEBUG_SIGN            0x02000000
#define DEBUG_TIME            0x04000000

extern int DigsigDebugLevel;

/* This is a hack to avoid using va_lists */
#define DSM_PRINT(dbg,fmt,arg...) \
    if (dbg & DigsigDebugLevel) printk(DIGSIG_MODULE_NAME" - " fmt,##arg)

#define DSM_PRINT_NO_PREFIX(dbg,fmt,arg...) \
    if (dbg & DigsigDebugLevel) printk(fmt,##arg)

#endif /* _DSI_DEBUG_H */
