/*
 * Digital Signature (DigSig)
 *
 * dsi_dev.h
 *
 * This file contains the header file access control functions
 *
 * Copyright (C) 2002-2003 Ericsson, Inc
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 * 
 * Vincent Roy, Axelle Apvrille
 */

#ifndef __DSI_DEV_H
#define __DSI_DEV_H

#include <linux/fs.h>

ssize_t dsi_write(struct file *, const char *, size_t, loff_t *);

#endif
