/*
 * Distributed Security Module (DSM)
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
 * Vincent Roy
 */
#ifndef __DSI_SYSFS_H
#define __DSI_SYSFS_H

ssize_t	digsig_store (struct kobject *obj, struct attribute *attr, const char *buff, size_t count);
ssize_t	digsig_show (struct kobject *obj, struct attribute *attr, char *buff);

#endif
