/***
 *
 *  include/rt1394_sys.h
 *
 *
 *  Copyright (C) 2005	Zhang Yuchen
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __RT1394_SYS_H_
#define __RT1394_SYS_H_

#include <rt-firewire_config.h>

#include <linux/time.h>
#include <linux/types.h>
#include <rtos_primitives.h>

#if	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
#define	CONFIG_KERNEL_26
#endif

#endif /* __RT1394_SYS_H_ */
