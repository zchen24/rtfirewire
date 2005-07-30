/***
 *  rt-firewire/include/rt1394_sys.h
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

//#define CONFIG_IEEE1394_DEBUG	1
//~ #define CONFIG_IEEE1394_VERBOSEDEBUG	1

<<<<<<< .mine
#define CONFIG_OHCI1394_DEBUG	1
=======
//#define CONFIG_OHCI1394_DEBUG	1
>>>>>>> .r182

//~ #define CONFIG_DEBUG_PRINT	1

#ifdef CONFIG_DEBUG_RPINT
#define	 DEBUG_PRINT(fmt, args...) \
rtos_print(fmt "\n" , ## args)
#else
#define	DEBUG_PRINT(fmt, args...)
#endif

#ifdef __IN_RTFW__
#include <rt-firewire_config.h>

#include <linux/time.h>
#include <linux/types.h>
#include <rtos_primitives.h>

#if	LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
#define	CONFIG_KERNEL_26
#endif

/*Internal priorities of each transaction server, 
relative to the base priority of server module*/
#define RESP_SERVER_PRI	10
#define BIS_SERVER_PRI		20
#define RT1394_SERVER_PRI	30
#define TIMEOUT_SERVER_PRI	5

#endif /*__IN_RTFW__ */

#endif /* __RT1394_SYS_H_ */
