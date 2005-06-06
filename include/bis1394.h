/**
 * @ingroup bis
 * @file
 * 
 * data structures and interfaces of bus internal service module
 */
#ifndef _IEEE1394_BIS_H
#define _IEEE1394_BIS_H

#include <hosts.h>
#include <ieee1394_chrdev.h>
#include <linux/types.h>
#include <rtos_primitives.h>

/**length of address space for incoming packet**/
#define 	BIS1394_REGION_ADDR_LEN	4096
#define 	BIS1394_REGION_ADDR_BASE	0xfffff0000000ULL + 0x4000

#ifdef  __KERNEL__
struct bis_host_info {
	struct hpsb_host *host;
		
	spinlock_t	echo_calls_lock;
	struct list_head	echo_calls;
};
#endif

struct bis_cmd {
	struct ieee1394_ioctl_head head;
	struct hpsb_host *host;	
		
	union {
		/** rtping **/
		struct {
			int	destid;	
			size_t	msg_size;
			unsigned int	timeout;
			__s64	rtt;
		} ping;
		
		/** timer synchronization**/
		struct {
			
		} sync;
	} args;
};
		

#define IOC_RTFW_PING	_IOWR(RTFW_IOC_TYPE_BIS, 0,	\
						struct bis_cmd)

#endif /* _IEEE1394_BIS_H */


	