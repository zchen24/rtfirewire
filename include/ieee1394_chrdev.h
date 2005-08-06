/**
 * @ingroup chrdev
 * @file
 *
 * data structures and interfaces of chrdev module
 */
#ifndef __IEEE1394_CHRDEV_H_
#define __IEEE1394_CHRDEV_H_

#include <hosts.h>

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/types.h>

#include <hosts.h>

extern struct list_head ioctl_handlers;

/**
 * @ingroup chrdev
 * @struct ioctl_handler
 */
struct ioctl_handler {
    /*! internal usage only */
    struct list_head entry;
    atomic_t         ref_count;

    /*! provider specification */
    const char       *service_name;
    unsigned int     ioctl_type;
    int              (*handler)(struct hpsb_host *host,
                                unsigned int request, unsigned long arg);
};

extern int ieee1394_register_ioctls(struct ioctl_handler *ioctls);
extern void ieee1394_unregister_ioctls(struct ioctl_handler *ioctls);

extern int __init ieee1394_chrdev_init(void);
extern void ieee1394_chrdev_release(void);

#else   /* ifndef __KERNEL__ */

#include <hosts.h>
#include <linux/types.h>

typedef unsigned short nodeid_t;

#endif  /* __KERNEL__ */

/*! user interface for /dev/rtnet-firewire */
#define RT1394_MINOR             241

/* which interface to operate on */
struct ieee1394_ioctl_head {
    unsigned char if_name[IFNAMSIZ];
};

struct ieee1394_core_cmd {
    struct ieee1394_ioctl_head head;

    union {
        struct {
            unsigned int    set_dev_flags;
            unsigned int    clear_dev_flags;
        } up;

        struct {
            int             ifindex;
            unsigned short  type;
            unsigned int    flags;
            unsigned char   dev_id[MAX_DEV_ID_LEN];
	    unsigned char driver[MAX_DRV_NAME_LEN];
	    unsigned long	mmio_end;
	    unsigned long	mmio_start;
	    unsigned long 	base_addr;
	    unsigned int irq;
	    unsigned int max_packet_size;
	    unsigned int pending_packets;
	    int generation;
	    nodeid_t node_id;
	    nodeid_t irm_id;
	    nodeid_t busmgr_id;
	    unsigned int bw_remaining;
	    unsigned long long channels;
	    unsigned long nb_iso_xmit_ctx;
	    unsigned long it_ctx_usage;
	    unsigned long nb_iso_rcv_ctx;
	    unsigned long ir_ctx_usage;
        } info;
    } args;
};

#define RTFW_IOC_NODEV_PARAM           0x80

/*! choose the magic number of for core ioctl*/
#define RTFW_IOC_TYPE_CORE	0
#define RTFW_IOC_TYPE_BIS		1

#define IOC_RTFW_IFUP                     _IOW(RTFW_IOC_TYPE_CORE, 0,    \
                                             struct ieee1394_core_cmd)
#define IOC_RTFW_IFDOWN                   _IOW(RTFW_IOC_TYPE_CORE, 1,    \
                                             struct ieee1394_core_cmd)
#define IOC_RTFW_IFINFO                   _IOWR(RTFW_IOC_TYPE_CORE, 2 |  \
                                              RTFW_IOC_NODEV_PARAM,    \
                                              struct ieee1394_core_cmd)

#endif  /* __IEEE1394_CHRDEV_H_ */
