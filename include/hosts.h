/**
 * @ingroup host
 * @file
 *
 * data structure and interfaces of @ref host "host management module"
 */
 
#ifndef _HOST_H_
#define _HOST_H_

/*! the maximum number of Firewire hosts in local system */
#define MAX_RT_HOSTS                  8

#define IFNAMSIZ 		32
#define MAX_DEV_ID_LEN	32
#define MAX_DRV_NAME_LEN 32

/*! host types */
#define HOST_TYPE_OHCI1394	0x1F
#define HOST_TYPE_PCILYNX	0X1E

/* Standard interface flags (netdevice->flags). copied from Linux/if.h */
#define	IFF_UP		0x1		/* interface is up		*/
#define	IFF_BROADCAST	0x2		/* broadcast address valid	*/
#define	IFF_DEBUG	0x4		/* turn on debugging		*/
#define	IFF_DUMMY	0x8		/* like loopback in ethernet		*/
#define	IFF_POINTOPOINT	0x10		/* interface is has p-p link	*/
#define	IFF_NOTRAILERS	0x20		/* avoid use of trailers	*/
#define	IFF_RUNNING	0x40		/* resources allocated		*/
#define	IFF_NOARP	0x80		/* no ARP protocol		*/
#define	IFF_PROMISC	0x100		/* receive all packets		*/
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets*/

#ifdef __KERNEL__

#include <linux/wait.h>
#include <linux/list.h>
#include <linux/timer.h>

#include <rtpkbuff.h>

#include <asm/semaphore.h>

#include "ieee1394_types.h"
#include "csr.h"

/*! the real-time device structure version */
#define RTDEV_VERS_2_1                 0x0201

#define PRIV_FLAG_UP                    0
#define PRIV_FLAG_ADDING_ROUTE          1

#define RTNETIF_F_NON_EXCLUSIVE_XMIT    0x00010000

/*! size of the array used to store config rom (in quadlets)
   maximum is 0x100. About 0x40 is needed for the default
   entries. So 0x80 should provide enough space for additional
   directories etc. 
   Note: All lowlevel drivers are required to allocate at least
         this amount of memory for the configuration rom!
*/
#define CSR_CONFIG_ROM_SIZE       0x100

/* These flag bits are private to the generic network queueing
 * layer, they may not be explicitly referenced by any other
 * code. (copied from linux/netdevice.h)
 */

enum netdev_state_t
{
	__LINK_STATE_XOFF=0,
	__LINK_STATE_START,
	__LINK_STATE_PRESENT,
	__LINK_STATE_SCHED,
	__LINK_STATE_NOCARRIER,
	__LINK_STATE_RX_SCHED
};


struct hpsb_iso;
struct hpsb_packet;

/** @addtogroup host
 *@{*/
/*  host structure for Firewire devices. */
struct hpsb_host {
    
    void *hostdata;
    
    atomic_t 	generation;
    
    atomic_t refcount;
    
    struct rtpkb_queue pending_packet_queue;
    
    struct timer_list	timeout;
    unsigned long	timeout_interval;
    
    unsigned char iso_listen_count[64];
    
    unsigned int max_packet_size;
    
    int node_count;
    int selfid_count;
    int nodes_active;
    
    nodeid_t node_id;
    nodeid_t irm_id;
    nodeid_t busmgr_id;
    
    unsigned in_bus_reset:1;
    unsigned is_shutdown:1;
    
    unsigned is_root:1;
    unsigned is_cycmst:1;
    unsigned is_irm:1;
    unsigned is_busmgr:1;
    
    int reset_retries;
    quadlet_t *topology_map;
    u8 *speed_map;
    struct csr_control csr;
	    
    unsigned long nb_iso_xmit_ctx;
    unsigned long it_ctx_usage;
    unsigned long nb_iso_rcv_ctx;
    unsigned long ir_ctx_usage;
	    
    struct hpsb_tlabel_pool tpool[64];

    struct pci_dev *pdev;
	
    int ifindex;
    
    int update_config_rom;
    #if 0
    struct work_struct delayed_reset;
    #endif
	    
    unsigned int config_roms;
    
    struct list_head addr_space;
    
    unsigned int	vers;
    
    unsigned char 		name[IFNAMSIZ];
    
    //~ unsigned long 	rmem_end;
    //~ unsigned long	rmem_start;
    unsigned long	mmio_end;
    unsigned long	mmio_start;
    unsigned long 	base_addr;
    unsigned int		irq;
    
    unsigned long 	state;
    
    struct module		*rt_owner;
	    
    unsigned int	flags;
    unsigned long	priv_flags;
    unsigned short	type;
    int 	features;
    
    unsigned char dev_id[MAX_DEV_ID_LEN];
    unsigned int dev_id_len;

#if 0
  /*
    * Todo
    */
    struct dev_mc_list	*mc_list;
    int 	mc_count;
    int	promiscuity;
    int	allmulti;
    
/* synchronization with layer above */  
    rtos_event_sem_t    *stack_event;    
/* protects critical section of xmit routine        */
    rtos_res_lock_t     xmit_lock;
/* management lock              */    
    rtos_spinlock_t     host_lock; 
#endif
/* non-real-time locking ,should be named nrt_lock; it's a mutex... */
    struct semaphore    nrt_lock;   

    
    unsigned int 		add_rtpkbs;
    
    struct rtpkb_pool 	pool;

#if 0    
    /* RTmac related fields */
    struct rtmac_disc	*mac_disc;
    struct rtmac_priv	*mac_priv;
     int	(*mac_detach)(struct hpsb_host *host);
#endif 
     
     struct hpsb_host_driver *driver;
};

enum devctl_cmd {
        /*! Host is requested to reset its bus and cancel all outstanding async
         * requests.  If arg == 1, it shall also attempt to become root on the
         * bus.  Return void. */
        RESET_BUS,

        /*! Arg is void, return value is the hardware cycle counter value. */
        GET_CYCLE_COUNTER,

        /*! Set the hardware cycle counter to the value in arg, return void.
         * FIXME - setting is probably not required. */
        SET_CYCLE_COUNTER,

        /*! Configure hardware for new bus ID in arg, return void. */
        SET_BUS_ID,

        /*! If arg true, start sending cycle start packets, stop if arg == 0.
         * Return void. */
        ACT_CYCLE_MASTER,

        /*! Cancel all outstanding async requests without resetting the bus.
         * Return void. */
        CANCEL_REQUESTS,

        /*! Decrease host usage count if arg == 0, increase otherwise.  Return
         * 1 for success, 0 for failure.  Increase usage may fail if the driver
         * is in the process of shutting itself down.  Decrease usage can not
         * fail. */
        MODIFY_USAGE,

        /*! Start or stop receiving isochronous channel in arg.  Return void.
         * This acts as an optimization hint, hosts are not required not to
         * listen on unrequested channels. */
        ISO_LISTEN_CHANNEL,
        ISO_UNLISTEN_CHANNEL
};

enum isoctl_cmd {
	/*! rawiso API - see iso.h for the meanings of these commands
	   (they correspond exactly to the hpsb_iso_* API functions)
	 * INIT = allocate resources
	 * START = begin transmission/reception
	 * STOP = halt transmission/reception
	 * QUEUE/RELEASE = produce/consume packets
	 * SHUTDOWN = deallocate resources
	 */

	XMIT_INIT,
	XMIT_START,
	XMIT_STOP,
	XMIT_QUEUE,
	XMIT_SHUTDOWN,

	RECV_INIT,
	 /*! multi-channel only */
	RECV_LISTEN_CHANNEL,  
	 /*! multi-channel only */
	RECV_UNLISTEN_CHANNEL,
	/*! multi-channel only; arg is a *u64 */
	RECV_SET_CHANNEL_MASK, 
	RECV_START,
	RECV_STOP,
	RECV_RELEASE,
	RECV_SHUTDOWN,
	RECV_FLUSH
};

enum reset_types {
        /*! 166 microsecond reset -- only type of reset available on
           non-1394a capable IEEE 1394 controllers */
        LONG_RESET,

        /*! Short (arbitrated) reset -- only available on 1394a capable
           IEEE 1394 capable controllers */
        SHORT_RESET,

	/*! Variants, that set force_root before issueing the bus reset */
	LONG_RESET_FORCE_ROOT, SHORT_RESET_FORCE_ROOT,

	/*! Variants, that clear force_root before issueing the bus reset */
	LONG_RESET_NO_FORCE_ROOT, SHORT_RESET_NO_FORCE_ROOT
};

struct hpsb_host_driver {
	struct module *owner;
	const char name[MAX_DRV_NAME_LEN];
	
	int 		(*open)(struct hpsb_host *host);
	int		(*stop)(struct hpsb_host *host);

	/* The hardware driver may optionally support a function that is used
	 * to set the hardware ConfigROM if the hardware supports handling
	 * reads to the ConfigROM on its own. */
	void (*set_hw_config_rom) (struct hpsb_host *host, quadlet_t *config_rom);

        /* This function shall implement packet transmission based on
         * packet->type.  It shall CRC both parts of the packet (unless
         * packet->type == raw) and do byte-swapping as necessary or instruct
         * the hardware to do so.  It can return immediately after the packet
         * was queued for sending.  After sending, hpsb_sent_packet() has to be
         * called.  Return 0 on success, negative errno on failure.
         * NOTE: The function must be callable in interrupt context.
         */
        int (*transmit_packet) (struct hpsb_host *host,
                                struct hpsb_packet *packet);

        /* This function requests miscellanous services from the driver, see
         * above for command codes and expected actions.  Return -1 for unknown
         * command, though that should never happen.
         */
        int (*devctl) (struct hpsb_host *host, enum devctl_cmd command, int arg);

	 /* ISO transmission/reception functions. Return 0 on success, -1
	  * (or -EXXX errno code) on failure. If the low-level driver does not
	  * support the new ISO API, set isoctl to NULL.
	  */
	int (*isoctl) (struct hpsb_iso *iso, enum isoctl_cmd command, unsigned long arg);

        /* This function is mainly to redirect local CSR reads/locks to the iso
         * management registers (bus manager id, bandwidth available, channels
         * available) to the hardware registers in OHCI.  reg is 0,1,2,3 for bus
         * mgr, bwdth avail, ch avail hi, ch avail lo respectively (the same ids
         * as OHCI uses).  data and compare are the new data and expected data
         * respectively, return value is the old value.
         */
        quadlet_t (*hw_csr_reg) (struct hpsb_host *host, int reg,
                                 quadlet_t data, quadlet_t compare);
};
/*@}*/

extern struct semaphore hpsb_hosts_lock;
extern struct hpsb_host *hpsb_hosts[MAX_RT_HOSTS];
	
extern struct hpsb_host *host_alloc(size_t extra);
extern void host_free(struct hpsb_host *host);

extern int host_register(struct hpsb_host *host);
extern int host_unregister(struct hpsb_host *host);

extern void host_alloc_name (struct hpsb_host *host, const char *name_mask);

extern struct hpsb_host *host_get_by_name(const char *name);
extern struct hpsb_host *host_get_by_index(int ifindex);
extern struct hpsb_host *host_get_by_devid(unsigned short type, char *dev_id);
extern int host_ref(struct hpsb_host *host);
extern void host_unref(struct hpsb_host *host);	

#if 0
extern int host_xmit(struct rtpkb *skb);
extern unsigned int host_xmit_proxy(struct hpsb_host *host, unsigned int priority);
#endif

extern int host_open(struct hpsb_host *host);
extern int host_close(struct hpsb_host *host);
	
int hpsb_update_config_rom_image(struct hpsb_host *host);
	
#endif /*__KERNEL__*/

#endif  /* _HOST_H_ */
