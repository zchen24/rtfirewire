/* rtfirewire/stack/hosts.c
 *
* Host management for RT-Firewire stack. 
 *
 * Copyright (C)  2005 Zhang Yuchen <y.zhang-4@student.utwente.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/**
 * @ingroup host
 * @file
 *
 * Implementation of host management module
 */

/**
 * @defgroup host host management module
 *
 *
 * For more details
 * see the @ref host management section of "Overview of Real-Time Firewire Stack".
 */


#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/timer.h>

#include <rtpkbuff.h>

#include "csr1212.h"
#include "ieee1394.h"
#include "ieee1394_types.h"
#include "hosts.h"
#include "ieee1394_core.h"
#include "highlevel.h"
#include "csr.h"
#include "config_roms.h"

DECLARE_MUTEX(hpsb_hosts_lock);

/*! module parameter,Number of additional global realtime packet buffers per network adapter*/
unsigned int device_rtpkbs = DEFAULT_DEVICE_RTPKBS;
MODULE_PARM(device_rtpkbs, "i");
MODULE_PARM_DESC(device_rtpkbs, "Number of additional global realtime packet "
                 "buffers per network adapter");

struct hpsb_host *hpsb_hosts[MAX_RT_HOSTS];
	
/**
 * @ingroup host
 * @anchor delayed_reset_bus
 * @todo fill in the doc of delayed_reset_bus
 */
static void delayed_reset_bus(void * __reset_info)
{
	struct hpsb_host *host = (struct hpsb_host*)__reset_info;
	int generation = host->csr.generation + 1;

	/* The generation field rolls over to 2 rather than 0 per IEEE
	 * 1394a-2000. */
	if (generation > 0xf || generation < 2)
		generation = 2;
	
	CSR_SET_BUS_INFO_GENERATION(host->csr.rom, generation);
	if (csr1212_generate_csr_image(host->csr.rom) != CSR1212_SUCCESS) {
		/* CSR image creation failed, reset generation field and do not
		 * issue a bus reset. */
		CSR_SET_BUS_INFO_GENERATION(host->csr.rom, host->csr.generation);
		return;
	}
	
	DEBUG_PRINT("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
	host->csr.generation = generation;
	host->update_config_rom = 0;
	if (host->driver->set_hw_config_rom)
		host->driver->set_hw_config_rom(host, host->csr.rom->bus_info_data);

	host->csr.gen_timestamp[host->csr.generation] = jiffies;
	//~ hpsb_reset_bus(host, SHORT_RESET);
	hpsb_reset_bus(host, LONG_RESET);
}


/**
 * @ingroup host
 * @anchor __host_get_by_name
 * find a host by its name (helper without lock)
 * 
 */
static inline struct hpsb_host *__host_get_by_name(const char *name)
{
	int i;
	struct hpsb_host *host;
		
	for(i=0;i<MAX_RT_HOSTS;i++){
		host = hpsb_hosts[i];
		if((host!=NULL)&&(strncmp(host->name, name, IFNAMSIZ) == 0))
			return host;
	}
	return NULL;
}

/**
 * @ingroup host
 * @anchor host_get_by_name
 * using the helper function ,with lock. 
 */
struct hpsb_host *host_get_by_name(const char *name)
{
	struct hpsb_host *host;
		
	down(&hpsb_hosts_lock);
	host = __host_get_by_name(name);
	up(&hpsb_hosts_lock);
	
	return host;
}


/**
 * @ingroup host
 * @anchor __host_get_by_index
 * find a host by its ifindex (helper without lock)
 */
static inline struct hpsb_host *__host_get_by_index(int ifindex)
{
	return hpsb_hosts[ifindex-1];
}

/**
 * @ingroup host
 * @anchor host_get_by_index
 * using helper with lock
 */
struct hpsb_host *host_get_by_index(int ifindex)
{
	struct hpsb_host *host;
		
	if((ifindex <= 0) || (ifindex > MAX_RT_HOSTS))
		return NULL;
	
	down(&hpsb_hosts_lock);
	host = __host_get_by_index(ifindex);
	up(&hpsb_hosts_lock);
	
	return host;
}


/**
 * @ingroup host
 * @anchor __host_get_by_devid
 * find a host by its device unique id (helper without lock)
 */
static inline struct hpsb_host *__host_get_by_devid(unsigned short type, char *dev_id)
{
	int i;
	struct hpsb_host *host;
		
	for(i = 0; i<MAX_RT_HOSTS; i++) {
		host = hpsb_hosts[i];
		if((host != NULL) && (host->type == type) &&
			(!memcmp(host->dev_id, dev_id, host->dev_id_len))) {
				return host;
		}
	}
	return NULL;
}

/**
 * @ingroup host
 * @anchor host_get_by_devid
 * using helper with lock
 */
struct hpsb_host *host_get_by_devid(unsigned short type, char *dev_id)
{
	struct hpsb_host *host;
		
	down(&hpsb_hosts_lock);
	host = __host_get_by_devid(type, dev_id);
	up(&hpsb_hosts_lock);
		
	return host;
}

/**
 * @ingroup host
 * @anchor host_alloc_name
 * allocate a name for the new host
 * 
 * @param mask - the name mask 
 */
void host_alloc_name (struct hpsb_host *host, const char *mask)
{
	char buf[IFNAMSIZ];
	int i;
	struct hpsb_host *tmp;
		
	for(i = 0; i<MAX_RT_HOSTS; i++) {
		snprintf(buf, IFNAMSIZ, mask, i);
		if((tmp = host_get_by_name(buf))==NULL) {
			strncpy(host->name, buf, IFNAMSIZ);
			break;
		}
	}
}


/**
 * @ingroup host
 * @anchor host_alloc
 * allocate a new host controller.
 *
 * Allocate a &hpsb_host and initialize the general subsystem specific 
 * fields. If the driver needs to store per host data, as drivers usually do, 
 * the amount of memory required can be specified by the @extra parameter. Once
 * allocated, the driver should initialize the driver specific parts, enable the controller
 * and make it available to the general subsystem using host_register().
 *
 * The &hpsb_host is allocated with an single initial reference 
 * belonging to the driver. Once the driver is done with the struct,
 * for example, when the driver is unloaded, it should release this
 * reference using host_unregister().
 *
 * @param extra is number of extra bytes to allocate for the driver private data.
 *
 * 
 * @return a pointer to the &hpsb_host if sucessful. %NULL if
 * no memory was available. 
 */
struct hpsb_host *host_alloc(size_t extra)
{
	struct hpsb_host *h;
	int i;
	
	h = kmalloc(sizeof(struct hpsb_host)+extra, SLAB_KERNEL);
	if(!h) return NULL;
	memset(h,0,sizeof(struct hpsb_host)+extra);
		
	h->csr.rom = csr1212_create_csr(&csr_bus_ops, CSR_BUS_INFO_SIZE, h);
	if (!h->csr.rom) {
		kfree(h);
		return NULL;
	}
		
	h->hostdata = h + 1;
	
	rtpkb_queue_init(&h->pending_packet_queue);
	INIT_LIST_HEAD(&h->addr_space);
	
	for (i = 2; i < 16; i++)
		h->csr.gen_timestamp[i] = jiffies - 60 * HZ;
	
	for(i=0; i<ARRAY_SIZE(h->tpool); i++)
		HPSB_TPOOL_INIT(&h->tpool[i]);
	
	atomic_set(&h->generation, 0);
	atomic_set(&h->refcount, 0);

#if 0
	INIT_WORK(&h->delayed_reset, delayed_reset_bus, h);
#endif

	h->topology_map = h->csr.topology_map + 3;
	h->speed_map = (u8 *)(h->csr.speed_map + 2);
	
#if 0
	rtos_res_lock_init(&h->xmit_lock);
	rtos_spin_lock_init(&h->host_lock);
#endif
	init_MUTEX(&h->nrt_lock);
	
	strcpy(h->name, "rtfw%d");
	
	return h;
}

/**
 * @ingroup host
 * @anchor host_free
 * free a host if the refcount is 0 and it is shutdown
 */
void host_free (struct hpsb_host *host)
{
	if(host){
		#if 0	
			host->stack_event = NULL;
			rtos_res_lock_delete(&host->xmit_lock);
		#endif
			kfree(host);
	}
}


/**
 * @ingroup host
 * @anchor host_ref
 * increase reference count for host controller.
 *
 * Increase the reference count for the specified host controller.
 * When holding a reference to a host, the memory allocated for the
 * host struct will not be freed and the host is guaranted to be in a 
 * consistent state. The driver may be unloaded or the controller may
 * be removed (PCMCIA), but the host struct will remain valid.  
 * 
 * @param host the host controller
 *
 * @return 1 on success. 
 */

int hpsb_ref_host(struct hpsb_host *host)
{
	int retval = 0;
	int i;
	
	down(&hpsb_hosts_lock);
	for(i=0;i<MAX_RT_HOSTS;i++){
		if(host==hpsb_hosts[i]){
			if(host->driver->devctl)
				host->driver->devctl(host,MODIFY_USAGE,1);
			atomic_inc(&host->refcount);
			retval = 1;
			break;
		}
	}
	up(&hpsb_hosts_lock);
	
	return retval;
}

/**
 * @ingroup host
 * @anchor hpsb_unref_host 
 * decrease reference count for host controller.
 *
 * Decrease the reference count for the specified host controller. 
 */

void hpsb_unref_host(struct hpsb_host *host)
{
	if(host->driver->devctl)
		host->driver->devctl(host,MODIFY_USAGE,0);
	
	down(&hpsb_hosts_lock);
	atomic_dec(&host->refcount);
	up(&hpsb_hosts_lock);
}

/**
 * @ingroup host
 * @anchor __host_new_index
 * return a new index in host list.
 * @return -ENOMEM if reaches max host number. 
 */
static inline int __host_new_index(void)
{
	int i;
	
	for(i=0; i<MAX_RT_HOSTS; i++)
		if(hpsb_hosts[i] == NULL)
			return i+1;
		
	return -ENOMEM;
}

/**
 * @ingroup host
 * @anchor host_register
 * register a new struct of host, also notice highlevel modules
 * and called lowlevel drive to raise a long bus reset in the end. 
 */
int host_register(struct hpsb_host *host)
{
#if 0	
	if(host->features & RTNETIF_F_NON_EXCLUSIVE_XMIT)
		host->start_xmit = host->hard_start_xmit;
	else
		host->start_xmit = host_locked_xmit;
#endif
	
	down(&hpsb_hosts_lock);
	
	host->ifindex = __host_new_index();
	
	if (strchr(host->name, '%') != NULL) 
		host_alloc_name(host, host->name);
	
	if (__host_get_by_name(host->name) != NULL){
		up(&hpsb_hosts_lock);
		return -EEXIST;
	}
	
	hpsb_hosts[host->ifindex-1] = host;
	
	up(&hpsb_hosts_lock);
	
	/* to allocated the vendor id and driver name */
	if (hpsb_default_host_entry(host))
		return -ENOMEM;
	/* to add extra unit directory, like ip over 1394 */
	hpsb_add_extra_config_roms(host);
	highlevel_add_host(host);
		
	//~ if(host->driver->devctl)
		//~ host->driver->devctl(host,RESET_BUS, LONG_RESET);
	set_bit(__LINK_STATE_PRESENT, &host->state);
	
	printk("RT-firewire: register %s\n", host->name);
	/*set up the host buffer pool for static memory allocation */
	rtpkb_pool_init(&host->pool,device_rtpkbs);
	strcpy(host->pool.name, host->name);

	/** 
	 * we do bus reset immediately, but better to be scheduled as a delayed task.
	  */
	host->driver->devctl(host, RESET_BUS, LONG_RESET);
	return 0;
}

/**
 * @ingroup host
 * @anchor host_unregister
 * to unregister a host, and notice highlevel modules
 * also set the is_shutdown, so the host can be freed later. 
 * @return 0 on success. 
 */
int host_unregister(struct hpsb_host *host)
{
	RTOS_ASSERT(host->ifindex != 0,
		printk("RT-firewire: host %s/%p was not registered\n", host->name, host);
		return -ENODEV;);
	
	if(host->flags&IFF_UP)
		host_close(host);
	
	host->is_shutdown = 1;
	
	down(&hpsb_hosts_lock);
	if(atomic_read(&host->refcount)>0)
		printk("RT-Firewire: unregistering %s deferred- refcount = %d\n",
				 host->name, atomic_read(&host->refcount));
	
	//~ while(atomic_read(&host->refcount)>0) {
		//~ up(&hpsb_hosts_lock);

		//~ printk("RT-Firewire: unregistering %s deferred- refcount = %d\n",
				//~ host->name, atomic_read(&host->refcount));
		//~ set_current_state(TASK_UNINTERRUPTIBLE);
		//~ schedule_timeout(1*HZ); /* wait a second */

		//~ down(&hpsb_hosts_lock);
	//~ }
#if 0
	cancel_delayed_work(&host->delayed_reset);
	flush_scheduled_work();
#endif
	
	
	hpsb_hosts[host->ifindex-1] = NULL;
	up(&hpsb_hosts_lock);
	
	highlevel_remove_host(host);
	
	hpsb_remove_extra_config_roms(host);
	
	clear_bit(__LINK_STATE_PRESENT, &host->state);
	printk("RT-firewire:unregistered %s\n", host->name);
	
	rtpkb_pool_release(&host->pool);
	
	RTOS_ASSERT(atomic_read(&host->refcount) == 0,
			printk("RT-Firewire: host reference counter >0!\n"););
			
	return 0;
}


/**
 * @ingroup host
 * @anchor hpsb_update_config_rom_image
 * check and probably update the host config rom image.
 * @todo fill in the doc of delayed reset. 
 */
int hpsb_update_config_rom_image(struct hpsb_host *host)
{
//~ #ifdef LINUX_VERSION_26
	//~ unsigned long reset_delay;
	//~ int next_gen = host->csr.generation + 1;

	//~ if (!host->update_config_rom)
		//~ return -EINVAL;

	//~ if (next_gen > 0xf)
		//~ next_gen = 2;

	//~ /* Stop the delayed interrupt, we're about to change the config rom and
	 //~ * it would be a waste to do a bus reset twice. */
	//~ cancel_delayed_work(&host->delayed_reset);

	//~ /* IEEE 1394a-2000 prohibits using the same generation number
	 //~ * twice in a 60 second period. */
	//~ if (jiffies - host->csr.gen_timestamp[next_gen] < 60 * HZ)
		//~ /* Wait 60 seconds from the last time this generation number was
		 //~ * used. */
		//~ reset_delay = (60 * HZ) + host->csr.gen_timestamp[next_gen] - jiffies;
	//~ else
		//~ /* Wait 1 second in case some other code wants to change the
		 //~ * Config ROM in the near future. */
		//~ reset_delay = HZ;

	//~ PREPARE_WORK(&host->delayed_reset, delayed_reset_bus, host);
	//~ schedule_delayed_work(&host->delayed_reset, reset_delay);
//~ #else
	HPSB_NOTICE("We reset the bus immediately\n");
	delayed_reset_bus((void *)host);
//~ #endif
	return 0;
}


/**
 * @ingroup host
 * @anchor host_open
 * general routine of openning a host, set the host state,
 * and call drivers "open" routine. 
 *
 * @return the return value of "open" routine of driver. 
 */
int host_open(struct hpsb_host *host)
{
	int ret = 0;
	
	if(host->flags & IFF_UP)
		return 0;
	
	if(host->driver->open)
		ret= host->driver->open(host);
	
	if(!ret){
		host->flags |=(IFF_UP | IFF_RUNNING);
		set_bit(__LINK_STATE_START, &host->state);
	}
	
	return ret;
}

/**
 * @ingroup host
 * @anchor host_close
 * general routine of closing a host, set the host state,
 * and call drivers "stop" routine. 
 *
 * @return the return value of "stop" routine of driver. 
 */
int host_close(struct hpsb_host *host)
{
	int ret=0;
	
	if( !(host->flags & IFF_UP))
		return 0;
	
	if(host->driver->stop)
		ret = host->driver->stop(host);
	
	host->flags &= ~(IFF_UP|IFF_RUNNING);
	clear_bit(__LINK_STATE_START, &host->state);
	
	return ret;
}

#if 0
/**
 * @ingroup host
 * @anchor host_locked_xmit
 * make the xmit routine critical section
 */
static int host_locked_xmit(struct hpsb_packet *packet, struct hpsb_host *host)
{
	int ret;
	
	rtos_res_lock(&host->xmit_lock);
	ret = host->driver->transmit_packet(host,packet);
	rtos_res_unlock(&host->xmit_lock);
	
	return ret;
}
#endif

