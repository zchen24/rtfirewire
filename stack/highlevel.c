/* rtfirewire/stack/highlevel.c
 * Implementation of application layer management for RT-FireWire
 * adapted from Linux 1394subsystem. 
 *
 * Copyright (C) 2005 Zhang Yuchen <y.zhang-4@student.utwente.nl>
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
 * @ingroup highlevel
 * @file
 * 
 * Implementation of highlevel drivers management
 */
 
 /**
  *@defgroup highlevel  highlevel drivers management module
  *
  * highlevel drivers management of Real-Time Firewire Stack. 
  *
  * For more info, 
  * see @ref highlevel drivers section in "Overview of Real-Time Firewire Stack". 
  */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/list.h>

#include <ieee1394.h>
#include <ieee1394_types.h>
#include <hosts.h>
#include <ieee1394_core.h>
#include <highlevel.h>
#include <ieee1394_chrdev.h>

static LIST_HEAD(hl_drivers);
static rwlock_t hl_drivers_lock = RW_LOCK_UNLOCKED;

static LIST_HEAD(hl_irqs);
static rwlock_t hl_irqs_lock = RW_LOCK_UNLOCKED;

static LIST_HEAD(addr_space);
static rwlock_t addr_space_lock = RW_LOCK_UNLOCKED;

/* addr_space list will have zero and max already included as bounds */
static struct hpsb_address_ops dummy_ops = { NULL, NULL, NULL, NULL };
static struct hpsb_address_serve dummy_zero_addr, dummy_max_addr;

/**
 * @ingroup highlevel
 * @anchor hl_get_hostinfo
 * 
 * find the host info of a certain host in the host info list of a certain
 * highlevel driver
 * 
 * 
 * @param hl is the pointer to the concerned highlevel driver
 * @param host is the pointer to the concerned host
 * @return NULL on failure, the poointer to corresponding host_info on success. 
 */
static struct hl_host_info *hl_get_hostinfo(struct hpsb_highlevel *hl,
					      struct hpsb_host *host)
{
	struct hl_host_info *hi = NULL;

	if (!hl || !host)
		return NULL;

	read_lock(&hl->host_info_lock);
	list_for_each_entry(hi, &hl->host_info_list, list) {
		if (hi->host == host) {
			read_unlock(&hl->host_info_lock);
			return hi;
		}
	}
	read_unlock(&hl->host_info_lock);

	return NULL;
}


/**
 * @ingroup highlevel
 * @anchor hpsb_get_hostinfo
 *
 * return the highlevel driver private data in a certain host_info
 * see @ref hl_get_hostinfo. 
 * 
 */
void *hpsb_get_hostinfo(struct hpsb_highlevel *hl, struct hpsb_host *host)
{
	
	struct hl_host_info *hi = hl_get_hostinfo(hl, host);

	if (hi)
		return hi->data;

	return NULL;
}


/**
 * @ingroup highlevel
 * @anchor hpsb_create_hostinfo
 * Create the host_info for a host to a highlevel driver. 
 *
 * @param data_size is the size of highlevel driver private data in the host_info.
 *
 * @note if size is zero, then the return here is only valid for error checking 
 */
void *hpsb_create_hostinfo(struct hpsb_highlevel *hl, struct hpsb_host *host,
			   size_t data_size)
{
	struct hl_host_info *hi;
	void *data;
	unsigned long flags;

	hi = hl_get_hostinfo(hl, host);
	if (hi) {
		HPSB_ERR("%s called hpsb_create_hostinfo when hostinfo already exists",
			 hl->name);
		return NULL;
	}

	hi = kmalloc(sizeof(*hi) + data_size, GFP_ATOMIC);
	if (!hi) {
		
		return NULL;
	}

	memset(hi, 0, sizeof(*hi) + data_size);

	if (data_size) {
		data = hi->data = hi + 1;
		hi->size = data_size;
	} else
		data = hi;

	hi->host = host;

	write_lock_irqsave(&hl->host_info_lock, flags);
	list_add_tail(&hi->list, &hl->host_info_list);
	write_unlock_irqrestore(&hl->host_info_lock, flags);

	return data;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_set_hostinfo
 *
 * set the highlevel driver specific data to host info
 *
 * @param data is the pointer to the prepared highlevel private data.
 * @return 0 on success.
 *  @b -EINVAL when host_info can not be found or it already has a private data,
 * 				or its private data size is zero.
 */
int hpsb_set_hostinfo(struct hpsb_highlevel *hl, struct hpsb_host *host,
		      void *data)
{
	struct hl_host_info *hi;

	hi = hl_get_hostinfo(hl, host);
	if (hi) {
		if (!hi->size && !hi->data) {
			hi->data = data;
			return 0;
		} else
			HPSB_ERR("%s called hpsb_set_hostinfo when hostinfo already has data",
				 hl->name);
	} else
		HPSB_ERR("%s called hpsb_set_hostinfo when no hostinfo exists",
			 hl->name);

	return -EINVAL;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_destory_hostinfo
 * Delete the host_info about a certain host. 
 */
void hpsb_destroy_hostinfo(struct hpsb_highlevel *hl, struct hpsb_host *host)
{
	struct hl_host_info *hi;

	hi = hl_get_hostinfo(hl, host);
	if (hi) {
		unsigned long flags;
		write_lock_irqsave(&hl->host_info_lock, flags);
		list_del(&hi->list);
		write_unlock_irqrestore(&hl->host_info_lock, flags);
		kfree(hi);
	}

	return;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_set_hostinfo_key
 * 
 */
void hpsb_set_hostinfo_key(struct hpsb_highlevel *hl, struct hpsb_host *host, unsigned long key)
{
	struct hl_host_info *hi;

	hi = hl_get_hostinfo(hl, host);
	if (hi)
		hi->key = key;

	return;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_get_hostinfo_bykey
 *
 */
void *hpsb_get_hostinfo_bykey(struct hpsb_highlevel *hl, unsigned long key)
{
	struct hl_host_info *hi;
	void *data = NULL;

	if (!hl)
		return NULL;

	read_lock(&hl->host_info_lock);
	list_for_each_entry(hi, &hl->host_info_list, list) {
		if (hi->key == key) {
			data = hi->data;
			break;
		}
	}
	read_unlock(&hl->host_info_lock);

	return data;
}

/**
 * @ingroup highlevel
 * @anchor highlevel_for_each_host_reg
 * Add new highlevel driver on each host.
 *
 * This includes called the add_host routine of that highlevel driver, and
 * update the configrom on each host. 
 */
static int highlevel_for_each_host_reg(struct hpsb_host *host, void *__data)
{
	struct hpsb_highlevel *hl = __data;
		
	hl->add_host(host);

        if (host->update_config_rom) {
		if (hpsb_update_config_rom_image(host) < 0) {
			HPSB_ERR("Failed to generate Configuration ROM image for host "
				 "%s-%d", hl->name, host->ifindex);
		}
	}

	return 0;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_register_highlevel
 * register a highlevel driver to stack.
 * 
 *This includes calling the module-specific "add_host" routine for each exsiting host, 
 * and registerring a ioctl handler to stack management (char device).
 * 
 * @param hl the pointer to the hpsb_highlevel struct
 * 
 * @return void 
 */
void hpsb_register_highlevel(struct hpsb_highlevel *hl)
{
        struct hpsb_host *host;
	int i;
	
	INIT_LIST_HEAD(&hl->addr_list);
	INIT_LIST_HEAD(&hl->host_info_list);

	rwlock_init(&hl->host_info_lock);

	write_lock(&hl_drivers_lock);
        list_add_tail(&hl->hl_list, &hl_drivers);
	write_unlock(&hl_drivers_lock);

	write_lock(&hl_irqs_lock);
	list_add_tail(&hl->irq_list, &hl_irqs);
	write_unlock(&hl_irqs_lock);

	if (hl->add_host) {
		down(&hpsb_hosts_lock);
		for (i = 0; i < MAX_RT_HOSTS; i++) {
			host = hpsb_hosts[i];
			if(host)
				highlevel_for_each_host_reg(host, hl);
		}
		up(&hpsb_hosts_lock);
	}
	
	/*if the highlevel application introduces new ioctl to /dev/rt-firewire */
	if(hl->hl_ioctl)
		list_add_tail(&hl->hl_ioctl->entry, &ioctl_handlers);
	
        return;
}

/**
 * @ingroup highlevel
 * @anchor __delete_addr
 * to delete an address space structure. 
 *
 * @note  This is an internal helper function. 
 */
static void __delete_addr(struct hpsb_address_serve *as)
{
	list_del(&as->host_list);
	list_del(&as->hl_list);
	kfree(as);
}

/**
 * @ingroup highlevel
 * @anchor __unregister_host
 * to unregister a host under a highlevel driver
 *
 * @note This is an internal helper function. 
 */
static void __unregister_host(struct hpsb_highlevel *hl, struct hpsb_host *host, int update_cr)
{
	unsigned long flags;
	struct list_head *lh, *next;
	struct hpsb_address_serve *as;

	/*! First, let the highlevel driver unreg */
	if (hl->remove_host)
		hl->remove_host(host);

	/*! Remove any addresses that are matched for this highlevel driver
	 * and this particular host. */
	write_lock_irqsave(&addr_space_lock, flags);
	list_for_each_safe (lh, next, &hl->addr_list) {
		as = list_entry(lh, struct hpsb_address_serve, hl_list);

		if (as->host == host)
			__delete_addr(as);
	}
	write_unlock_irqrestore(&addr_space_lock, flags);

	/*! Now update the config-rom to reflect anything removed by the
	 * highlevel driver. */
	//~ if (update_cr && host->update_config_rom) {
		//~ if (hpsb_update_config_rom_image(host) < 0) {
			//~ HPSB_ERR("Failed to generate Configuration ROM image for host "
				 //~ "%s-%d", hl->name, host->ifindex);
		//~ }
	//~ }

	/*! And finally, remove all the host info associated between these
	 * two. */
	hpsb_destroy_hostinfo(hl, host);
}

/**
 * @ingroup highlevel
 * @anchor highlevel_for_each_host_unreg
 * Remove highlevel driver on each host.
 * 
 * @param __data - pointer to the highlevel driver
 */
static int highlevel_for_each_host_unreg(struct hpsb_host *host, void *__data)
{
	struct hpsb_highlevel *hl = __data;

	__unregister_host(hl, host, 1);

	return 0;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_unregister_highlevel
 * unregister a highlevel module to stack.
 * 
 *This includes unregisterring the address mapping , 
 * calling the driver-specific "remove_host" routine for each exsiting host, 
 * destorying the hostinfo 
 * and possibly unregisterring the ioctl handler from /dev/rt-firewire.
 * 
 * @param hl the pointer to the hpsb_highlevel struct
 * @return void 
 * @todo fill in the documentation about irq_list. 
 */
void hpsb_unregister_highlevel(struct hpsb_highlevel *hl)
{
	struct hpsb_host *host;
	int i;
		
	write_lock(&hl_irqs_lock);
	list_del(&hl->irq_list);
	write_unlock(&hl_irqs_lock);

	write_lock(&hl_drivers_lock);
        list_del(&hl->hl_list);
	write_unlock(&hl_drivers_lock);

	down(&hpsb_hosts_lock);
		for (i = 0; i < MAX_RT_HOSTS; i++) {
			host = hpsb_hosts[i];
			if(host)
				highlevel_for_each_host_unreg(host, hl);
		}
	up(&hpsb_hosts_lock);
	
	if(hl->hl_ioctl)
		list_del(&hl->hl_ioctl->entry);
}


/**
 * @ingroup highlevel
 * @anchor hpsb_allocate_and_register_addrspace
 * @todo fill in doc
 */
u64 hpsb_allocate_and_register_addrspace(struct hpsb_highlevel *hl,
					 struct hpsb_host *host,
					 struct hpsb_address_ops *ops,
					 u64 size, u64 alignment,
					 u64 start, u64 end)
{
	struct hpsb_address_serve *as, *a1, *a2;
	struct list_head *entry;
	u64 retval = ~0ULL;
	unsigned long flags;
	u64 align_mask = ~(alignment - 1);

	if ((alignment & 3) || (alignment > 0x800000000000ULL) ||
	    ((hweight32(alignment >> 32) +
	      hweight32(alignment & 0xffffffff) != 1))) {
		HPSB_ERR("%s called with invalid alignment: 0x%048llx",
			 __FUNCTION__, (unsigned long long)alignment);
		return retval;
	}

	if (start == ~0ULL && end == ~0ULL) {
		start = CSR1212_ALL_SPACE_BASE + 0xffff00000000ULL;  /* ohci1394.c limit */
		end = CSR1212_ALL_SPACE_END;
	}

	if (((start|end) & ~align_mask) || (start >= end) || (end > 0x1000000000000ULL)) {
		HPSB_ERR("%s called with invalid addresses (start = %012Lx    end = %012Lx)",
			 __FUNCTION__, (unsigned long long)start, (unsigned long long)end);
		return retval;
	}

	as = (struct hpsb_address_serve *)
		kmalloc(sizeof(struct hpsb_address_serve), GFP_KERNEL);
	if (as == NULL) {
		return retval;
	}

	INIT_LIST_HEAD(&as->host_list);
	INIT_LIST_HEAD(&as->hl_list);
	as->op = ops;
	as->host = host;

	write_lock_irqsave(&addr_space_lock, flags);

	list_for_each(entry, &host->addr_space) {
		u64 a1sa, a1ea;
		u64 a2sa, a2ea;

		a1 = list_entry(entry, struct hpsb_address_serve, host_list);
		a2 = list_entry(entry->next, struct hpsb_address_serve, host_list);

		a1sa = a1->start & align_mask;
		a1ea = (a1->end + alignment -1) & align_mask;
		a2sa = a2->start & align_mask;
		a2ea = (a2->end + alignment -1) & align_mask;

		if ((a2sa - a1ea >= size) && (a2sa - start >= size) && (a2sa > start)) {
			as->start = max(start, a1ea);
			as->end = as->start + size;
			list_add(&as->host_list, entry);
			list_add_tail(&as->hl_list, &hl->addr_list);
			retval = as->start;
			break;
		}
	}

	write_unlock_irqrestore(&addr_space_lock, flags);

	if (retval == ~0ULL) {
		kfree(as);
	}

	return retval;
}


/**
 * @ingroup highlevel
 * @anchor hpsb_register_addrspace
 * To register an address space for a certain highlevel module on a certain host
 *
 * @param hl the pointer to highlevel module
 * @param the host to register addr space to
 * @param ops the pointer to address space operations
 * @param start, end the stand and end address 
 * @return 1 on success. 
 *
 * @note the new address can only be successfully registerred 
 * if it doesnt have any overlap with other registerred space,
 * i.e. the one before it and the one behind. 
 */

int hpsb_register_addrspace(struct hpsb_highlevel *hl, struct hpsb_host *host,
                            struct hpsb_address_ops *ops, u64 start, u64 end)
{
	struct hpsb_address_serve *as;
        struct list_head *lh;
        int retval = 0;
        unsigned long flags;

        if (((start|end) & 3) || (start >= end) || (end > 0x1000000000000ULL)) {
                HPSB_ERR("%s called with invalid addresses", __FUNCTION__);
                return 0;
        }

        as = (struct hpsb_address_serve *)
                kmalloc(sizeof(struct hpsb_address_serve), GFP_KERNEL);
        if (as == NULL) {
                return 0;
        }

        INIT_LIST_HEAD(&as->host_list);
        INIT_LIST_HEAD(&as->hl_list);
        as->op = ops;
        as->start = start;
        as->end = end;
	as->host = host;

        write_lock_irqsave(&addr_space_lock, flags);
	
	list_for_each(lh, &host->addr_space) {
		struct hpsb_address_serve *as_this =
			list_entry(lh, struct hpsb_address_serve, host_list);
		struct hpsb_address_serve *as_next =
			list_entry(lh->next, struct hpsb_address_serve, host_list);

		if (as_this->end > as->start)
			break;

		if (as_next->start >= as->end) {
			list_add(&as->host_list, lh);
			list_add_tail(&as->hl_list, &hl->addr_list);
			retval = 1;
			break;
		}
	}
	write_unlock_irqrestore(&addr_space_lock, flags);

	if (retval == 0)
		kfree(as);

        return retval;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_unregister_addrspace
 * To unregister an address space. 
 *
 * This includes unregister the address space from 
 * both global list and highlevel module list. 
 * 
 * @return  1 on success. Otherwise 0 (possibly address space is not registered). 
 */
int hpsb_unregister_addrspace(struct hpsb_highlevel *hl, struct hpsb_host *host, u64 start)
{
        int retval = 0;
        struct hpsb_address_serve *as;
        struct list_head *lh, *next;
        unsigned long flags;

        write_lock_irqsave(&addr_space_lock, flags);

        lh = hl->addr_list.next;

	list_for_each_safe (lh, next, &hl->addr_list) {
                as = list_entry(lh, struct hpsb_address_serve, hl_list);
                if (as->start == start && as->host == host) {
			__delete_addr(as);
                        retval = 1;
                        break;
                }
        }
	
        write_unlock_irqrestore(&addr_space_lock, flags);

        return retval;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_listen_channel
 * To register listenning to a certain channel
 * 
 * @param channel number can not be larger than 63. 
 * @param isoconfig
 * @return 0 on success. 
 */
int hpsb_listen_channel(struct hpsb_highlevel *hl, struct hpsb_host *host,
                         unsigned int channel)
{
        //~ int ret;
	//~ struct hpsb_iso *iso;
	//~ unsigned int data_buf_size = isoconfig->data_buf_size;
	//~ unsigned int buf_packets = isoconfig->buf_packets;
	//~ int channel=isoconfig->channel;
	//~ int irqinterval = isoconfig->irqinterval;
	//~ int dma_mode = isoconfig->dma_mode;
	//~ int pri = isoconfig->pri;
	
	if (channel > 63 || channel < 0) {
                HPSB_ERR("%s called with invalid channel", hl->name);
                return -EINVAL;
        }
	
	if(host->iso_listen_count[channel]++==0){
		//this channel on hardware was not opened
		HPSB_NOTICE("%s try to allocate channel[%d]\n", hl->name, channel);
		return host->driver->devctl(host, ISO_LISTEN_CHANNEL, channel);
	}	
	
	return 0;
	//~ if (host->iso_listen_count[channel]++ > 0) {
		//~ //one channel can only be listened by one highlevel
		//~ HPSB_ERR("%s try to allocate channel %d which is already occupied\n", hl->name, channel);
	//~ }
	
	//~ //now we start to operation on software level
	//~ iso = hpsb_iso_recv_init(host,data_buf_size,buf_packets, channel,
						//~ dma_mode,irq_interval,isoconfig->callback,isoconfig->arg,pri);
	//~ if(iso==NULL){
		//~ ret = -ENOMEM;
		//~ goto isofail;
	//~ }
	
	//~ //now on the hardware level
	//~ ret= host->driver->devctl(host, ISO_LISTEN_CHANNEL, channel);
	//~ if(ret) //hardware level operation failed
		//~ goto hwfail;
	
	//~ isoconfig->iso_handle = (void *)iso;
	//~ return ret;

//~ hwfail:
	//~ hpsb_iso_shutdown(iso);
//~ isofail:
	//~ return ret;
}

/**
 * @ingroup highlevel
 * @anchor hpsb_unlisten_channel
 * To unlisten to a certain channel 
 *
 * @param channel number, can not be larger 63. 
 * @return void
 *
*/
void hpsb_unlisten_channel(struct hpsb_highlevel *hl, struct hpsb_host *host, 
                           unsigned int channel)
{
	
	if (channel > 63 || channel < 0) {
                HPSB_ERR("%s called with invalid channel", hl->name);
                return;
        }

        if (--host->iso_listen_count[channel] == 0) {
                host->driver->devctl(host, ISO_UNLISTEN_CHANNEL, channel);
        }
		//~ }else{
		//~ //one channel can only be listened by one highlevel
		//~ HPSB_ERR("%d channel is occupied by multiple highlevels!!!\n", channel);
	//~ }
	
	//~ struct hpsb_iso *iso=(struct hpsb_iso *)isoconfig->iso_handle;
	//~ hpsb_iso_shutdown(iso);
}

/**
 * @ingroup highlevel
 * @anchor init_hpsb_highlevel
 * Initialization of highlevel managment module on a certain host. 
 * 
 * @note see @ref highlevel module management section of "Overview of Real-Time Firewire stack". 
 */
static void init_hpsb_highlevel(struct hpsb_host *host)
{
	INIT_LIST_HEAD(&dummy_zero_addr.host_list);
	INIT_LIST_HEAD(&dummy_zero_addr.hl_list);
	INIT_LIST_HEAD(&dummy_max_addr.host_list);
	INIT_LIST_HEAD(&dummy_max_addr.hl_list);

	dummy_zero_addr.op = dummy_max_addr.op = &dummy_ops;

	dummy_zero_addr.start = dummy_zero_addr.end = 0;
	dummy_max_addr.start = dummy_max_addr.end = ((u64) 1) << 48;

	list_add_tail(&dummy_zero_addr.host_list, &host->addr_space);
	list_add_tail(&dummy_max_addr.host_list, &host->addr_space);
}

/**
 * @ingroup highlevel
 * @anchor highlevel_add_host
 * Called when a new host is added, also update the host config rom. 
 *
 */
void highlevel_add_host(struct hpsb_host *host)
{
	struct hpsb_highlevel *hl = NULL;
	struct list_head *lh;
		
	init_hpsb_highlevel(host);

        read_lock(&hl_drivers_lock);
        list_for_each(lh, &hl_drivers) {
                hl = list_entry(lh, struct hpsb_highlevel, hl_list);
		if (hl->add_host)
			hl->add_host(host);
        }
        read_unlock(&hl_drivers_lock);
	
	//~ if (host->update_config_rom) {
		//~ if (hpsb_update_config_rom_image(host) < 0)
			//~ HPSB_ERR("Failed to generate Configuration ROM image for "
				 //~ "host %s-%d", hl->name, host->ifindex);
	//~ }
}

/**
 * @ingroup highlevel
 * @anchor highlevel_remove_host
 * Called when a new host is removed. 
 *
 */
void highlevel_remove_host(struct hpsb_host *host)
{
        struct hpsb_highlevel *hl;
	
	read_lock(&hl_drivers_lock);
	list_for_each_entry(hl, &hl_drivers, hl_list)
		__unregister_host(hl, host, 0);
	read_unlock(&hl_drivers_lock);
}


/**
 * @ingroup highlevel
 * @anchor highlevel_host_reset
 * Called when a new host is resetted. 
 *
 */
void highlevel_host_reset(struct hpsb_host *host)
{
	struct hpsb_highlevel *hl;

	read_lock(&hl_irqs_lock);
	list_for_each_entry(hl, &hl_irqs, irq_list) {
                if (hl->host_reset)
                        hl->host_reset(host);
        }
	read_unlock(&hl_irqs_lock);
}

/**
 * @ingroup highlevel
 * @anchor highlevel_iso_receive
 * Called when isochronous data is received.
 *
 * @param data - pointer to received data, 
 * including iso header. 
 * @param length - the length of data. 
 * 
 * @note the channel number is parsed from data header. 
 */
void highlevel_iso_receive(struct hpsb_host *host, quadlet_t *data,
			   size_t length)
{
        struct hpsb_highlevel *hl;
        int channel = (((quadlet_t *)data)[0] >> 8) & 0x3f;

        read_lock(&hl_irqs_lock);
	list_for_each_entry(hl, &hl_irqs, irq_list) {
                if (hl->iso_receive)
                        hl->iso_receive(host, channel, data, length);
        }
        read_unlock(&hl_irqs_lock);
}

/**
 * @ingroup highlevel
 * @anchor highlevel_fcp_request
 * Called when the fcp register (in csr) is accessed. 
 *
 * @param direction -- fcp command or fcp response
 * @param data --  received data
 * @param length -- length of data
 */
void highlevel_fcp_request(struct hpsb_host *host, int nodeid, int direction,
			   quadlet_t *data, size_t length)
{
        struct hpsb_highlevel *hl;
        int cts = (data)[0] >> 4;

        read_lock(&hl_irqs_lock);
	list_for_each_entry(hl, &hl_irqs, irq_list) {
                if (hl->fcp_request)
                        hl->fcp_request(host, nodeid, direction, cts, data,
					length);
        }
        read_unlock(&hl_irqs_lock);
}

/**
 * @ingroup highlevel
 * @anchor highlevel_read
 * Called when a read operation occurs in a certain range of address
 *
 * @param addr -  the accessed address
 * @param flags - the low 16 bits of first quadlet of data. 
 *
 * @return rcode - the return code of read access. 
 * - @b RCODE_COMPLETE: returned by highlevel module "read" routine. 
 * - @b RCODE _ADDRESS_ERROR: the address is not registered
 * - @b RCODE _TYPE_ERROR:  no "read" routine is registered for that address
 * 
 * @note the accessed address range can cover more then 1  highlevel module-registered space. 
 * Thus more then 1 "read" routines maybe called. 
 *
 * @note see @ref highlevel module management section of "Overview of Real-Time Firewire stack". 
 */
int highlevel_read(struct hpsb_host *host, struct hpsb_packet *req, quadlet_t *data, unsigned int length)
{
        u64 addr = (((u64)(req->header[1] & 0xffff))<<32) | req->header[2];
	
	struct hpsb_address_serve *as;
        //~ unsigned int partlength;
        int rcode = RCODE_ADDRESS_ERROR;

        read_lock(&addr_space_lock);

	list_for_each_entry(as, &host->addr_space, host_list) {
		if (as->start > addr)
			break;

                if (as->end > addr) {
                        //~ partlength = min(as->end - addr, (u64) length);
			if(as->end - addr < (u64)length){
				HPSB_ERR("shared packet between multiple registered address ranges\
								is deprecated!\n");
				rcode = RCODE_ADDRESS_ERROR;
				break;
			}

                        if (as->op->read) {
                                rcode = as->op->read(host, req, data, length);
                        } else {
                                rcode = RCODE_TYPE_ERROR;
                        }
			break;

			//~ data += partlength;
                        //~ length -= partlength;
                        //~ addr += partlength;

                        //~ if ((rcode != RCODE_COMPLETE) || !length) {
                                //~ break;
                        //~ }
                }
        }

        read_unlock(&addr_space_lock);

        return rcode;
}

/**
 * @ingroup highlevel
 * @anchor highlevel_write
 * Called when a write operation occurs in a certain range of address
 *
 * @param addr -  the accessed address
 * @param flags - the low 16 bits of first quadlet of data. 
 *
 * @return rcode - the return code of write access. 
 * - @b RCODE_COMPLETE: returned by highlevel module "write" routine. 
 * - @b RCODE _ADDRESS_ERROR: the address is not registered
 * - @b RCODE _TYPE_ERROR:  no "write" routine is registered for that address
 * 
 * @note the accessed address range can cover more then 1  highlevel module-registered space. 
 * Thus more then 1 "write" routines maybe called. 
 *
 * @note see @ref highlevel module management section of "Overview of Real-Time Firewire stack". 
 */
int highlevel_write(struct hpsb_host *host, struct hpsb_packet *req, unsigned int length)
{
	 u64 addr = (((u64)(req->header[1] & 0xffff))<<32) | req->header[2];
	
	struct hpsb_address_serve *as;
        //~ unsigned int partlength;
        int rcode = RCODE_ADDRESS_ERROR;

        read_lock(&addr_space_lock);

	list_for_each_entry(as, &host->addr_space, host_list) {
		if (as->start > addr)
			break;

                if (as->end > addr) {
                        //~ partlength = min(as->end - addr, (u64) length);
			if(as->end - addr < (u64)length){
				HPSB_ERR("shared packet between multiple registered address ranges\
								is deprecated!\n");
				rcode = RCODE_ADDRESS_ERROR;
				break;
			}

                        if (as->op->write) {
                                rcode = as->op->write(host, req, length);
                        } else {
                                rcode = RCODE_TYPE_ERROR;
                        }
			break;

			//~ data += partlength;
                        //~ length -= partlength;
                        //~ addr += partlength;

                        //~ if ((rcode != RCODE_COMPLETE) || !length) {
                                //~ break;
                        //~ }
                }
        }

        read_unlock(&addr_space_lock);

        //~ if (length && (rcode == RCODE_COMPLETE)) {
                //~ rcode = RCODE_ADDRESS_ERROR;
        //~ }

        return rcode;
}

/**
 * @ingroup highlevel
 * @anchor highlevel_lock
 * Called when a lock operation occurs in a certain range of address
 *
 * @param addr -  the accessed address
 * @param flags - the low 16 bits of first quadlet of data. 
 *
 * @return rcode - the return code of lock access. 
 * - @b RCODE_COMPLETE: returned by highlevel module "lock" routine. 
 * - @b RCODE _ADDRESS_ERROR: the address is not registered
 * - @b RCODE _TYPE_ERROR:  no "lock" routine is registered for that address
 * 
 * @note the accessed address range can not cover more then 1  highlevel module-registered space. 
 * Thus only 1 "lock" routine can be called. 
 *
 * @note see @ref highlevel module management section of "Overview of Real-Time Firewire stack". 
 */
int highlevel_lock(struct hpsb_host *host, struct hpsb_packet *req, quadlet_t *store)
{
        u64 addr = (((u64)(req->header[1] & 0xffff))<<32) | req->header[2];
	
	struct hpsb_address_serve *as;
        int rcode = RCODE_ADDRESS_ERROR;

        read_lock(&addr_space_lock);

	list_for_each_entry(as, &host->addr_space, host_list) {
		if (as->start > addr)
			break;

                if (as->end > addr) {
                        if (as->op->lock) {
                                rcode = as->op->lock(host, req, store);
                        } else {
                                rcode = RCODE_TYPE_ERROR;
                        }

                        break;
                }
        }

        read_unlock(&addr_space_lock);

        return rcode;
}


/**
 * @ingroup highlevel
 * @anchor highlevel_lock64
 * Called when a lock operation occurs in a certain range of address
 *
 * @param addr -  the accessed address
 * @param flags - the low 16 bits of first quadlet of data. 
 *
 * @return rcode - the return code of lock access. 
 * - @b RCODE_COMPLETE: returned by highlevel module "lock64" routine. 
 * - @b RCODE _ADDRESS_ERROR: the address is not registered
 * - @b RCODE _TYPE_ERROR:  no "lock64" routine is registered for that address
 * 
 * @note the accessed address range can not cover more then 1  highlevel module-registered space. 
 * Thus only 1 "lock64" routine can be called. 
 *
 * @note see @ref highlevel module management section of "Overview of Real-Time Firewire stack". 
 */
int highlevel_lock64(struct hpsb_host *host, struct hpsb_packet *req, octlet_t *store)
{
        u64 addr = (((u64)(req->header[1] & 0xffff))<<32) | req->header[2];
	
	struct hpsb_address_serve *as;
        int rcode = RCODE_ADDRESS_ERROR;

        read_lock(&addr_space_lock);

	list_for_each_entry(as, &host->addr_space, host_list) {
		if (as->start > addr)
			break;

                if (as->end > addr) {
                        if (as->op->lock64) {
                                rcode = as->op->lock64(host, req, store);
                        } else {
                                rcode = RCODE_TYPE_ERROR;
                        }

                        break;
                }
        }

        read_unlock(&addr_space_lock);

        return rcode;
}




