/* rtfirewire/stack/iso.c
 * Application interface for isochronous transaction of RT-FireWire.
 * adapted from Linux 1394subsystem.  
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
 * @ingroup iso
 * @file
 * 
 * Implementation of iso module
 */

#include <linux/slab.h>
#include <linux/sched.h>
#include <iso.h>
#include <ieee1394_types.h>
#include <ieee1394.h>
#include <hosts.h>
#include <ieee1394_core.h>
#include <highlevel.h>
#include <ieee1394_transactions.h>
#include <csr.h>

#define 	QUADLET_SIZE 	32
#define 	QUADLET_MASK 	(~(QUADLET_SIZE-1))
#define	QUADLET_ALIGN(val)	(((val)+QUADLET_SIZE-1) & QUADLET_MASK)

int hpsb_iso_res_release(struct hpsb_iso *iso);
	
/**
 * @ingroup iso
 * @anchor hpsb_iso_stop
 * stop the hardware from xmitting or receiving
 */
void hpsb_iso_stop(struct hpsb_iso *iso)
{
	if (!(iso->flags & HPSB_ISO_STARTED))
		return;

	iso->host->driver->isoctl(iso, iso->type == HPSB_ISO_XMIT ?
				  XMIT_STOP : RECV_STOP, 0);
	iso->flags &= ~HPSB_ISO_STARTED;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_shutdown
 * shutdown the hardware from xmitting or receiving.
 */
void hpsb_iso_shutdown(struct hpsb_iso *iso)
{
	if (iso->flags & HPSB_ISO_RES_INIT) {
		hpsb_iso_stop(iso);
		iso->host->driver->isoctl(iso, iso->type == HPSB_ISO_XMIT ?
					  XMIT_SHUTDOWN : RECV_SHUTDOWN, 0);
		iso->flags &= ~HPSB_ISO_RES_INIT;
	}

	dma_region_free(&iso->data_buf);
	
	if(iso->type == HPSB_ISO_XMIT){
		//we are still owning some bandwidth and channel number, so need to release them here
		if(hpsb_iso_res_release(iso))
			HPSB_ERR("failed to release iso %s!!!\n",iso->name);
	}
	
	kfree(iso);
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_common_init
 * initialize the common iso structure for a host
 *  - buufferd packets
 *  - dma receving mode
 *  - irq interval
 *  - xmit or recv channel
 *  - allocate the data buffer
 *  - assign the priority, which will be used for the bottomhalf server
 */
static struct hpsb_iso* hpsb_iso_common_init(struct hpsb_host *host, enum hpsb_iso_type type,
					     unsigned int data_buf_size,
					     unsigned int buf_packets,
					     int channel,
					     int dma_mode,
					     int irq_interval,
					     void (*callback)(struct hpsb_iso*, void*),
					     void* arg,
					     unsigned char *name,
					      int pri)
{
	struct hpsb_iso *iso;
	int dma_direction;
	
	/* make sure driver supports the ISO API */
	if (!host->driver->isoctl) {
		HPSB_ERR("ieee1394: host driver '%s' does not support the rawiso API\n",
		       host->driver->name);
		return NULL;
	}

	/* sanitize parameters */

	if (buf_packets < 2)
		buf_packets = 2;

	if ((dma_mode < HPSB_ISO_DMA_DEFAULT) || (dma_mode > HPSB_ISO_DMA_PACKET_PER_BUFFER))
		dma_mode=HPSB_ISO_DMA_DEFAULT;

	if (irq_interval == 0)     /* really interrupt for each packet*/
		irq_interval = 1;
	else if ((irq_interval < 0) || (irq_interval > buf_packets / 4))
 		irq_interval = buf_packets / 4;

	if (channel < -1 || channel >= 64)
		return NULL;

	/* channel = -1 is OK for multi-channel recv but not for xmit */
	if (type == HPSB_ISO_XMIT && channel < 0)
		return NULL;

	/* allocate and write the struct hpsb_iso */

	iso = kmalloc(sizeof(*iso) + buf_packets * sizeof(struct hpsb_iso_packet_info), GFP_KERNEL);
	if (!iso)
		return NULL;

	iso->infos = (struct hpsb_iso_packet_info *)(iso + 1);

	iso->type = type;
	iso->host = host;
	iso->hostdata = NULL;
	iso->callback = callback;
	iso->arg = arg;
	//~ init_waitqueue_head(&iso->waitq);
	iso->channel = channel;
	iso->irq_interval = irq_interval;
	iso->dma_mode = dma_mode;
	dma_region_init(&iso->data_buf);
	//~ iso->buf_size = PAGE_ALIGN(data_buf_size);
	iso->buf_size = QUADLET_ALIGN(data_buf_size);
	iso->buf_packets = buf_packets;
	iso->pkt_dma = 0;
	iso->first_packet = 0;
	rtos_spin_lock_init(&iso->lock);
	iso->pri = pri;
	iso->bandwidth = -1;

	if (iso->type == HPSB_ISO_XMIT) {
		iso->n_ready_packets = iso->buf_packets;
		dma_direction = PCI_DMA_TODEVICE;
	} else {
		iso->n_ready_packets = 0;
		dma_direction = PCI_DMA_FROMDEVICE;
	}

	atomic_set(&iso->overflows, 0);
	iso->flags = 0;
	iso->prebuffer = 0;

	/* allocate the packet buffer */
	if (dma_region_alloc(&iso->data_buf, iso->buf_size, host->pdev, dma_direction))
		goto err;
	
	snprintf(iso->name, 32, name);

	return iso;

err:
	hpsb_iso_shutdown(iso);
	return NULL;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_n_ready
 * return the number of ready packets. 
 */
int hpsb_iso_n_ready(struct hpsb_iso *iso)
{
	unsigned long flags;
	int val;

	rtos_spin_lock_irqsave(&iso->lock, flags);
	val = iso->n_ready_packets;
	rtos_spin_unlock_irqrestore(&iso->lock, flags);

	return val;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_res_release
 * release the isochronous resource 
 */
int hpsb_iso_res_release(struct hpsb_iso *iso)
{
	struct hpsb_host *host;
	int channel, gen;
	unsigned int bandwidth;
	nodeid_t irm_id;
	quadlet_t new, old;
	u64 ch_addr;
	
	host = iso->host;
	channel = iso->channel;
	bandwidth = iso->bandwidth;
	irm_id = host->irm_id;
	
	gen = get_hpsb_generation(iso->host);
	
	if(!(iso->flags & HPSB_ISO_RES_ALLOC)) {
		HPSB_ERR("iso %s is not allocated\n", iso->name);
		return 0;
	}
	
	/**release the channel first**/
	if(channel>=0 && channel<=31)
		ch_addr = CSR_CHANNELS_AVAILABLE_LO;
	else{
		if(channel>=32 && channel<=63){
			channel = channel - 32;
			ch_addr = CSR_CHANNELS_AVAILABLE_HI;
		}
		else{
			HPSB_ERR("out of range channel number %d\n", channel);
			return -EINVAL;
		}
	}
	
	if (hpsb_read(host, irm_id, gen,  ch_addr+CSR_REGISTER_BASE, 
						&old, sizeof(old), IEEE1394_PRIORITY_HIGHEST))
	{
		HPSB_ERR("failed to read available channel number\n");
		return -EAGAIN;
	}
	HPSB_NOTICE("%s:%x",ch_addr==CSR_CHANNELS_AVAILABLE_HI \
								? "channle hi":"channel lo", old); 
	
	new = old | (swab32(1UL<<channel)); //not sure if this is correct
	
	if(hpsb_lock(host, irm_id, gen, ch_addr+CSR_REGISTER_BASE, 
					EXTCODE_COMPARE_SWAP, &new, old,IEEE1394_PRIORITY_HIGHEST))
	{
		HPSB_ERR("failed to deallocate required channel\n");
		return -EAGAIN;
	}
	
	iso->channel = -1;
	HPSB_NOTICE("channel %d deallocated\n",channel);
	
	if(bandwidth!=-1){
		/** deallocate the bandwidth **/
		if (hpsb_read(host, irm_id, gen,  CSR_BANDWIDTH_AVAILABLE+CSR_REGISTER_BASE, 
						&old, sizeof(old), IEEE1394_PRIORITY_HIGHEST))
		{
			HPSB_ERR("failed to read available bandwidth\n");
			return -EAGAIN;
		}
	
		new = be32_to_cpu(old) + bandwidth; //also include the header size
		HPSB_NOTICE("new bandwidth: %d\n", new); 
		new = cpu_to_be32(new);
	
		if(hpsb_lock(host, irm_id, gen, CSR_BANDWIDTH_AVAILABLE+CSR_REGISTER_BASE, 
					EXTCODE_COMPARE_SWAP, &new, old,IEEE1394_PRIORITY_HIGHEST))
		{
			HPSB_ERR("failed to allocate required bandwidth\n");
			return -EAGAIN;
		}
		iso->bandwidth = -1;
		
		iso->flags &= ~HPSB_ISO_RES_ALLOC;
	
		HPSB_NOTICE("bandwidth %d units released\n",bandwidth);
	}
	
	return 0;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_rec_alloc
 * this function allocates the resource for a certain iso xmit 
 * context
 */
/*the nubmer of bw units needed to transmit a byte at speed 100Mb/s*/
#define BASE_UNITS_PERBYTE 5 
int hpsb_iso_res_alloc(struct hpsb_iso *iso)
{
	struct hpsb_host *host;
	int channel, gen;
	unsigned int bandwidth;
	nodeid_t irm_id;
	quadlet_t new, old;
	u64 ch_addr;
	
	if(!(iso->flags & HPSB_ISO_RES_INIT)){
		HPSB_ERR("iso %s is not initialized\n", iso->name);
		return -EINVAL;
	}
	
	if(iso->flags & HPSB_ISO_RES_ALLOC) {
		HPSB_ERR("iso %s is already allocated\n", iso->name);
		return 0;
	}
	
	host = iso->host;
	channel = iso->channel;
	bandwidth = iso->bandwidth;
	irm_id = host->irm_id;
	
	gen = get_hpsb_generation(iso->host);
	
	if(channel>=0 && channel<=31)
		ch_addr = CSR_CHANNELS_AVAILABLE_LO;
	else 
		if(channel>=32 && channel<=63)
		{
			channel = channel - 32;
			ch_addr = CSR_CHANNELS_AVAILABLE_HI;
		}
		else{
			HPSB_ERR("out of range channel number %d\n", channel);
			return -EINVAL;
		}
	

	/*** allocate channel ***/
	if (hpsb_read(host, irm_id, gen,  ch_addr+CSR_REGISTER_BASE, 
						&old, sizeof(old), IEEE1394_PRIORITY_HIGHEST))
	{
		HPSB_ERR("failed to read available channel\n");
		return -EAGAIN;
	}
	
	HPSB_NOTICE("old channels: %x\n", be32_to_cpu(old));
	new = be32_to_cpu(old) & (~(1<<channel)); //not sure if this is correct
	HPSB_NOTICE("new channels: %x\n", new);
	new = cpu_to_be32(new);
	if(new == old) {
		HPSB_ERR("channle %d already in use\n",channel);
		return -EBUSY;
	}
	
	if(hpsb_lock(host, irm_id, gen, ch_addr+CSR_REGISTER_BASE, 
					EXTCODE_COMPARE_SWAP, &new, old,IEEE1394_PRIORITY_HIGHEST))
	{
		HPSB_ERR("failed to allocate required channel\n");
		return -EAGAIN;
	}
	
	HPSB_NOTICE("channel %d allocated\n",channel);
	
	
	/*** allocate bandwidth ***/
	if (hpsb_read(host, irm_id, gen,  CSR_BANDWIDTH_AVAILABLE+CSR_REGISTER_BASE, 
						&old, sizeof(old), IEEE1394_PRIORITY_HIGHEST))
	{
		HPSB_ERR("failed to read available bandwidth\n");
		return -EAGAIN;
	}

	new = be32_to_cpu(old) - bandwidth; //also include the header size
	HPSB_NOTICE("new bandwidth: %d\n", new); 
	new = cpu_to_be32(new);
	
	if(hpsb_lock(host, irm_id, gen, CSR_BANDWIDTH_AVAILABLE+CSR_REGISTER_BASE, 
					EXTCODE_COMPARE_SWAP, &new, old,IEEE1394_PRIORITY_HIGHEST))
	{
		HPSB_ERR("failed to allocate required bandwidth\n");
		return -EAGAIN;
	}
	
	iso->flags |= HPSB_ISO_RES_ALLOC;

	HPSB_NOTICE("bandwidth %d units allocated\n",iso->bandwidth);
	
	return 0;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_xmit_init
 * initialize xmit in driver
 * change the iso flags to HPSB_ISO_RES_INIT
 */
struct hpsb_iso* hpsb_iso_xmit_init(struct hpsb_host *host,
				    unsigned int data_buf_size,
				    unsigned int buf_packets,
				    int channel,
				    int speed,
				    int irq_interval,
				    void (*callback)(struct hpsb_iso*, void*),
				    void *arg,
				    unsigned char *name,
					int pri)
{
	int speed_val;
	
	struct hpsb_iso *iso = hpsb_iso_common_init(host, HPSB_ISO_XMIT,
						    data_buf_size, buf_packets,
						    channel, HPSB_ISO_DMA_DEFAULT, irq_interval, callback, arg, name, pri);
	if (!iso)
		return NULL;

	iso->speed = speed;
	
	if(speed>=0 && speed<=5)
		speed_val = hpsb_speedto_val[iso->speed]/hpsb_speedto_val[0];
	else
		return NULL;
	
	/** we calculate the bandwidth here **/
	iso->bandwidth = ((iso->buf_size + 8)*BASE_UNITS_PERBYTE)/speed_val+1;
	
	/** also assign the channel number **/
	iso->channel = channel;

	/* tell the driver to start working */
	if (host->driver->isoctl(iso, XMIT_INIT, 0))
		goto err;

	iso->flags |= HPSB_ISO_RES_INIT;
	
	HPSB_NOTICE("bandwidth:%d, channel:%d\n", iso->bandwidth, iso->channel);
	
	if(hpsb_iso_res_alloc(iso)){
		goto err;
	}
	
	return iso;

err:
	hpsb_iso_shutdown(iso);
	return NULL;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_recv_init
 * initialize the recv in driver
 * change the iso->flags to HPSB_ISO_RES_INIT
 */
struct hpsb_iso* hpsb_iso_recv_init(struct hpsb_host *host,
				    unsigned int data_buf_size,
				    unsigned int buf_packets,
				    int channel,
				    int dma_mode,
				    int irq_interval,
				    void (*callback)(struct hpsb_iso*, void*), 
				    void *arg,		
				    unsigned char *name,
				    int pri)
{
	struct hpsb_iso *iso = hpsb_iso_common_init(host, HPSB_ISO_RECV,
						    data_buf_size, buf_packets,
						    channel, dma_mode, irq_interval, callback, arg, name, pri);
	
	if (!iso)
		return NULL;

	/* tell the driver to start working */
	if (host->driver->isoctl(iso, RECV_INIT, 0))
		goto err;

	iso->flags |= HPSB_ISO_RES_INIT;
	return iso;

err:
	hpsb_iso_shutdown(iso);
	return NULL;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_recv_listen_channel
 */
int hpsb_iso_recv_listen_channel(struct hpsb_iso *iso, unsigned char channel)
{
	if (iso->type != HPSB_ISO_RECV || iso->channel != -1 || channel >= 64)
		return -EINVAL;
	return iso->host->driver->isoctl(iso, RECV_LISTEN_CHANNEL, channel);
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_recv_unlisten_channel
 */
int hpsb_iso_recv_unlisten_channel(struct hpsb_iso *iso, unsigned char channel)
{
       if (iso->type != HPSB_ISO_RECV || iso->channel != -1 || channel >= 64)
               return -EINVAL;
       return iso->host->driver->isoctl(iso, RECV_UNLISTEN_CHANNEL, channel);
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_recv_set_channel_mask
 */
int hpsb_iso_recv_set_channel_mask(struct hpsb_iso *iso, u64 mask)
{
	if (iso->type != HPSB_ISO_RECV || iso->channel != -1)
		return -EINVAL;
	return iso->host->driver->isoctl(iso, RECV_SET_CHANNEL_MASK, (unsigned long) &mask);
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_recv_flush
 */
int hpsb_iso_recv_flush(struct hpsb_iso *iso)
{
	(struct hpsb_iso*)iso=iso;
	if (iso->type != HPSB_ISO_RECV)
		return -EINVAL;
	return iso->host->driver->isoctl(iso, RECV_FLUSH, 0);
}

/**
 * @ingroup iso
 * @anchor do_iso_xmit_start
 */
static int do_iso_xmit_start(struct hpsb_iso *iso, int cycle)
{
	int retval;

	retval = iso->host->driver->isoctl(iso, XMIT_START, cycle);
	if (retval)
		return retval;

	iso->flags |= HPSB_ISO_STARTED;
	return retval;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_xmit_start
 */
int hpsb_iso_xmit_start(struct hpsb_iso *iso, int cycle, int prebuffer)
{
	if (iso->type != HPSB_ISO_XMIT)
		return -1;

	if (iso->flags & HPSB_ISO_STARTED)
		return 0;

	if (cycle < -1)
		cycle = -1;
	else if (cycle >= 8000)
		cycle %= 8000;

	iso->xmit_cycle = cycle;

	if (prebuffer < 0)
		prebuffer = iso->buf_packets;
	else if (prebuffer == 0)
		prebuffer = 1;

	if (prebuffer > iso->buf_packets)
		prebuffer = iso->buf_packets;

	iso->prebuffer = prebuffer;

	/*! remember the starting cycle; DMA will commence from xmit_queue_packets()
	   once enough packets have been buffered */
	iso->start_cycle = cycle;

	return 0;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_recv_start
 */
int hpsb_iso_recv_start(struct hpsb_iso *iso, int cycle, int tag_mask, int sync)
{
	int retval = 0;
	int isoctl_args[3];

	if (iso->type != HPSB_ISO_RECV)
		return -1;

	if (iso->flags & HPSB_ISO_STARTED)
		return 0;

	if (cycle < -1)
		cycle = -1;
	else if (cycle >= 8000)
		cycle %= 8000;

	isoctl_args[0] = cycle;

	if (tag_mask < 0)
		/* match all tags */
		tag_mask = 0xF;
	isoctl_args[1] = tag_mask;

	isoctl_args[2] = sync;

	retval = iso->host->driver->isoctl(iso, RECV_START, (unsigned long) &isoctl_args[0]);
	if (retval)
		return retval;

	iso->flags |= HPSB_ISO_STARTED;
	return retval;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_check_offset_len
 */
/*! check to make sure the user has not supplied bogus values of offset/len
   that would cause the kernel to access memory outside the buffer */
static int hpsb_iso_check_offset_len(struct hpsb_iso *iso,
				     unsigned int offset, unsigned short len,
				     unsigned int *out_offset, unsigned short *out_len)
{
	if (offset >= iso->buf_size)
		return -EFAULT;

	/* make sure the packet does not go beyond the end of the buffer */
	if (offset + len > iso->buf_size)
		return -EFAULT;

	/* check for wrap-around */
	if (offset + len < offset)
		return -EFAULT;

	/* now we can trust 'offset' and 'length' */
	*out_offset = offset;
	*out_len = len;

	return 0;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_xmit_queue_packet
 * 
 * @note it maps the data to dma for xmitting, 
 * only until the buffer is full, the xmit controller will
 * be started to do real xmitting. 
 */
int hpsb_iso_xmit_queue_packet(struct hpsb_iso *iso, u32 offset, u16 len, u8 tag, u8 sy)
{
	struct hpsb_iso_packet_info *info;
	unsigned long flags;
	int rv;

	if (iso->type != HPSB_ISO_XMIT)
		return -EINVAL;

	/* is there space in the buffer? */
	if (iso->n_ready_packets <= 0) {
		return -EBUSY;
	}

	info = &iso->infos[iso->first_packet];

	/* check for bogus offset/length */
	if (hpsb_iso_check_offset_len(iso, offset, len, &info->offset, &info->len))
		return -EFAULT;

	info->tag = tag;
	info->sy = sy;

	rtos_spin_lock_irqsave(&iso->lock, flags);

	rv = iso->host->driver->isoctl(iso, XMIT_QUEUE, (unsigned long) info);
	if (rv)
		goto out;

	/* increment cursors */
	iso->first_packet = (iso->first_packet+1) % iso->buf_packets;
	iso->xmit_cycle = (iso->xmit_cycle+1) % 8000;
	iso->n_ready_packets--;

	if (iso->prebuffer != 0) {
		iso->prebuffer--;
		if (iso->prebuffer <= 0) {
			iso->prebuffer = 0;
			rv = do_iso_xmit_start(iso, iso->start_cycle);
		}
	}

out:
	rtos_spin_unlock_irqrestore(&iso->lock, flags);
	return rv;
}

void hpsb_iso_xmit_callback(struct hpsb_iso *iso, void *sem)
{
	rtos_event_signal((rtos_event_t *)sem);
}
/**
 * @ingroup iso
 * @anchor hpsb_iso_xmit_sync
 */
int hpsb_iso_xmit_sync(struct hpsb_iso *iso)
{
	if (iso->type != HPSB_ISO_XMIT)
		return -EINVAL;
	
	rtos_event_t sem;
	rtos_event_init(&sem);
	
	iso->callback = hpsb_iso_xmit_callback;
	iso->arg = (void *)&sem;
	
	rtos_event_wait(&sem);
	
	rtos_event_delete(&sem);
	
	return 0;
	//~ return wait_event_interruptible(iso->waitq, hpsb_iso_n_ready(iso) == iso->buf_packets);
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_packet_sent
 */
void hpsb_iso_packet_sent(struct hpsb_iso *iso, int cycle, int error)
{
	unsigned long flags;
	rtos_spin_lock_irqsave(&iso->lock, flags);

	/* predict the cycle of the next packet to be queued */

	/* jump ahead by the number of packets that are already buffered */
	cycle += iso->buf_packets - iso->n_ready_packets;
	cycle %= 8000;

	iso->xmit_cycle = cycle;
	iso->n_ready_packets++;
	iso->pkt_dma = (iso->pkt_dma + 1) % iso->buf_packets;

	if (iso->n_ready_packets == iso->buf_packets || error != 0) {
		/* the buffer has run empty! */
		atomic_inc(&iso->overflows);
	}

	rtos_spin_unlock_irqrestore(&iso->lock, flags);
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_packet_received
 */
void hpsb_iso_packet_received(struct hpsb_iso *iso, u32 offset, u16 len,
			      u16 cycle, u8 channel, u8 tag, u8 sy)
{
	unsigned long flags;
	rtos_spin_lock_irqsave(&iso->lock, flags);

	if (iso->n_ready_packets == iso->buf_packets) {
		/* overflow! */
		atomic_inc(&iso->overflows);
	} else {
		struct hpsb_iso_packet_info *info = &iso->infos[iso->pkt_dma];
		info->buf =offset+iso->data_buf.kvirt;
		info->offset = offset;
		info->len = len;
		info->cycle = cycle;
		info->channel = channel;
		info->tag = tag;
		info->sy = sy;

		iso->pkt_dma = (iso->pkt_dma+1) % iso->buf_packets;
		iso->n_ready_packets++;
	}

	rtos_spin_unlock_irqrestore(&iso->lock, flags);
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_recv_release_packets
 */
int hpsb_iso_recv_release_packets(struct hpsb_iso *iso, unsigned int n_packets)
{
	unsigned long flags;
	unsigned int i;
	int rv = 0;

	if (iso->type != HPSB_ISO_RECV)
		return -1;

	rtos_spin_lock_irqsave(&iso->lock, flags);
	for (i = 0; i < n_packets; i++) {
		rv = iso->host->driver->isoctl(iso, RECV_RELEASE,
					       (unsigned long) &iso->infos[iso->first_packet]);
		if (rv)
			break;

		iso->first_packet = (iso->first_packet+1) % iso->buf_packets;
		iso->n_ready_packets--;
	}
	rtos_spin_unlock_irqrestore(&iso->lock, flags);
	return rv;
}

/**
 * @ingroup iso
 * @anchor hpsb_iso_wake
 */
void hpsb_iso_wake(struct hpsb_iso *iso)
{
	//~ wake_up_interruptible(&iso->waitq);

	if (iso->callback)
		iso->callback(iso, iso->arg);
	else
		HPSB_ERR("iso[%s] has no callback!!!\n", iso->name);
}


