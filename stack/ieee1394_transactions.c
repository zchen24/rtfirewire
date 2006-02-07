/* rtfirewire/stack/ieee1394_transactions.c
 * Transaction helper module for RT-FireWire,
 * adapted from Linux 1394subsystem.
 * Copyright (C)  2005 Zhang Yuchen <yuchen623@gmail.com>
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
 * @ingroup trans
 * @file 
 *
 * Transaction helper module
 * - functions to make packets for different type of transaction
 * - functions to get/free transaction label
 * - functions to examine the result of transaction
 * - functions to do atomic transaction. 
 *
 */
 
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/smp_lock.h>
#include <linux/interrupt.h>

#include <asm/errno.h>

#include <ieee1394.h>
#include <ieee1394_types.h>
#include <hosts.h>
#include <ieee1394_core.h>
#include <highlevel.h>
#include <ieee1394_transactions.h>


#define PREP_ASYNC_HEAD_ADDRESS(tc) \
        packet->tcode = tc; \
        packet->header[0] = (packet->node_id << 16) | (packet->tlabel << 10) \
                | (1 << 8) | (tc << 4) | (packet->pri); \
        packet->header[1] = (packet->host->node_id << 16) | (addr >> 32); \
        packet->header[2] = addr & 0xffffffff

/**
 * @ingroup trans
 * @anchor fill_async_readquad
 */
static void fill_async_readquad(struct hpsb_packet *packet, u64 addr)
{
        PREP_ASYNC_HEAD_ADDRESS(TCODE_READQ);
        packet->header_size = 12;
        packet->data_size = 0;
        packet->expect_response = 1;
}

/**
 * @ingroup trans
 * @anchor fill_async_readblock
 */
static void fill_async_readblock(struct hpsb_packet *packet, u64 addr, int length)
{
        PREP_ASYNC_HEAD_ADDRESS(TCODE_READB);
        packet->header[3] = length << 16;
        packet->header_size = 16;
        packet->data_size = 0;
        packet->expect_response = 1;
}

/**
 * @ingroup trans
 * @anchor fill_async_writequad
 */
static void fill_async_writequad(struct hpsb_packet *packet, u64 addr, quadlet_t data)
{
        PREP_ASYNC_HEAD_ADDRESS(TCODE_WRITEQ);
        packet->header[3] = data;
        packet->header_size = 16;
        packet->data_size = 0;
        packet->expect_response = 1;
}

/**
 * @ingroup trans
 * @anchor fill_async_writeblock
 */
static void fill_async_writeblock(struct hpsb_packet *packet, u64 addr, int length)
{
        PREP_ASYNC_HEAD_ADDRESS(TCODE_WRITEB);
        packet->header[3] = length << 16;
        packet->header_size = 16;
        packet->expect_response = 1;
        packet->data_size = length + (length % 4 ? 4 - (length % 4) : 0);
}

/**
 * @ingroup trans
 * @anchor fill_async_lock
 */
static void fill_async_lock(struct hpsb_packet *packet, u64 addr, int extcode,
                     int length)
{
        PREP_ASYNC_HEAD_ADDRESS(TCODE_LOCK_REQUEST);
        packet->header[3] = (length << 16) | extcode;
        packet->header_size = 16;
        packet->data_size = length;
        packet->expect_response = 1;
}

/**
 * @ingroup trans
 * @anchor fill_iso_packet
 */
static void fill_iso_packet(struct hpsb_packet *packet, int length, int channel,
                     int tag, int sync)
{
        packet->header[0] = (length << 16) | (tag << 14) | (channel << 8)
                | (TCODE_ISO_DATA << 4) | sync;

        packet->header_size = 4;
        packet->data_size = length;
        packet->type = hpsb_iso;
        packet->tcode = TCODE_ISO_DATA;
}

/**
 * @ingroup trans
 * @anchor fill_phy_packet
 */
static void fill_phy_packet(struct hpsb_packet *packet, quadlet_t data)
{
        packet->header[0] = data;
        packet->header[1] = ~data;
        packet->header_size = 8;
        packet->data_size = 0;
        packet->expect_response = 0;
        packet->type = hpsb_raw;             /* No CRC added */
        packet->speed_code = IEEE1394_SPEED_100; /* Force speed to be 100Mbps */
}

/**
 * @ingroup trans
 * @anchor fill_async_stream_packet
 */
static void fill_async_stream_packet(struct hpsb_packet *packet, int length,
				     int channel, int tag, int sync)
{
	packet->header[0] = (length << 16) | (tag << 14) | (channel << 8)
	                  | (TCODE_STREAM_DATA << 4) | sync;

	packet->header_size = 4;
	packet->data_size = length;
	packet->type = hpsb_async;
	packet->tcode = TCODE_ISO_DATA;
}

/**
 * @ingroup trans
 * @anchor hpsb_get_tlabel
 * allocate a transaction label
 *
 * Every asynchronous transaction on the 1394 bus needs a transaction
 * label to match the response to the request.  This label has to be
 * different from any other transaction label in an outstanding request to
 * the same node to make matching possible without ambiguity.
 *
 * There are 64 different tlabels, so an allocated tlabel has to be freed
 * with hpsb_free_tlabel() after the transaction is complete (unless it's
 * reused again for the same target node).
 *
 * @param packet - the packet who's tlabel/tpool we set
 * @return  Zero on success, otherwise non-zero. A non-zero return
 * generally means there are no available tlabels. 
 */
int hpsb_get_tlabel(struct hpsb_packet *packet)
{
	unsigned long flags;
	struct hpsb_tlabel_pool *tp;

	tp = &packet->host->tpool[packet->node_id & NODE_MASK];

	//~ if (irqs_disabled() || in_atomic()) {
	//~ if(in_interrupt()) {
		//~ if (down_trylock(&tp->count))
			//~ return 1;
	//~ } else {
		//~ down(&tp->count);
	//~ }
	//~ rtos_res_lock(&tp->count); //64 tasks can call here without blocking
	if(atomic_read(&tp->count)<0) {
		HPSB_ERR("run out of tlabel\n");
		return 1;
	}
	atomic_dec(&tp->count);

	rtos_spin_lock_irqsave(&tp->lock, flags);

	packet->tlabel = find_next_zero_bit(tp->pool, 64, tp->next);
	if (packet->tlabel > 63)
		packet->tlabel = find_first_zero_bit(tp->pool, 64);
	tp->next = (packet->tlabel + 1) % 64;
	/* Should _never_ happen */
	RTOS_ASSERT(!test_and_set_bit(packet->tlabel, tp->pool),;);
	tp->allocations++;
	rtos_spin_unlock_irqrestore(&tp->lock, flags);

	return 0;
}

/**
 * @ingroup trans
 * @anchor hpsb_free_tlabel
 * free an allocated transaction label
 * @param packet whos tlabel/tpool needs to be cleared
 *
 * Frees the transaction label allocated with hpsb_get_tlabel().  The
 * tlabel has to be freed after the transaction is complete (i.e. response
 * was received for a split transaction or packet was sent for a unified
 * transaction).
 *
 * A tlabel must not be freed twice.
 */
void hpsb_free_tlabel(struct hpsb_packet *packet)
{
        unsigned long flags;
	struct hpsb_tlabel_pool *tp;

	tp = &packet->host->tpool[packet->node_id & NODE_MASK];

	RTOS_ASSERT(!(packet->tlabel > 63 || packet->tlabel < 0),return;);

        rtos_spin_lock_irqsave(&tp->lock, flags);
	RTOS_ASSERT(test_and_clear_bit(packet->tlabel, tp->pool),;);
        rtos_spin_unlock_irqrestore(&tp->lock, flags);

	//~ up(&tp->count);
	atomic_inc(&tp->count);
}


/**
 * @ingroup trans
 * @anchor hpsb_packet_success
 * see if the async transaction is successful. 
 */
int hpsb_packet_success(struct hpsb_packet *packet)
{
        switch (packet->ack_code) {
        case ACK_PENDING:
                switch ((packet->header[1] >> 12) & 0xf) {
                case RCODE_COMPLETE:
                        return 0;
                case RCODE_CONFLICT_ERROR:
                        return -EAGAIN;
                case RCODE_DATA_ERROR:
                        return -EREMOTEIO;
                case RCODE_TYPE_ERROR:
                        return -EACCES;
                case RCODE_ADDRESS_ERROR:
                        return -EINVAL;
                default:
                        HPSB_ERR("received reserved rcode %d from node %d",
                                 (packet->header[1] >> 12) & 0xf,
                                 packet->node_id);
                        return -EAGAIN;
                }
                HPSB_PANIC("reached unreachable code 1 in %s", __FUNCTION__);

        case ACK_BUSY_X:
        case ACK_BUSY_A:
        case ACK_BUSY_B:
                return -EBUSY;

        case ACK_TYPE_ERROR:
                return -EACCES;

        case ACK_COMPLETE:
                if (packet->tcode == TCODE_WRITEQ
                    || packet->tcode == TCODE_WRITEB) {
                        return 0;
                } else {
                        HPSB_ERR("impossible ack_complete from node %d "
                                 "(tcode %d)", packet->node_id, packet->tcode);
                        return -EAGAIN;
                }


        case ACK_DATA_ERROR:
                if (packet->tcode == TCODE_WRITEB
                    || packet->tcode == TCODE_LOCK_REQUEST) {
                        return -EAGAIN;
                } else {
                        HPSB_ERR("impossible ack_data_error from node %d "
                                 "(tcode %d)", packet->node_id, packet->tcode);
                        return -EAGAIN;
                }

        case ACK_ADDRESS_ERROR:
                return -EINVAL;

        case ACK_TARDY:
        case ACK_CONFLICT_ERROR:
        case ACKX_NONE:
        case ACKX_SEND_ERROR:
        case ACKX_ABORTED:
        case ACKX_TIMEOUT:
                /* error while sending */
                return -EAGAIN;

        default:
                HPSB_ERR("got invalid ack %d from node %d (tcode %d)",
                         packet->ack_code, packet->node_id, packet->tcode);
                return -EAGAIN;
        }

        HPSB_PANIC("reached unreachable code 2 in %s", __FUNCTION__);
}

/**
 * @ingroup trans
 * @anchor hpsb_make_readpacket
 * to make an async read packet
 */
struct hpsb_packet *hpsb_make_readpacket(struct hpsb_host *host, nodeid_t node,
					 u64 addr, size_t length, unsigned int pri)
{
        struct hpsb_packet *packet;

	if (length == 0)
		return NULL;

	packet = hpsb_alloc_packet(length,&host->pool,pri);
	if (!packet){
		
		return NULL;
	}
	
	packet->host = host;
	packet->node_id = node;

	if (hpsb_get_tlabel(packet)) {
		
		hpsb_free_packet(packet);
		return NULL;
	}

	if (length == 4)
		fill_async_readquad(packet, addr);
	else
		fill_async_readblock(packet, addr, length);

	return packet;
}

/**
 * @ingroup trans
 * @anchor hpsb_make_writepacket
 */
struct hpsb_packet *hpsb_make_writepacket (struct hpsb_host *host, nodeid_t node,
					   u64 addr, quadlet_t *buffer, size_t length, unsigned int pri)
{
	struct hpsb_packet *packet;

	if (length == 0)
		return NULL;

	packet = hpsb_alloc_packet(length,&host->pool,pri);
	if (!packet)
		return NULL;
	
	if (length % 4) { /* zero padding bytes */
		packet->data[length >> 2] = 0;
	}
	packet->host = host;
	packet->node_id = node;

	if (hpsb_get_tlabel(packet)) {
		hpsb_free_packet(packet);
		return NULL;
	}

	if (length == 4) {
		fill_async_writequad(packet, addr, buffer ? *buffer : 0);
	} else {
		fill_async_writeblock(packet, addr, length);
		if (buffer)
			memcpy(packet->data, buffer, length);
	}

	return packet;
}

/**
 * @ingroup trans
 * @anchor hpsb_make_streampacket
 * make an stream packet
 */
struct hpsb_packet *hpsb_make_streampacket(struct hpsb_host *host, u8 *buffer, int length,
                                           int channel, int tag, int sync, unsigned int pri)
{
	struct hpsb_packet *packet;

	if (length == 0)
		return NULL;

	packet = hpsb_alloc_packet(length, &host->pool, pri);
	if (!packet)
		return NULL;

	if (length % 4) { /* zero padding bytes */
		packet->data[length >> 2] = 0;
	}
	packet->host = host;

	if (hpsb_get_tlabel(packet)) {
		hpsb_free_packet(packet);
		return NULL;
	}

	fill_async_stream_packet(packet, length, channel, tag, sync);
	if (buffer)
		memcpy(packet->data, buffer, length);

	return packet;
}

/**
 * @ingroup trans
 * @anchor hpsb_make_lockpacket
 */
struct hpsb_packet *hpsb_make_lockpacket(struct hpsb_host *host, nodeid_t node,
                                         u64 addr, int extcode, quadlet_t *data,
					 quadlet_t arg, unsigned int pri)
{
	struct hpsb_packet *packet;
	u32 length;

	packet = hpsb_alloc_packet(8, &host->pool, pri);
	if (!packet) return NULL;

	packet->host = host;
	packet->node_id = node;
	if (hpsb_get_tlabel(packet)) {
		hpsb_free_packet(packet);
		return NULL;
	}

	switch (extcode) {
	case EXTCODE_FETCH_ADD:
	case EXTCODE_LITTLE_ADD:
		length = 4;
		if (data)
			packet->data[0] = *data;
		break;
	default:
		length = 8;
		if (data) {
			packet->data[0] = arg;
			packet->data[1] = *data;
		}
		break;
	}
	fill_async_lock(packet, addr, extcode, length);

	return packet;
}

/**
 * @ingroup trans
 * @anchor hpsb_make_lock64packet
 */
struct hpsb_packet *hpsb_make_lock64packet(struct hpsb_host *host, nodeid_t node,
                                           u64 addr, int extcode, octlet_t *data,
					   octlet_t arg, unsigned int pri)
{
	struct hpsb_packet *packet;
	u32 length;

	packet = hpsb_alloc_packet(16, &host->pool, pri);
	if (!packet) return NULL;
	
	packet->host = host;
	packet->node_id = node;
	if (hpsb_get_tlabel(packet)) {
		hpsb_free_packet(packet);
		return NULL;
	}

	switch (extcode) {
	case EXTCODE_FETCH_ADD:
	case EXTCODE_LITTLE_ADD:
		length = 8;
		if (data) {
			packet->data[0] = *data >> 32;
			packet->data[1] = *data & 0xffffffff;
		}
		break;
	default:
		length = 16;
		if (data) {
			packet->data[0] = arg >> 32;
			packet->data[1] = arg & 0xffffffff;
			packet->data[2] = *data >> 32;
			packet->data[3] = *data & 0xffffffff;
		}
		break;
	}
	fill_async_lock(packet, addr, extcode, length);

	return packet;
}

/**
 * @ingroup trans
 * @anchor hpsb_make_phypacket
 */
struct hpsb_packet *hpsb_make_phypacket(struct hpsb_host *host,
                                        quadlet_t data)
{
        struct hpsb_packet *packet;

	/* we assign physical packet the highest priority */
        packet = hpsb_alloc_packet(0,&host->pool, IEEE1394_PRIORITY_HIGHEST);
        if (!packet) return NULL;

        packet->host = host;
        fill_phy_packet(packet, data);

        return packet;
}

/**
 * @ingroup trans
 * @anchor hpsb_make_isopacket
 */
struct hpsb_packet *hpsb_make_isopacket(struct hpsb_host *host,
					int length, int channel,
					int tag, int sync, unsigned int pri)
{
	struct hpsb_packet *packet;

	packet = hpsb_alloc_packet(length, &host->pool, pri);
	if (!packet) return NULL;

	packet->host = host;
	fill_iso_packet(packet, length, channel, tag, sync);

	packet->generation = get_hpsb_generation(host);

	return packet;
}

/* 
 * Define the call back function used in hpsb_read/write/lock
 * set the response packet
 */ 
static void tranaction_complete_packet (struct hpsb_packet *packet, void *data) 
{ 
        packet->processed = 1; 
        // Set the response packet 
        ((hpsb_transaction_response*) data)->pResponsePacket = packet; 
       // Free the semaphore 
        rtos_event_signal(((hpsb_transaction_response*) data)->pSem); 
}

/**
 * @ingroup trans
 * @anchor hpsb_read
 * an atomic read, i.e. blocked between req and resp.
 */
int hpsb_read(struct hpsb_host *host, nodeid_t node, unsigned int generation,
	      u64 addr, quadlet_t *buffer, size_t length, unsigned int pri)
{
        hpsb_transaction_response transaction_response; 
        struct hpsb_packet *packet;
        rtos_event_t sem;
        int retval = 0;

        if (length == 0)
                return -EINVAL;

	//~ BUG_ON(in_interrupt()); // We can't be called in an interrupt, yet

		packet = hpsb_make_readpacket(host, node, addr, length,pri);
		if (!packet) return -ENOMEM;
		packet->generation = generation;
		
		
		rtos_event_init(&sem); 
        // Set the call back data 
        transaction_response.pResponsePacket = NULL; 
        transaction_response.pSem = &sem; 
      
        // Set the callback 
        hpsb_set_packet_complete_task(packet, tranaction_complete_packet, (void *)&transaction_response); 
        retval = hpsb_send_packet(packet); 
        if (retval == 0) 
                rtos_event_wait(&sem); 
                
		if (retval < 0) goto hpsb_read_fail;
		
		packet = transaction_response.pResponsePacket; 
        retval = hpsb_packet_success(packet); 
        if (retval == 0) 
        { 
                if (length == 4) { 
                        *buffer = packet->header[3]; 
                } else { 
                        memcpy(buffer, packet->data, length); 
                } 
        } 
hpsb_read_fail: 
        hpsb_free_tlabel(packet); 
        hpsb_free_packet(packet); 
        return retval; 
}

/**
 * @ingroup trans
 * @anchor hpsb_write
 * an atomic write, i.e. blocked between req and resp
 */
int hpsb_write(struct hpsb_host *host, nodeid_t node, unsigned int generation,
	       u64 addr, quadlet_t *buffer, size_t length, unsigned int pri)
{
		hpsb_transaction_response transaction_response;
		struct hpsb_packet *packet;
		rtos_event_t sem;
		int retval;

		if (length == 0)
			return -EINVAL;

	//~ BUG_ON(in_interrupt()); // We can't be called in an interrupt, yet

		packet = hpsb_make_writepacket (host, node, addr, buffer, length, pri);
		if (!packet)
			return -ENOMEM;
		packet->generation = generation;
		
		rtos_event_init(&sem); 
        // Set the call back data 
        transaction_response.pResponsePacket = NULL; 
        transaction_response.pSem = &sem; 
        
        // Set the callback 
        hpsb_set_packet_complete_task(packet, tranaction_complete_packet, (void *)&transaction_response); 
        retval = hpsb_send_packet(packet); 
        if (retval == 0) 
                rtos_event_wait(&sem); 
                
		if (retval < 0) goto hpsb_read_fail;
		
		packet = transaction_response.pResponsePacket; 
        retval = hpsb_packet_success(packet); 
        if (retval == 0) 
        { 
                if (length == 4) { 
                        *buffer = packet->header[3]; 
                } else { 
                        memcpy(buffer, packet->data, length); 
                } 
        } 
hpsb_write_fail: 
        hpsb_free_tlabel(packet); 
        hpsb_free_packet(packet); 
        return retval; 
}

/**
 * @ingroup trans
 * @anchor hpsb_lock
 * atomic lock,i.e. blocked between req and resp. 
 */
int hpsb_lock(struct hpsb_host *host, nodeid_t node, unsigned int generation,
		u64 addr, int extcode, quadlet_t *data, quadlet_t arg, 
		unsigned int pri)
{
        hpsb_transaction_response transaction_response;
        struct hpsb_packet *packet;
        int retval = 0;

	//~ BUG_ON(in_interrupt()); // We can't be called in an interrupt, yet

		packet = hpsb_make_lockpacket(host, node, addr, extcode, data, arg, pri);
        if (!packet)
                return -ENOMEM;
       	packet->generation = generation;
       	
       	rtos_event_init(&sem); 
        // Set the call back data 
        transaction_response.pResponsePacket = NULL; 
        transaction_response.pSem = &sem; 
        
        // Set the callback 
        hpsb_set_packet_complete_task(packet, tranaction_complete_packet, (void *)&transaction_response); 
        retval = hpsb_send_packet(packet); 
        if (retval == 0) 
                rtos_event_wait(&sem); 
                
		if (retval < 0) goto hpsb_read_fail;
		
		packet = transaction_response.pResponsePacket; 
        retval = hpsb_packet_success(packet); 
        if (retval == 0) 
        { 
                if (length == 4) { 
                        *buffer = packet->header[3]; 
                } else { 
                        memcpy(buffer, packet->data, length); 
                } 
        } 
hpsb_lock_fail: 
        hpsb_free_tlabel(packet); 
        hpsb_free_packet(packet); 
        return retval; 
}

/**
 * @ingroup trans
 * @anchor hpsb_send_gasp
 * atomic gasp sending, not blocked
 */
int hpsb_send_gasp(struct hpsb_host *host, int channel, unsigned int generation,
		   quadlet_t *buffer, size_t length, u32 specifier_id,
		   unsigned int version, unsigned int pri)
{
	struct hpsb_packet *packet;
	int retval = 0;
	u16 specifier_id_hi = (specifier_id & 0x00ffff00) >> 8;
	u8 specifier_id_lo = specifier_id & 0xff;

	HPSB_VERBOSE("Send GASP: channel = %d, length = %Zd", channel, length);

	length += 8;

	packet = hpsb_make_streampacket(host, NULL, length, channel, 3, 0, pri);
	if (!packet)
		return -ENOMEM;

	packet->data[0] = cpu_to_be32((host->node_id << 16) | specifier_id_hi);
	packet->data[1] = cpu_to_be32((specifier_id_lo << 24) | (version & 0x00ffffff));

	memcpy(&(packet->data[2]), buffer, length - 8);

	packet->generation = generation;

	packet->no_waiter = 1;

	retval = hpsb_send_packet(packet);
	if (retval < 0)
		hpsb_free_packet(packet);

	return retval;
}

