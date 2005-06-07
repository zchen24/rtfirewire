/**
 * @ingroup core
 * @file 
 * 
 * Implementation of stack module
 * 
 */
 
 /**
  * @defgroup core 1394 stack core
  * 
  * Firewire stack core processing:
  * - hpsb_packet management
  * - packet handling and forwarding to highlevel or lowlevel
  * - host time out implementation
  * - bus initialization after reset
  *
  * For more details, see @ref "Overview of Real-Time Firewire Stack". 
  */
 
/**
 * IEEE 1394 for Linux
 *
 * Core support: hpsb_packet management, packet handling and forwarding to
 *               highlevel or lowlevel code
 * Adapted to RTAI by Zhang Yuchen <y.zhang-4@student.utwente.nl>
 *
 * Copyright (C) 1999, 2000 Andreas E. Bombe
 *                     2002 Manfred Weihs <weihs@ict.tuwien.ac.at>
 *
 * This code is licensed under the GPL.  See the file COPYING in the root
 * directory of the kernel sources for details.
 *
 *
 * Contributions:
 *
 * Manfred Weihs <weihs@ict.tuwien.ac.at>
 *        loopback functionality in hpsb_send_packet
 *        allow highlevel drivers to disable automatic response generation
 *              and to generate responses themselves (deferred)
 *
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/bitops.h>
#include <asm/byteorder.h>
#include <asm/semaphore.h>

#include <ieee1394_types.h>
#include <ieee1394.h>
#include <hosts.h>
#include <ieee1394_core.h>
#include <highlevel.h>
#include <ieee1394_transactions.h>
#include <csr.h>
#include <dma.h>
#include <iso.h>
#include <rtskbuff.h>

#include <rt1394_config.h>
#include <rtos_primitives.h>
#include <rt_serv.h>

/** response list for response broker */
struct rtskb_head comp_list = {
	.name = "comp",
};

/** request lists for request brokers */
struct rtskb_head bis_req_list = {
	.name = "bis",
};
struct rtskb_head rt_req_list = {
	.name = "rt",
};
struct rtskb_head nrt_req_list = {
	.name = "nrt",
};

struct rtskb_pool bis_req_pool = {
	.name = "bis",
};
struct rtskb_pool rt_req_pool = {
	.name = "rt",
};
struct rtskb_pool nrt_req_pool = {
	.name = "nrt",
};

struct rt_serv_struct *comp_server;
struct rt_serv_struct *bis_req_server;
struct rt_serv_struct *rt_req_server;
struct rt_serv_struct *nrt_req_server;

rtos_time_t	probe;

/* We are GPL, so treat us special */
MODULE_LICENSE("GPL");

/* Some globals used */
const char *hpsb_speedto_str[] = { "S100", "S200", "S400", "S800", "S1600", "S3200" };

//~ #define CONFIG_IEEE1394_VERBOSEDEBUG
//~ #ifdef CONFIG_IEEE1394_VERBOSEDEBUG
//~ static void dump_packet(const char *text, quadlet_t *data, int size)
//~ {
	//~ rtos_print("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
	//~ int i;

	//~ size /= 4;
	//~ size = (size > 4 ? 4 : size);

	//~ rtos_print(KERN_DEBUG "ieee1394: %s", text);
	//~ for (i = 0; i < size; i++)
		//~ rtos_print(" %08x", data[i]);
	//~ rtos_print("\n");
//~ }
//~ #else
#define dump_packet(x,y,z)
//~ #endif

static void abort_requests(struct hpsb_host *host);
static void queue_packet_complete(struct hpsb_packet *packet);

/**
 * @ingroup core
 * @anchor hpsb_set_packet_complete_task
 * Set the completion task for packet
 *
 * set the task that runs when a packet
 * completes. You cannot call this more than once on a single packet
 * before it is sent.
 *
 * @param packet - the packet whose completion we want the task added to
 * @param routine - function to call
 * @param data - data (if any) to pass to the above function
 */
void hpsb_set_packet_complete_task(struct hpsb_packet *packet,
				   void (*routine)(void *), void *data)
{
	BUG_ON(packet->complete_routine != NULL);
	packet->complete_routine = routine;
	packet->complete_data = data;
	return;
}

/**
 * @ingroup core
 * @anchor hpsb_alloc_packet
 * allocate new packet structure from real-time buffer pool
 *
 * This function allocates, initializes and returns a new &struct hpsb_packet.
 * It can be used in interrupt context.  A header block is always included, its
 * size is big enough to contain all possible 1394 headers.  The data block is
 * only allocated when data_size is not zero.
 *
 * For packets for which responses will be received the data_size has to be big
 * enough to contain the response's data block since no further allocation
 * occurs at response matching time.
 *
 * The packet's generation value will be set to the current generation number
 * for ease of use.  Remember to overwrite it with your own recorded generation
 * number if you can not be sure that your code will not race with a bus reset.
 *
 * @param pri is the priority of the allocated packet. (Priority is only used in asynchronous datagram transaction)
 * @return A pointer to a &struct hpsb_packet or NULL on allocation
 * failure.
 */
struct hpsb_packet *hpsb_alloc_packet(size_t data_size,struct rtskb_pool *pool)
{
        
	struct hpsb_packet *packet = NULL;
        struct rtskb *skb;

	
	data_size = ((data_size + 3) & ~3);
	
	skb = alloc_rtskb(data_size + sizeof(*packet), pool);
	if(skb == NULL)
		return NULL;
	
	memset(skb->data, 0, data_size + sizeof(*packet));
	
	packet = (struct hpsb_packet *)skb->data;
	if(!packet){
		rtos_print("%s:buffer data pointer NULL! do hack now\n", __FUNCTION__);
		rtskb_clean(skb);
		packet = (struct hpsb_packet *)skb->data;
	}
	packet->skb = skb;
	
	packet->header = packet->embedded_header;
	packet->state = hpsb_unused;
	packet->generation = -1;
	INIT_LIST_HEAD(&packet->driver_list);
	atomic_set(&packet->refcnt, 1);
	
	packet->data = (quadlet_t *)(skb->data + sizeof(*packet));//somehow, we dont want the data pointer to be NULL
	packet->data_size = data_size;
	
		
	return packet;
}


/**
 * @ingroup core
 * @anchor hpsb_free_packet
 *
 * Return the associated rtskb to its origin pool. 
 */
void hpsb_free_packet (struct hpsb_packet *packet)
{
	if(packet && atomic_dec_and_test(&packet->refcnt)) {
		//~ rtos_print("freeing packet to %s\n", packet->skb->pool->name);
		//~ RTNET_ASSERT(!list_empty(&packet->driver_list), );
		kfree_rtskb(packet->skb);
	}
}


/**
 * @ingroup core 
 * @anchor hpsb_reset_bus
 * Call the reset routine of underlying driver with a 
 * specified reset type. 
 *
 * @param host - the host to reset
 * @param type - the type of reset
 * @return 0 if bus is resetted, 1 if bus is already in reset. 
 */

int hpsb_reset_bus(struct hpsb_host *host, int type)
{
        if (!host->in_bus_reset) {
		if(host->driver->devctl)
			host->driver->devctl(host, RESET_BUS, type);
                return 0;
        } else {
		rtos_print("host %s is already in reset\n", host->name);
                return 1;
        }
}

/**
 * @ingroup core
 * @anchor hpsb_bus_reset
 * Called when a bus reset occurs in a certain host. 
 * This function reset the related host attributes. 
 * 
 * @return 0 on normal, 1 if the bus reset notice has 
 * been rasied. 
 */
int hpsb_bus_reset(struct hpsb_host *host)
{
        
	if (host->in_bus_reset) {
                HPSB_NOTICE("%s called while bus reset already in progress",
			    __FUNCTION__);
                return 1;
        }

	/* since after bus reset, the nodeid may be changed, we have to cancel all the requests */
        abort_requests(host);
        host->in_bus_reset = 1;
        host->irm_id = -1;
	host->is_irm = 0;
        host->busmgr_id = -1;
	host->is_busmgr = 0;
	host->is_cycmst = 0;
        host->node_count = 0;
        host->selfid_count = 0;

        return 0;
}


/**
 * @ingroup core
 * @anchor check_selfids
 * @internal
 * 
 * Verify num_of_selfids SelfIDs and return number of nodes.
 * 
 * @return 1 on success, zero in case verification failed.
 *
 * @note this function is called after selfid phase of bus reset has finished. 
 * The selfids are stored in bus topology map. 
 * For more info, see @ref Bus reset section of "Overview of Real-Time Firewire stack". 
 */
static int check_selfids(struct hpsb_host *host)
{
        int nodeid = -1;
        int rest_of_selfids = host->selfid_count;
        struct selfid *sid = (struct selfid *)host->topology_map;
        struct ext_selfid *esid;
        int esid_seq = 23;

	host->nodes_active = 0;

        while (rest_of_selfids--) {
                if (!sid->extended) {
                        nodeid++;
                        esid_seq = 0;
                        
                        if (sid->phy_id != nodeid) {
                                HPSB_INFO("SelfIDs failed monotony check with "
                                          "%d", sid->phy_id);
                                return 0;
                        }
                        
			if (sid->link_active) {
				host->nodes_active++;
				if (sid->contender)
					host->irm_id = LOCAL_BUS | sid->phy_id;
			}
                } else {
                        esid = (struct ext_selfid *)sid;

                        if ((esid->phy_id != nodeid) 
                            || (esid->seq_nr != esid_seq)) {
                                HPSB_INFO("SelfIDs failed monotony check with "
                                          "%d/%d", esid->phy_id, esid->seq_nr);
                                return 0;
                        }
                        esid_seq++;
                }
                sid++;
        }
        
        esid = (struct ext_selfid *)(sid - 1);
        while (esid->extended) {
                if ((esid->porta == 0x2) || (esid->portb == 0x2)
                    || (esid->portc == 0x2) || (esid->portd == 0x2)
                    || (esid->porte == 0x2) || (esid->portf == 0x2)
                    || (esid->portg == 0x2) || (esid->porth == 0x2)) {
                                HPSB_INFO("SelfIDs failed root check on "
                                          "extended SelfID");
                                return 0;
                }
                esid--;
        }

        sid = (struct selfid *)esid;
        if ((sid->port0 == 0x2) || (sid->port1 == 0x2) || (sid->port2 == 0x2)) {
                        HPSB_INFO("SelfIDs failed root check");
                        return 0;
        }

	host->node_count = nodeid + 1;
        return 1;
}

/**
 * @ingroup core
 * @anchor build_speed_map
 * To build the speed map for the whole bus
 * after bus reset. 
 *
 * @note for more info, please see @ref Bus reset section of 
 * "Overview of Real-Time Firewire stack"
 */
static void build_speed_map(struct hpsb_host *host, int nodecount)
{
	u8 speedcap[nodecount];
        u8 cldcnt[nodecount];
        u8 *map = host->speed_map;
        struct selfid *sid;
        struct ext_selfid *esid;
        int i, j, n;

        for (i = 0; i < (nodecount * 64); i += 64) {
                for (j = 0; j < nodecount; j++) {
                        map[i+j] = IEEE1394_SPEED_MAX;
                }
        }

        for (i = 0; i < nodecount; i++) {
                cldcnt[i] = 0;
        }

        /* find direct children count and speed */
        for (sid = (struct selfid *)&host->topology_map[host->selfid_count-1],
                     n = nodecount - 1;
             (void *)sid >= (void *)host->topology_map; sid--) {
                if (sid->extended) {
                        esid = (struct ext_selfid *)sid;

                        if (esid->porta == 0x3) cldcnt[n]++;
                        if (esid->portb == 0x3) cldcnt[n]++;
                        if (esid->portc == 0x3) cldcnt[n]++;
                        if (esid->portd == 0x3) cldcnt[n]++;
                        if (esid->porte == 0x3) cldcnt[n]++;
                        if (esid->portf == 0x3) cldcnt[n]++;
                        if (esid->portg == 0x3) cldcnt[n]++;
                        if (esid->porth == 0x3) cldcnt[n]++;
                } else {
                        if (sid->port0 == 0x3) cldcnt[n]++;
                        if (sid->port1 == 0x3) cldcnt[n]++;
                        if (sid->port2 == 0x3) cldcnt[n]++;

                        speedcap[n] = sid->speed;
                        n--;
                }
        }

        /* set self mapping */
        for (i = 0; i < nodecount; i++) {
                map[64*i + i] = speedcap[i];
        }

        /* fix up direct children count to total children count;
         * also fix up speedcaps for sibling and parent communication */
        for (i = 1; i < nodecount; i++) {
                for (j = cldcnt[i], n = i - 1; j > 0; j--) {
                        cldcnt[i] += cldcnt[n];
                        speedcap[n] = min(speedcap[n], speedcap[i]);
                        n -= cldcnt[n] + 1;
                }
        }

        for (n = 0; n < nodecount; n++) {
                for (i = n - cldcnt[n]; i <= n; i++) {
                        for (j = 0; j < (n - cldcnt[n]); j++) {
                                map[j*64 + i] = map[i*64 + j] =
                                        min(map[i*64 + j], speedcap[n]);
                        }
                        for (j = n + 1; j < nodecount; j++) {
                                map[j*64 + i] = map[i*64 + j] =
                                        min(map[i*64 + j], speedcap[n]);
                        }
                }
        }
}

/**
 * @ingroup core
 * @anchor hpsb_selfid_received
 *
 * @param sid -  the received selfid pakcet
 *
 * @note this function is called in ISR for 
 * receiving selfid in hardware. 
 */
void hpsb_selfid_received(struct hpsb_host *host, quadlet_t sid)
{
        if (host->in_bus_reset) {
                HPSB_VERBOSE("Including SelfID 0x%x", sid);
                host->topology_map[host->selfid_count++] = sid;
        } else {
                HPSB_NOTICE("Spurious SelfID packet (0x%08x) received from bus %d",
			    sid, NODEID_TO_BUS(host->node_id));
        }
}

/**
 * @ingroup core
 * @anchor hpsb_selfid_complete
 * 
 * This function is called when selfid phase is finished. 
 * 
 * @note see more info in @ref bus reset section of 
 * "Overview of Real-Time Firewire Stack"
 * @todo the highlevel reset routines can stay in either rtai domain
 * or linux. 
 */
void hpsb_selfid_complete(struct hpsb_host *host, int phyid, int isroot)
{
	if (!host->in_bus_reset)
		HPSB_NOTICE("SelfID completion called outside of bus reset!");

        host->node_id = LOCAL_BUS | phyid;
        host->is_root = isroot;

        if (!check_selfids(host)) {
                if (host->reset_retries++ < 20) {
                        /* selfid stage did not complete without error */
                        HPSB_NOTICE("Error in SelfID stage, resetting");
			host->in_bus_reset = 0;
			/* this should work from ohci1394 now... */
                        hpsb_reset_bus(host, LONG_RESET);
                        return;
                } else {
                        HPSB_NOTICE("Stopping out-of-control reset loop");
                        HPSB_NOTICE("Warning - topology map and speed map will not be valid");
			host->reset_retries = 0;
                }
        } else {
		host->reset_retries = 0;
                build_speed_map(host, host->node_count);
        }

	HPSB_VERBOSE("selfid_complete called with successful SelfID stage "
		     "... irm_id: 0x%X node_id: 0x%X",host->irm_id,host->node_id);

        /* irm_id is kept up to date by check_selfids() */
        if (host->irm_id == host->node_id) {
                host->is_irm = 1;
        } else {
                host->is_busmgr = 0;
                host->is_irm = 0;
        }

        if (isroot) {
		host->driver->devctl(host, ACT_CYCLE_MASTER, 1);
		host->is_cycmst = 1;
	}
	atomic_inc(&host->generation);
	host->in_bus_reset = 0;
        highlevel_host_reset(host);
}

/**
 * @ingroup core
 * @anchor hpsb_packet_sent
 * Function called when the ack of a certain request packet has been reecived. 
 *
 * @note see @ref Asynchronous Transaction setion of "Overview of Real-Time Firewire stack".
 */
void hpsb_packet_sent(struct hpsb_host *host, struct hpsb_packet *packet, 
                      int ackcode)
{
        unsigned long flags;

	rtos_spin_lock_irqsave(&host->pending_packet_queue.lock, flags);
	
        packet->ack_code = ackcode;

        if (packet->no_waiter || packet->state == hpsb_complete) {
                /* if packet->no_waiter, must not have a tlabel allocated */
		rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
                hpsb_free_packet(packet);
                return;
        }
	
	atomic_dec(&packet->refcnt); /* drop HC's reference */
	/* here the packet must be on the host->pending_packet_queue */

        if (ackcode != ACK_PENDING || !packet->expect_response) {
                packet->state = hpsb_complete;
		__rtskb_unlink(packet->skb, &host->pending_packet_queue);
		rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
		queue_packet_complete(packet);
                return;
        }

        packet->state = hpsb_pending;
        packet->sendtime = jiffies;

        rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
	
	mod_timer(&host->timeout, jiffies + host->timeout_interval);
}


/**
 * @ingroup core
 * @anchor hpsb_send_phy_config
 * transmit a PHY configuration packet on the bus
 *
 * This function sends a PHY config packet on the bus through the specified host.
 *
 * @param host - host that PHY config packet gets sent through
 * @param rootid - root whose force_root bit should get set (-1 = don't set force_root)
 * @param gapcnt - gap count value to set (-1 = don't set gap count)
 *
 * @return 0 for success or error number otherwise.
 */
int hpsb_send_phy_config(struct hpsb_host *host, int rootid, int gapcnt)
{
	struct hpsb_packet *packet;
	int retval = 0;

	if (rootid >= ALL_NODES || rootid < -1 || gapcnt > 0x3f || gapcnt < -1 ||
	   (rootid == -1 && gapcnt == -1)) {
		HPSB_DEBUG("Invalid Parameter: rootid = %d   gapcnt = %d",
			   rootid, gapcnt);
		return -EINVAL;
	}

	packet = hpsb_alloc_packet(0,&host->pool);
	if (!packet)
		return -ENOMEM;

	packet->host = host;
	packet->header_size = 8;
	packet->data_size = 0;
	packet->expect_response = 0;
	packet->no_waiter = 0;
	packet->type = hpsb_raw;
	packet->header[0] = 0;
	
	
	if (rootid != -1)
		packet->header[0] |= rootid << 24 | 1 << 23;
	if (gapcnt != -1)
		packet->header[0] |= gapcnt << 16 | 1 << 22;

	packet->header[1] = ~packet->header[0];

	packet->generation = get_hpsb_generation(host);
	
	retval = hpsb_send_packet_and_wait(packet);
	hpsb_free_packet(packet);
	
	return retval;
}

/**
 * @ingroup core
 * @anchor hpsb_send_packet
 * transmit a packet on the bus
 *
 * The packet is sent through the host specified in the packet->host field.
 * Before sending, the packet's transmit speed is automatically determined using
 * the local speed map when it is an async, non-broadcast packet.
 *
 * Possibilities for failure are that host is either not initialized, in bus
 * reset, the packet's generation number doesn't match the current generation
 * number or the host reports a transmit error.
 *
 * @return False (0) on failure, true (1) otherwise.
 * @todo static memory allocation in loopback
 */
int hpsb_send_packet(struct hpsb_packet *packet)
{	
	struct hpsb_host *host = packet->host;
		
	if(host->is_shutdown)
		return -EINVAL;
	if(host->in_bus_reset ||
		(packet->generation != get_hpsb_generation(host)))
		return -EAGAIN;
	
	packet->state = hpsb_queued;
	
	/*silly?*/
	//~ WARN_ON(packet->no_waiter && packet->expect_response);
	
	if(!packet->no_waiter || packet->expect_response) {
		atomic_inc(&packet->refcnt);
		packet->sendtime = jiffies;
		rtskb_queue_tail(&host->pending_packet_queue, packet->skb);
	}
	
	if (packet->node_id == host->node_id) {
		rtos_print("sending to local....\n");
		
		rtos_get_time(&probe);
		packet->xmit_time = rtos_time_to_nanosecs(&probe);
		
		struct hpsb_packet *pkt;
		size_t size;
		
		pkt = hpsb_alloc_packet(0, &host->pool);
		if(!pkt)
			return -ENOMEM;
		
		size = packet->data_size + packet->header_size;
		pkt->data_size = size;

                memcpy(pkt->data, packet->header, packet->header_size);

		if(packet->data_size)
			memcpy(((u8*)pkt->data)+packet->header_size, packet->data, packet->data_size);
		
		//~ host->pkt->ack = ((data[size/4-1]>>16)&0x1f
				//~ == 0x11) ? 1 : 0;
		pkt->ack = 0;
		pkt->pri = packet->pri;
		pkt->host = host;
		
		dump_packet("send packet local:", packet->header, 
				packet->header_size);
		
		hpsb_packet_sent(host, packet, packet->expect_response ? ACK_PENDING : ACK_COMPLETE);
		hpsb_packet_received(pkt);
		
		return 0;
	}
	
	if(packet->type == hpsb_async && packet->node_id != ALL_NODES) {
		packet->speed_code =
			host->speed_map[NODEID_TO_NODE(host->node_id) * 64
					+ NODEID_TO_NODE(packet->node_id)];
	}
	
        switch (packet->speed_code) {
        case 2:
                dump_packet("send packet 400:", packet->header,
                            packet->header_size);
                break;
        case 1:
                dump_packet("send packet 200:", packet->header,
                            packet->header_size);
                break;
        default:
                dump_packet("send packet 100:", packet->header,
                            packet->header_size);
        }

        return host->driver->transmit_packet(host, packet);
}

/**
 * @ingroup core
 * @anchor complete_packet
 * To notify the complete of packet transaction, set as a callback. 
 *
 * We could just use complete() directly as the packet complete
 * callback, but this is more typesafe, in the sense that we get a 
 * compiler error if the prototype for the complete() changes. 
 */
static void complete_packet (void *data)
{
	rtos_event_signal((rtos_event_t *) data);
}
	
/**
 * @ingroup core
 * @anchor hpsb_send_packet_and_wait
 * Wait until packet transaction is done. 
 */
int hpsb_send_packet_and_wait(struct hpsb_packet *packet)
{
	rtos_event_t done;
	int retval;
	
	rtos_event_init(&done);
	hpsb_set_packet_complete_task(packet, complete_packet, &done);
	retval = hpsb_send_packet(packet);
	if (retval == 0)
		rtos_event_wait(&done);
	
	return retval;
}


/**
 * @ingroup core
 * @anchor send_packet_nocare
 */
static void send_packet_nocare(struct hpsb_packet *packet)
{
        if (!hpsb_send_packet(packet)) {
                hpsb_free_packet(packet);
        }
}

/**
 * @ingroup core
 * @anchor handle_packet_respnse
 * handle the response packet.
 *
 * Return is void, but error can happen when the tlabel does not match. 
 * Or tcode does not match. 
 *
 * @note see more info in @ref Asynchronous Transaction section of 
 * "Overview of Real-Time Firewire Stack". 
 *
 * @todo this routine will be moved to rtai domain. 
 */
void handle_packet_response(struct hpsb_packet *pkt)
{
	struct hpsb_packet *packet;
	struct hpsb_host  *host = pkt->host;
	quadlet_t *data = pkt->data;
	size_t size = pkt->data_size;
        struct rtskb *skb;
	int tcode = pkt->tcode;
        int tcode_match = 0;
        int tlabel;
        unsigned long flags;

	tlabel = (data[0] >> 10) & 0x3f;

        rtos_spin_lock_irqsave(&host->pending_packet_queue.lock, flags);
	
	rtskb_queue_walk(&host->pending_packet_queue, skb) {
		packet = (struct hpsb_packet *)skb->data;
		if ((packet->tlabel == tlabel)
			&& (packet->node_id == (data[1] >> 16))){
				break;
		}
		
		packet == NULL;
	}
	
	if (packet == NULL) {
		HPSB_DEBUG("unsolicited response packet received - no tlabel match");
		dump_packet("contents:", data, 16);
		rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
		return;
	}

	//~ rtos_print("request tcode: %d\n", packet->tcode);
        switch (packet->tcode) {
        case TCODE_WRITEQ:
        case TCODE_WRITEB:
                if (tcode != TCODE_WRITE_RESPONSE)
			break;
		tcode_match = 1;
		memcpy(packet->header, data, 12);
		break;
        case TCODE_READQ:
                if (tcode != TCODE_READQ_RESPONSE)
			break;
		tcode_match = 1;
		memcpy(packet->header, data, 16);
                break;
        case TCODE_READB:
                if (tcode != TCODE_READB_RESPONSE)
			break;
		tcode_match = 1;
		BUG_ON(packet->skb->len - sizeof(*packet) < size -16);
		memcpy(packet->header, data, 16);
		memcpy(packet->data, data+4, size-16);
		break;
        case TCODE_LOCK_REQUEST:
                if (tcode != TCODE_LOCK_RESPONSE)
			break;
		tcode_match = 1;
		size = min((size - 16), (size_t)8);
		BUG_ON(packet->skb->len - sizeof(*packet) < size);
		memcpy(packet->header, data, 16);
		memcpy(packet->data, data+4, size);
		break;
        }
	
	if(!tcode_match) {
		rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
		HPSB_INFO("unsolicited response packet received - tcode mismatch");
                dump_packet("contents:", data, 16);
		return;
	}
	
	__rtskb_unlink(skb, skb->list);
	
	if (packet->state == hpsb_queued) {
		packet->sendtime =  jiffies;
		packet->ack_code = ACK_PENDING;
	}
	
	packet->state = hpsb_complete;
	rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
	
	queue_packet_complete(packet);
	
	hpsb_free_packet(pkt);
}

/**
 * @ingroup core
 * @anchor create_reply_packet
 * Create the general reply packet for asynchronous transactions
 * 
 * The fill_xxx routines are called after this function to fill in the 
 * specific stuff. 
 * @param data - the received request packet, from which the created reply 
 * packet draw the header info from: like node_id, tlabel. 
 * @note this routine can be called both in rtai and linux domain. 
 * @todo to distiguish if current process context if real-time or not.
 * and do sub-routines accordingly. 
 */
static struct hpsb_packet *create_reply_packet(struct hpsb_host *host,
					       quadlet_t *data, size_t dsize, int pri)
{
	struct hpsb_packet *p;
	
	
	p = hpsb_alloc_packet(dsize, &host->pool);
	if (unlikely (p == NULL)) {
		/* FIXME - send data_error response */
			return NULL;
	}
	
	p->pri = pri;
	p->type = hpsb_async;
	p->state = hpsb_unused;
	p->host = host;
	p->node_id = data[1] >> 16;
	p->tlabel = (data[0] >> 10)& 0x3f;
	p->no_waiter = 1;
	
	p->generation = get_hpsb_generation(host);
	
	if(dsize % 4)
		p->data[dsize / 4] = 0;
	
	return p;
}

#define PREP_ASYNC_HEAD_RCODE(tc) \
	packet->tcode = tc; \
	packet->header[0] = (packet->node_id << 16) | (packet->tlabel << 10) \
		| (1 << 8) | (tc << 4); \
	packet->header[1] = (packet->host->node_id << 16) | (rcode << 12); \
	packet->header[2] = 0
/**
 * @ingroup packet
 * @anchor fill_async_readquad_resp
 * fill in an quadlet read response
 */
static void fill_async_readquad_resp(struct hpsb_packet *packet, int rcode,
                              quadlet_t data)
{
	PREP_ASYNC_HEAD_RCODE(TCODE_READQ_RESPONSE);
	packet->header[3] = data;
	packet->header_size = 16;
	packet->data_size = 0;
}
/**
 * @ingroup packet
 * @anchor fill_async_readblock_resp
 * fill in an block read response
 */
static void fill_async_readblock_resp(struct hpsb_packet *packet, int rcode,
                               int length)
{
	if (rcode != RCODE_COMPLETE)
		length = 0;

	PREP_ASYNC_HEAD_RCODE(TCODE_READB_RESPONSE);
	packet->header[3] = length << 16;
	packet->header_size = 16;
	packet->data_size = length + (length % 4 ? 4 - (length % 4) : 0);
}

/**
 * @ingroup packet
 * @anchor fill_async_write_resp
 * fill in write response
 */
static void fill_async_write_resp(struct hpsb_packet *packet, int rcode)
{
	PREP_ASYNC_HEAD_RCODE(TCODE_WRITE_RESPONSE);
	packet->header[2] = 0;
	packet->header_size = 12;
	packet->data_size = 0;
}

/**
 * @ingroup packet
 * @anchor fill_async_lock_resp
 * fill in lock response
 */
static void fill_async_lock_resp(struct hpsb_packet *packet, int rcode, int extcode,
                          int length)
{
	if (rcode != RCODE_COMPLETE)
		length = 0;

	PREP_ASYNC_HEAD_RCODE(TCODE_LOCK_RESPONSE);
	packet->header[3] = (length << 16) | extcode;
	packet->header_size = 16;
	packet->data_size = length;
}

#define PREP_REPLY_PACKET(length, pri) \
                packet = create_reply_packet(host, data, length, pri); \
                if (packet == NULL) break

/**
 * @ingroup core
 * @anchor handle_incoming_packet
 * Routine for processing request packets.
 *
 * This routine also create the response packet (if needed) and send it.
 *
 * @note the routines entered by highlevel_x should be done
 * in either Linux or rtai domain. That means there should be 
 * a task handover between this routine and next. 
 * @todo add task handover to Linux/rtai here.
 */
void req_worker(unsigned long arg)
{
	
	struct rtskb_head *list = (struct rtskb_head *)arg;
	struct rtskb *skb;
	struct hpsb_packet *pkt;
	struct hpsb_host *host;
	quadlet_t *data;
	char tcode;
	int write_acked, pri;
	
	struct hpsb_packet *packet;
        int length, rcode, extcode;
        quadlet_t buffer;
        nodeid_t source;
        nodeid_t dest;
        u16 flags;
        u64 addr;

	while ((skb = rtskb_dequeue(list)) != NULL) {
			
			pkt = (struct hpsb_packet *)skb->data;
			tcode = pkt->tcode;
			data = pkt->data;
			write_acked = pkt->ack;
			pri = pkt->pri;
			host = pkt->host;
			source = data[1] >> 16;
			dest = data[0] >> 16;
			flags = (u16) data[0];
			
			//~ rtos_print("tcode: %d\n", tcode);	
			switch (tcode) {
				case TCODE_WRITEQ:
					addr = (((u64)(data[1] & 0xffff)) << 32) | data[2];
					rcode = highlevel_write(host, source, dest, data+3,
									addr, 4, flags);

					if (!write_acked
						&& (NODEID_TO_NODE(data[0] >> 16) != NODE_MASK)
						&& (rcode >= 0)) {
						/* not a broadcast write, reply */
						PREP_REPLY_PACKET(0,pri);
						fill_async_write_resp(packet, rcode);
						send_packet_nocare(packet);
					}
					break;

				case TCODE_WRITEB:
					addr = (((u64)(data[1] & 0xffff)) << 32) | data[2];
					rcode = highlevel_write(host, source, dest, data+4,
									addr, data[3]>>16, flags);

					if (!write_acked
						&& (NODEID_TO_NODE(data[0] >> 16) != NODE_MASK)
						&& (rcode >= 0)) {
						/* not a broadcast write, reply */
						PREP_REPLY_PACKET(0, pri);
						fill_async_write_resp(packet, rcode);
						send_packet_nocare(packet);
					}
					break;

				case TCODE_READQ:
					addr = (((u64)(data[1] & 0xffff)) << 32) | data[2];
					rcode = highlevel_read(host, source, &buffer, addr, 4, flags);

					if (rcode >= 0) {
						PREP_REPLY_PACKET(0, pri);
						fill_async_readquad_resp(packet, rcode, buffer);
						send_packet_nocare(packet);
					}
					break;

				case TCODE_READB:
				
					length = data[3] >> 16;
					PREP_REPLY_PACKET(length, pri);
					addr = (((u64)(data[1] & 0xffff)) << 32) | data[2];
					rcode = highlevel_read(host, source, packet->data, addr,
								length, flags);
					

					if (rcode >= 0) {
						fill_async_readblock_resp(packet, rcode, length);
						send_packet_nocare(packet);
					} else {
						hpsb_free_packet(packet);
					}

					break;

				case TCODE_LOCK_REQUEST:
					length = data[3] >> 16;
					extcode = data[3] & 0xffff;
					addr = (((u64)(data[1] & 0xffff)) << 32) | data[2];

					PREP_REPLY_PACKET(8, pri);

					if ((extcode == 0) || (extcode >= 7)) {
						/* let switch default handle error */
						length = 0;
					}

				switch (length) {
				case 4:
					rcode = highlevel_lock(host, source, (quadlet_t *)packet->data, addr,
							       data[4], 0, extcode,flags);
					fill_async_lock_resp(packet, rcode, extcode, 4);
					break;
				case 8:
					if ((extcode != EXTCODE_FETCH_ADD) 
					    && (extcode != EXTCODE_LITTLE_ADD)) {
						rcode = highlevel_lock(host, source,
								       (quadlet_t *)packet->data, addr,
								       data[5], data[4], 
								       extcode, flags);
						fill_async_lock_resp(packet, rcode, extcode, 4);
					} else {
						rcode = highlevel_lock64(host, source,
							     (octlet_t *)packet->data, addr,
							     *(octlet_t *)(data + 4), 0ULL,
							     extcode, flags);
						fill_async_lock_resp(packet, rcode, extcode, 8);
					}
					break;
				case 16:
					rcode = highlevel_lock64(host, source,
								 (octlet_t *)packet->data, addr,
								 *(octlet_t *)(data + 6),
								 *(octlet_t *)(data + 4), 
								 extcode, flags);
					fill_async_lock_resp(packet, rcode, extcode, 8);
					break;
				default:
					rcode = RCODE_TYPE_ERROR;
					fill_async_lock_resp(packet, rcode,
							     extcode, 0);
				}
				if (rcode >= 0) {
					send_packet_nocare(packet);
				} else {
					hpsb_free_packet(packet);
				}
				break;
			}
			
		kfree_rtskb(skb);
	}
}

#undef PREP_REPLY_PACKET

#define cond_le32_to_cpu(data, noswap) \
	(noswap ? data : le32_to_cpu(data))

/**
 * @ingroup core
 * @anchor hpsb_packet_received
 * Routine for received packet.
 * 
 * @param write_acked - 
 */
void hpsb_packet_received(struct hpsb_packet *pkt)
{
        char tcode;
	struct hpsb_packet *nwpkt;
	struct rtskb_head *req_list;
	struct hpsb_host *host;
	
	host = pkt->host;

        if (host->in_bus_reset) {
                HPSB_INFO("received packet during reset; ignoring");
                return;
        }

	dump_packet("received packet:", pkt->data, pkt->data_size);

        tcode = ((pkt->data)[0] >> 4) & 0xf; 
	pkt->tcode = tcode;

        switch (tcode) {
        case TCODE_WRITE_RESPONSE:
        case TCODE_READQ_RESPONSE:
        case TCODE_READB_RESPONSE:
        case TCODE_LOCK_RESPONSE:
                handle_packet_response(pkt);
                break;

        case TCODE_WRITEQ:
        case TCODE_WRITEB:
        case TCODE_READQ:
        case TCODE_READB:
        case TCODE_LOCK_REQUEST:
		
		//~ rtos_print("request received with pri:%d\n",pkt->pri);
	
		//~ rtos_time_t pa, pb;
		//~ rtos_get_time(&pa);
		/**
		* it's a request, so we need to deliver it to one of the brokers*/
		if(pkt->pri == 0)
			req_list = &bis_req_list;
		else if(pkt->pri>0||pkt->pri<15)
			req_list = &rt_req_list;
			else if(pkt->pri==15)
			req_list = &nrt_req_list;
				else
				rtos_print("request with outrange priority received!!!\n");
				
		if(rtskb_acquire(pkt->skb, req_list->pool)) {
			rtos_print("req list %s run out of memory\n", req_list->name);
			break;
		}
		//~ rtos_get_time(&pb);
		//~ rtos_time_diff(&pb, &pb, &pa);
		//~ rtos_print("%s:time diff is %d ns\n", __FUNCTION__, rtos_time_to_nanosecs(&pb));
		
		if(pkt->pri>0 || pkt->pri<15)
			rtskb_queue_pri(req_list, pkt->skb); //we do queue-reordering based on priority for realtime data request.
		else
			rtskb_queue_tail(req_list, pkt->skb);
		//~ rtos_get_time(&pb);
		//~ rtos_time_diff(&pb, &pb, &pa);
		//~ rtos_print("%s:time diff is %d ns\n", __FUNCTION__, rtos_time_to_nanosecs(&pb));
		
		break;

        case TCODE_ISO_DATA:
                //~ highlevel_iso_receive(host, data, size);
                break;

        case TCODE_CYCLE_START:
		rtos_print("cycle start!\n");
                /* simply ignore this packet if it is passed on */
                break;

        default:
                HPSB_NOTICE("received packet with bogus transaction code %d", 
                            tcode);
                break;
        }
}

/**
 * @ingroup core
 * @anchor abort_requests
 * Cancel requests
 *
 * All pending requests are cancelled, 
 * and they are queued to completion queue
 * with ack_code = ACKX_ABORTED.
 */
void abort_requests(struct hpsb_host *host)
{
        struct hpsb_packet *packet;
	struct rtskb *skb;
		
	
	host->driver->devctl(host, CANCEL_REQUESTS, 0);
	
	while ((skb = rtskb_dequeue(&host->pending_packet_queue)) != NULL) {
		packet = (struct hpsb_packet *)skb->data;
		
		packet->state = hpsb_complete;
		packet->ack_code = ACKX_ABORTED;
		queue_packet_complete(packet);
	}
}
	
/**
 * @ingroup core
 * @anchor abort_timedouts
 * Routine for implementing bus timeout.
 * 
 * The host timer gives an alarm, afterwhich, 
 * the expired request packets will be dequeued from pending
 * queue and queued in completion queue, with 
 * ack_code = ACKX_TIMEOUT.
 * 
 * @note the host timer is based on Linux jiffies.
 * @param __opaque - pointer to host. 	
 */
void abort_timedouts(unsigned long __opaque)
{
	struct hpsb_host *host = (struct hpsb_host *)__opaque;
        unsigned long flags;
        struct hpsb_packet *packet;
	struct rtskb *skb;
        unsigned long expire;

        rtos_spin_lock_irqsave(&host->csr.lock, flags);
	expire = host->csr.expire;
        rtos_spin_unlock_irqrestore(&host->csr.lock, flags);
	
	/* Hold the lock around this, since we aren't dequeuing all 
	 * packets, just ones we need. */
        rtos_spin_lock_irqsave(&host->pending_packet_queue.lock, flags);
	
	while (!rtskb_queue_empty (&host->pending_packet_queue)) {
		skb = rtskb_peek(&host->pending_packet_queue);
		
		packet = (struct hpsb_packet *)skb->data;
			
		if  (time_before(packet->sendtime + expire, jiffies)) {
			__rtskb_unlink(skb, skb->list);
			packet->state = hpsb_complete;
			packet->ack_code = ACKX_TIMEOUT;
			queue_packet_complete(packet);
		}else {
			/* Since packets are added to the tail, the oldest
			 * ones are first, always. When we get to one that 
			 * isn't timed out, the rest aren't either. */
			break;
		}
	}
	
	if(!rtskb_queue_empty(&host->pending_packet_queue))
		mod_timer(&host->timeout, jiffies + host->timeout_interval);
	
	rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
}

/**
 * @ingroup core
 * @anchor queue_packet_complete
 * This function queues the packet that is completed to the queue of
 * kernel thread @khpsbpkt, which serves the various completion routines 
 * of packets
 * 
 * @note only asynchronous packet goes in this routine. 
 * @todo this routine stays in the task handover between pending packets and 
 * completing packets, therefore the classical real-time/non-real-time switching 
 * problem exists here. How to ditiguish process context and choose afterward routines 
 * should be sloved in todo. 
 */
static void queue_packet_complete(struct hpsb_packet *packet)
{
	if (packet->no_waiter) {
		hpsb_free_packet(packet);
		return;
	}
	if (packet->complete_routine != NULL) {
		rtskb_queue_pri(&comp_list, packet->skb);
	}
	return;
}



/**
 * @ingroup core
 * @anchor hpsbpkt_thread
 * The routine for kernel thread for postprocessing
 * of finished packet
 * 
 * @param __hi - unused 
 * @note the synchronization between this kernel thread and 
 * stack is done via semaphore; @khpsbpkt_sig. 
 */
void comp_worker(unsigned long data)
{
	
	struct rtskb_head *list = (struct rtskb_head *)data;
	struct rtskb *skb;
	struct hpsb_packet *packet;
	void (*complete_routine)(void*);
	void *complete_data;
	rtos_time_t		time;
	
	while ((skb = rtskb_dequeue(list)) != NULL) {
			packet = (struct hpsb_packet *)skb->data;
				
			//get the time of receiving response
			rtos_get_time(&time);
			//calculate and log the time elapsecd between request and response
			packet->xmit_time = rtos_time_to_nanosecs(&time) - packet->xmit_time;
			rtos_print("%s:req2resp latency is %d ns\n", __FUNCTION__, packet->xmit_time);
				
			complete_routine = packet->complete_routine;
			complete_data = packet->complete_data;
			
			packet->complete_routine = packet->complete_data = NULL;
			
			if(!complete_routine)
				rtos_print("%s: complete routine NULL\n", __FUNCTION__);
			else
				complete_routine(complete_data);
	}
}
		
	



struct proc_dir_entry *rtfw_procfs_entry;
	
/**
 * @ingroup core
 * @anchor ieee1394_core_init
 */
int ieee1394_core_init(void)
{
	int i, ret=0;
	unsigned char *name;
	
	/**
	 * Must be done before we start anything else, since it may be used
	*/
	rtfw_procfs_entry = proc_mkdir("rt-firewire",0);
	if(rtfw_procfs_entry==NULL) {
		HPSB_ERR("unalbe to create /proc/rt-firewire\n");
		return -ENOMEM;
	}
	
	/* non-fatal error */
	if (hpsb_init_config_roms()) {
		HPSB_ERR("Failed to initialize some config rom entries.\n");
		HPSB_ERR("Some features may not be available\n");
	}
	
	
	
	rtskb_queue_head_init(&comp_list);
	name = "comp";
	comp_server = rt_serv_init(name, comp_worker, (unsigned long)&comp_list, 10);
	if(!comp_server){
		rtos_print("RT-FireWire:response server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_comp_server;
	}
	
	comp_list.event = &comp_server->event;
	
	
	rtskb_queue_head_init(&bis_req_list);
	rtskb_pool_init(&bis_req_pool, 16);
	bis_req_list.pool = &bis_req_pool;
	name = "bis";
	bis_req_server = rt_serv_init(name, req_worker, (unsigned long)&bis_req_list, 20);
	if(!bis_req_server){
		rtos_print("RT-FireWire:Bus internal request server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_bis_req_server;
	}
	bis_req_list.event = &bis_req_server->event;

	rtskb_queue_head_init(&rt_req_list);
	rtskb_pool_init(&rt_req_pool, 16);
	rt_req_list.pool = &rt_req_pool;
	name = "rt";
	rt_req_server = rt_serv_init(name, req_worker, (unsigned long)&rt_req_list, 30);
	if(!rt_req_server){
		rtos_print("RT-FireWire:Real-Time request server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_rt_req_server;
	}
	rt_req_list.event = &rt_req_server->event;

	rtskb_queue_head_init(&nrt_req_list);
	rtskb_pool_init(&nrt_req_pool, 16);
	nrt_req_list.pool = &nrt_req_pool;
	name = "nrt";
	nrt_req_server = rt_serv_init(name, req_worker, (unsigned long)&nrt_req_list, 40);
	if(!nrt_req_server){
		rtos_print("RT-FireWire:Non Real-Time request server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_nrt_req_server;
	}
	nrt_req_list.event = &nrt_req_server->event;
	
	
	ret = init_csr();
	if(ret) {
		HPSB_INFO("init csr failed");
		ret = -ENOMEM;
		goto error_exit_init_csr;
	}
	
	return ret;

error_exit_init_csr:
	rt_serv_delete(nrt_req_server);
error_exit_nrt_req_server:
	rtskb_pool_release(&nrt_req_pool);
	rt_serv_delete(rt_req_server);
error_exit_rt_req_server:
	rtskb_pool_release(&rt_req_pool);
	rt_serv_delete(bis_req_server);
error_exit_bis_req_server:
	rtskb_pool_release(&bis_req_pool);
	rt_serv_delete(comp_server);
error_exit_comp_server:
exit_cleanup_config_roms:
	hpsb_cleanup_config_roms();
	remove_proc_entry("rt-firewire",0);
	return ret;
}

/**
 * @ingroup core
 * @anchor ieee1394_core_cleanup
 */
void ieee1394_core_cleanup(void)
{
	cleanup_csr();
	
	rt_serv_delete(nrt_req_server);
	rt_serv_delete(rt_req_server);
	rt_serv_delete(bis_req_server);
	rt_serv_delete(comp_server);
	rtskb_pool_release(&bis_req_pool);
	rtskb_pool_release(&nrt_req_pool);
	rtskb_pool_release(&rt_req_pool);
	
	hpsb_cleanup_config_roms();
	remove_proc_entry("rt-firewire",0);
}

