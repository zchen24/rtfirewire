/**
 * @file 
 * Implementation of RT-FireWire kernel
 * adapted from Linux FireWire stack.
 * 
 * @note Copyright 2005 Zhang Yuchen <yuchen623@gmail.com>
 */
 
/**
 * @ingroup kernel
 * @file 
 */
 
 /**
  * @defgroup kernel
  * 
  * RT-FireWire kernel processing:
  * - hpsb_packet allocation and management
  * - asynchronous transaction layer implementation
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
#include <config_roms.h>
#include <dma.h>
#include <iso.h>

#include <rtpkbuff.h>
#include <rt_serv.h>

#define MICRO_SEC	1000 //in ns

/*Internal priorities of each transaction server, 
relative to the base priority of server module*/
#define RESP_SERVER_PRI	90
#define BIS_SERVER_PRI		85
#define RT1394_SERVER_PRI	80
#define TIMEOUT_SERVER_PRI	95

#ifdef CONFIG_IEEE1394_DEBUG
static void dump_packet(const char *text, quadlet_t *data, int size)
{
	int i;

	size /= 4;
	size = (size > 4 ? 4 : size);

	rtos_print("RT-FireWire: %s", text);
	for (i = 0; i < size; i++)
		rtos_print(" %08x", data[i]);
	rtos_print("\n");
}
#else
#define dump_packet(x,y,z)
#endif /*! CONFIG_IEEE1394_DEBUG */

/** packet queue for our response server **/
struct rtpkb_prio_queue resp_list = {
	.name = "resp1394",
};

/** packet queue for our bus internal service request server **/
struct rtpkb_queue bis_req_list = {
	.name = "bis1394",
};

/** packet queue for our real-time request server **/
struct rtpkb_prio_queue rt_req_list = {
	.name = "rt1394",
};

/** packet queue for our non real-time request server **/
struct rtpkb_queue nrt_req_list = {
	.name = "nrt1394",
};

/** memory pool for each server **/
struct rtpkb_pool bis_req_pool = {
	.name = "bis1394",
};
struct rtpkb_pool rt_req_pool = {
	.name = "rt1394",
};
struct rtpkb_pool nrt_req_pool = {
	.name = "nrt1394",
};

/** servers **/
struct rt_serv_struct *resp_server;
struct rt_serv_struct *bis_req_server;
struct rt_serv_struct *rt_req_server;
struct rt_serv_struct *nrt_req_server;
struct rt_serv_struct *timeout_server;


/* Some globals used */
const char *hpsb_speedto_str[] = { "S100", "S200", "S400", "S800", "S1600", "S3200" };
const int hpsb_speedto_val[] = { 100, 200, 400, 800, 1600, 3200};


static void abort_requests(struct hpsb_host *host);
static void queue_packet_complete(struct hpsb_packet *packet);

/**
 * @ingroup kernel
 * @anchor hpsb_set_packet_complete_task
 * Set the callback function of the  request packet.
 *
 *
 * @param[in] packet - the packet in concern
 * @param[in] routine - callback function
 * @param[in] data - data (if any) to pass to the callback function
 */
void hpsb_set_packet_complete_task(struct hpsb_packet *packet,
				   void (*routine)(struct hpsb_packet *, void *), void *data)
{
	packet->complete_routine = routine;
	packet->complete_data = data;
	return;
}

/**
 * @ingroup kernel
 * @anchor hpsb_alloc_packet
 * allocate new packet structure from real-time packet buffer pool
 *
 * This function allocates, initializes and returns a new @struct hpsb_packet.
 * It can be used in interrupt context. 
 *
 *
 * The packet's generation value will be set to -1 as beginning,
 * Remember to overwrite it with your own recorded generation
 * number if you can not be sure that your code will not race with a bus reset.
 * 
 * @param priority is the priority assigned to the allocated packet, the priority for the 
 * memory object is IEEE1394_OBJECT_PRIORITY + priority. 
 * @return A pointer to a &struct hpsb_packet or NULL on allocation
 * failure.
 */
struct hpsb_packet *hpsb_alloc_packet(size_t data_size,struct rtpkb_pool *pool, unsigned int priority)
{
        
	struct hpsb_packet *packet = NULL;
        struct rtpkb *pkb;

	size_t length = data_size + IEEE1394_HEADER_SIZE;
	length = ((length + 3) & ~3);
	
	pkb = alloc_rtpkb(length, pool);
	if(pkb == NULL)
		return NULL;
	packet = (struct hpsb_packet *)pkb;
	memset((u8 *)packet + sizeof(packet->base), 0, sizeof(*packet) - sizeof(packet->base));	
	
	packet->header=(quadlet_t *)pkb->data;
	packet->data = (quadlet_t *)(pkb->data + IEEE1394_HEADER_SIZE);
	packet->pri = priority;
	pkb->priority = IEEE1394_OBJECT_PRIORITY + priority;

	packet->state = hpsb_unused;
	packet->generation = -1;
	INIT_LIST_HEAD(&packet->driver_list);
	atomic_set(&packet->refcnt, 1);

	packet->header_size = IEEE1394_HEADER_SIZE;
	packet->data_size = data_size;
			
	return packet;
}


/**
 * @ingroup kernel
 * @anchor hpsb_free_packet
 *
 * Return the memory object to its origin pool. 
 */
void hpsb_free_packet (struct hpsb_packet *packet)
{
	if(packet == NULL) {
		HPSB_ERR("packet NULL!!!\n");
		return;
	}
	if(!atomic_dec_and_test(&packet->refcnt))
		HPSB_ERR("packet to %s still refered!\n", 
				((struct rtpkb *)packet)->pool->name);
	
	kfree_rtpkb((struct rtpkb *)packet);
}


/**
 * @ingroup kernel 
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
		HPSB_ERR("host %s is already in reset\n", host->name);
                return 1;
        }
}

/**
 * @ingroup kernel
 * @anchor hpsb_bus_reset
 * Called by driver when a bus reset occurs on a certain host. 
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
 * @ingroup kernel
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
 * @ingroup kernel
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
 * @ingroup kernel
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
 * @ingroup kernel
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
 * @ingroup kernel
 * @anchor hpsb_packet_sent
 * Function called when the ack of a certain request packet has been reecived. 
 *
 * @note see @ref Asynchronous Transaction setion of "Overview of Real-Time FireWire stack".
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
		__rtpkb_unlink((struct rtpkb *)packet, &host->pending_packet_queue);
		rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
		queue_packet_complete(packet);
                return;
        }

        packet->state = hpsb_pending;

        rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
	
	nanosecs_t  timeout = 30000*MICRO_SEC; //for real-time application
	
	if(packet->pri==IEEE1394_PRIORITY_HIGHEST) //for bus internal service
		timeout = 20000*MICRO_SEC;
	if(packet->pri==IEEE1394_PRIORITY_LOWEST) //for non real-time application
		timeout = 50000*MICRO_SEC;

	//here we add new timeout to our timeout server
	packet->misc = (unsigned long ) rt_request_pend(timeout_server, (unsigned long)packet, //the parameter passed to server
							timeout,//the time length of timeout (ns)
							NULL, //for now, no callback needed from server
							0, NULL); //no callback data; no name
	rt_serv_sync(timeout_server);
}


/**
 * @ingroup kernel
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

	/* we assign highest priority to physical packet */
	packet = hpsb_alloc_packet(0,&host->pool, IEEE1394_PRIORITY_HIGHEST);
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
 * @ingroup kernel
 * @anchor hpsb_send_packet
 * transmit a packet on the bus
 *
 * The packet is sent through the host specified in the packet->host field.
 * Before sending, the packet's transmit speed is automatically determined using
 * the local speed map when it is an async, non-broadcast packet.
 *
 * Possibilities for failure are that host is either not initialized, or in bus
 * reset, or the packet's generation number doesn't match the current generation
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
		rtpkb_queue_tail(&host->pending_packet_queue, (struct rtpkb *)packet);
	}
	
	HPSB_NOTICE("packet is sent to %d, while host is %d", packet->node_id, host->node_id);
	if (packet->node_id == host->node_id) {
		HPSB_NOTICE("sending to local....\n");
		
		packet->xmit_time = rtos_get_time();
		
		struct hpsb_packet *recvpkt;
		
		recvpkt = hpsb_alloc_packet(packet->data_size, &host->pool, packet->pri);
		if(!recvpkt)
			return -ENOMEM;
		
		recvpkt->data_size = packet->data_size;
		recvpkt->header_size = packet->header_size;

                memcpy(recvpkt->header, packet->header, packet->header_size);

		if(packet->data_size)
			memcpy(recvpkt->data, packet->data, packet->data_size);
			
		recvpkt->write_acked = (((packet->data[packet->data_size/4-1]>>16) & 0x1f)
				== 0x11) ? 1 : 0;
		recvpkt->host = host;
		recvpkt->tcode = packet->tcode;
		
		dump_packet("send packet local:", packet->header, 
				packet->header_size);
		
		hpsb_packet_sent(host, packet, packet->expect_response ? 
				ACK_PENDING : ACK_COMPLETE);
		hpsb_packet_received(recvpkt);
		
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
 * @ingroup kernel
 * @anchor complete_packet
 * To notify the completion of transaction, set as a callback. 
 *
 * @param data -- the counting semaphore set during sending of the packet. 
 */
static void complete_packet (struct hpsb_packet *packet, void *data)
{
	packet->processed = 1;	
	//~ wake_up(&packet->waitq);
	rtos_event_t	*sem=(rtos_event_t *)data;
	rtos_event_signal(sem);
}
	
/**
 * @ingroup kernel
 * @anchor hpsb_send_packet_and_wait
 * Wait until packet transaction is done. 
 * Synchronized versoin of hpsb_send_packet. 
 */
int hpsb_send_packet_and_wait(struct hpsb_packet *packet)
{
	int retval;
	rtos_event_t	sem;
	rtos_event_init(&sem);
	
	//~ init_waitqueue_head(&packet->waitq);
	hpsb_set_packet_complete_task(packet, complete_packet, (void *)&sem);
	retval = hpsb_send_packet(packet);
	if (retval == 0)
		//~ retval = wait_event_interruptible(packet->waitq, packet->processed);
		rtos_event_wait(&sem, 0);
	
	return retval;
}


/**
 * @ingroup kernel
 * @anchor send_packet_nocare
 */
static void send_packet_nocare(struct hpsb_packet *packet)
{
        if (hpsb_send_packet(packet)) {
		//sending failed in hardware, so we need to free the packet here. 
		//otherwise, the packet will be freed in hpsb_packet_sent
                hpsb_free_packet(packet);
        }
}

/**
 * @ingroup kernel
 * @anchor handle_packet_respnse
 * handle the response packet.
 *
 * Return is void, but error can happen when the tlabel does not match. 
 * Or tcode does not match. 
 */
void handle_packet_response(struct hpsb_packet *resp)
{
	struct hpsb_packet *packet = NULL;
	struct hpsb_host  *host = resp->host;
        struct rtpkb *pkb;
	int tcode = resp->tcode;
        int tcode_match = 0;
        int tlabel;
        unsigned long flags;

	tlabel = (resp->header[0] >> 10) & 0x3f;

        rtos_spin_lock_irqsave(&host->pending_packet_queue.lock, flags);
	
	rtpkb_queue_walk(&host->pending_packet_queue, pkb) {
		packet = (struct hpsb_packet *)pkb;

		if ((packet->tlabel == tlabel)
			&& (packet->node_id == (resp->header[1] >> 16))){
				break;
		}
		
		packet = NULL;
	}

	if (packet == NULL) {
		HPSB_DEBUG("unsolicited response packet received \
					or packet has been dequeued due to timeout \
					- no tlabel match");
		dump_packet("contents:", resp->header, 16);
		rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
		hpsb_free_packet(resp);
		return;
	}
	
	//we first cancel the timeout setting in timeout server
	if(packet->misc)
		rt_request_delete(timeout_server, (struct rt_request_struct *)packet->misc);
	else {
		hpsb_free_packet(resp);
		return;
	}

	switch(packet->tcode){
		case TCODE_WRITEQ:
		case TCODE_WRITEB:
				if(tcode != TCODE_WRITE_RESPONSE)
					break;
				tcode_match = 1;
				break;
		case TCODE_READQ:
				if (tcode != TCODE_READQ_RESPONSE)
					break;
				tcode_match = 1;
				break;
		case TCODE_READB:
				if (tcode != TCODE_READB_RESPONSE)
					break;
				tcode_match = 1;
				break;
		case TCODE_LOCK_REQUEST:
				if (tcode != TCODE_LOCK_RESPONSE)
					break;
				tcode_match = 1;
				break;
	}
		
	if(!tcode_match) {
		rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
		HPSB_INFO("unsolicited response packet received - tcode mismatch");
                dump_packet("contents:", resp->header, resp->header_size);
		hpsb_free_packet(resp);
		return;
	}
	
	__rtpkb_unlink(pkb, pkb->list);
	
	rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
	
	
	if (packet->state == hpsb_queued) {
		resp->ack_code = ACK_PENDING;
	}else{
		resp->ack_code = packet->ack_code;
	}
	
	resp->state = hpsb_complete;
	
	resp->xmit_time = packet->xmit_time;
	resp->no_waiter = packet->no_waiter;
	resp->complete_routine = packet->complete_routine;
	resp->complete_data = packet->complete_data;
	
	struct rtpkb_pool *pool = pkb->pool;
	hpsb_free_tlabel(packet);
	hpsb_free_packet(packet);
	rtpkb_acquire((struct rtpkb *)resp, pool);
		
	queue_packet_complete(resp);
}

/**
 * @ingroup kernel
 * @anchor create_reply_packet
 * Create the general reply packet for asynchronous transactions
 * 
 * The fill_xxx routines are called after this function to fill in the 
 * specific stuff. 
 * @param data - the received request packet, from which the created reply 
 * packet draw the header info from: like node_id, tlabel. 
 * @note this routine can be called both in rtai and linux domain. 
 * @todo to distiguish if current process context is real-time or not.
 * and do sub-routines accordingly. 
 */
static struct hpsb_packet *create_reply_packet(struct hpsb_host *host,
					       quadlet_t *req_header, size_t dsize, int pri)
{
	struct hpsb_packet *packet;
	
	
	packet = hpsb_alloc_packet(dsize, &host->pool, pri);
	if (packet == NULL) {
		/* FIXME - send data_error response */
			return NULL;
	}

	packet->type = hpsb_async;
	packet->state = hpsb_unused;
	packet->host = host;
	packet->node_id = req_header[1] >> 16;
	packet->tlabel = (req_header[0] >> 10)& 0x3f;
	packet->no_waiter = 1;
	
	packet->generation = get_hpsb_generation(host);
	
	if(dsize % 4)
		packet->data[dsize / 4] = 0;
	
	return packet;
}

#define PREP_ASYNC_HEAD_RCODE(tc) \
	packet->tcode = tc; \
	packet->header[0] = (packet->node_id << 16) | (packet->tlabel << 10) \
		| (1 << 8) | (tc << 4) | (packet->pri); \
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
                packet = create_reply_packet(host, req->header, length, pri); \
                if (packet == NULL) break

/**
 * Routine for prcessing incoming request packets.
 * @param arg is the priority of request packet. 
 * According to the priority, the routine finds the request
 * from three queues: bus internal service queue, real-time application
 * queue and non real-time application queue. 
 */
void req_worker(unsigned long arg)
{
	
	int priority = (int)arg;
	struct rtpkb *pkb;
	if(priority == 0)
		pkb = rtpkb_dequeue(&bis_req_list);
	else {
		if(priority == 15)
			pkb = rtpkb_dequeue(&nrt_req_list);
		else
			pkb = rtpkb_prio_dequeue(&rt_req_list);
	}
	
	struct hpsb_packet *req;
	struct hpsb_host *host;
	char tcode;
	int write_acked, pri;
	
	struct hpsb_packet *packet;
        int length, rcode, extcode;
        quadlet_t buffer;

	{		
		req = (struct hpsb_packet *)pkb;
		tcode = req->tcode;
		write_acked = req->write_acked;
		pri = req->pri;
		host = req->host;

			switch (tcode) {
				case TCODE_WRITEQ:
					rcode = highlevel_write(host, req, 4);

					if (!write_acked
						&& (NODEID_TO_NODE(req->header[0] >> 16) != NODE_MASK)
						&& (rcode >= 0)) {
						/* not a broadcast write, reply */
						PREP_REPLY_PACKET(0,pri);
						fill_async_write_resp(packet, rcode);
						send_packet_nocare(packet);
					}
					break;

				case TCODE_WRITEB:
					length = req->header[3] >> 16;
					rcode = highlevel_write(host, req, length);

					if (!write_acked
						&& (NODEID_TO_NODE(req->header[0] >> 16) != NODE_MASK)
						&& (rcode >= 0)) {
						/* not a broadcast write, reply */
						PREP_REPLY_PACKET(0, pri);
						fill_async_write_resp(packet, rcode);
						send_packet_nocare(packet);
					}
					break;

				case TCODE_READQ:
					rcode = highlevel_read(host, req, &buffer, 4);

					if (rcode >= 0) {
						PREP_REPLY_PACKET(0, pri);
						fill_async_readquad_resp(packet, rcode, buffer);
						send_packet_nocare(packet);
					}
					break;

				case TCODE_READB:
					length = req->header[3] >> 16;
					PREP_REPLY_PACKET(length, pri);
					rcode = highlevel_read(host, req, packet->data, length);
				
					if (rcode >= 0) {
						fill_async_readblock_resp(packet, rcode, length);
						send_packet_nocare(packet);
					} else {
						hpsb_free_packet(packet);
					}

					break;

				case TCODE_LOCK_REQUEST:
					length = req->header[3] >> 16;
					extcode = req->header[3] & 0xffff;

					PREP_REPLY_PACKET(8, pri);

					if ((extcode == 0) || (extcode >= 7)) {
						/* let switch default handle error */
						length = 0;
					}

				switch (length) {
				case 4:
					rcode = highlevel_lock(host, req, (quadlet_t *)packet->data);
					fill_async_lock_resp(packet, rcode, extcode, 4);
					break;
				case 8:
					if ((extcode != EXTCODE_FETCH_ADD) 
					    && (extcode != EXTCODE_LITTLE_ADD)) {
						rcode = highlevel_lock(host, req,
								       (quadlet_t *)packet->data);
						fill_async_lock_resp(packet, rcode, extcode, 4);
					} else {
						rcode = highlevel_lock64(host, req,
							     (octlet_t *)packet->data);
						fill_async_lock_resp(packet, rcode, extcode, 8);
					}
					break;
				case 16:
					rcode = highlevel_lock64(host, req,
								 (octlet_t *)packet->data);
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
			
	}
	
	hpsb_free_packet(req);
}

#undef PREP_REPLY_PACKET

#define cond_le32_to_cpu(data, noswap) \
	(noswap ? data : le32_to_cpu(data))

/**
 * @ingroup kernel
 * @anchor hpsb_packet_received
 * Routine for processing received packet.
 * 
 * @param write_acked - 
 */
void hpsb_packet_received(struct hpsb_packet *packet)
{

	struct rt_serv_struct *broker=NULL;

        if (packet->host->in_bus_reset) {
                HPSB_INFO("received packet during reset; ignoring");
                return;
        }

	dump_packet("received packet:", packet->header, packet->header_size);
	HPSB_NOTICE("packet priority %d\n, tcode %d", packet->pri, packet->tcode);

        switch (packet->tcode) {
        case TCODE_WRITE_RESPONSE:
        case TCODE_READQ_RESPONSE:
        case TCODE_READB_RESPONSE:
        case TCODE_LOCK_RESPONSE:
                handle_packet_response(packet);
                break;

        case TCODE_WRITEQ:
        case TCODE_WRITEB:
        case TCODE_READQ:
        case TCODE_READB:
        case TCODE_LOCK_REQUEST:

		switch(packet->pri){
			case IEEE1394_PRIORITY_HIGHEST:
					if(rtpkb_acquire((struct rtpkb *)packet, bis_req_list.pool)) {
						HPSB_ERR("req list %s run out of memory\n", bis_req_list.name);
						break;
					}
					rtpkb_queue_tail(&bis_req_list, (struct rtpkb *)packet);
					broker = bis_req_server;
					break;
			case IEEE1394_PRIORITY_LOWEST:
					if(rtpkb_acquire((struct rtpkb *)packet, nrt_req_list.pool)) {
						HPSB_ERR("req list %s run out of memory\n", nrt_req_list.name);
						break;
					}
					rtpkb_queue_tail(&nrt_req_list, (struct rtpkb *)packet);
					broker = nrt_req_server;
					break;
			default:
					if(packet->pri >15 || packet->pri <0){
						HPSB_ERR("request with outrange priority received!!!\n");
						break;
					}else{
						if(rtpkb_acquire((struct rtpkb *)packet,rt_req_list.pool)) {
							HPSB_ERR("req list %s run out of memory\n", rt_req_list.name);
							break;
						}
						rtpkb_prio_queue_tail(&rt_req_list, (struct rtpkb *)packet); 
						broker = rt_req_server;
					}
					break;
		}
		
		break;

        case TCODE_ISO_DATA:

                break;

        case TCODE_CYCLE_START:
		HPSB_NOTICE("cycle start message received\n");
                /* simply ignore this packet if it is passed on */
                break;

        default:
                HPSB_NOTICE("received packet with bogus transaction code %d", 
                            packet->tcode);
                break;
        }
	
	if(broker){
		//ok, we need to pend the request to server, and sync it. 
		rt_request_pend(broker, (unsigned long)packet->pri, //the parameter passed to server
								0, //no delay wanted
								NULL, //for now, no callback needed from server
								0, NULL); //no callback data; no name
		rt_serv_sync(broker);
	}
}

/**
 * @ingroup kernel
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
	struct rtpkb *pkb;
		
	
	host->driver->devctl(host, CANCEL_REQUESTS, 0);
	
	while ((pkb = rtpkb_dequeue(&host->pending_packet_queue)) != NULL) {
		packet = (struct hpsb_packet *)pkb;
		
		//dont forget to cancel timeout setting
		rt_request_delete(timeout_server, (struct rt_request_struct *)packet->misc);
			
		packet->state = hpsb_complete;
		packet->ack_code = ACKX_ABORTED;
		hpsb_free_tlabel(packet);
		queue_packet_complete(packet);
	}
}
	
/* Internal proc for timeout server */
void abort_timedouts(unsigned long data)
{
	struct hpsb_packet *packet = (struct hpsb_packet *)data;
	struct hpsb_host *host = packet->host;
		
	HPSB_ERR("packet sent to node[%d] from %s timeouts!!!\n", 
			packet->node_id, packet->host->name);
	
	unsigned long flags;
	rtos_spin_lock_irqsave(&host->pending_packet_queue.lock, flags);
	
	//get packet out of the pending packet queue
	struct rtpkb *pkb = (struct rtpkb *)packet;
	__rtpkb_unlink(pkb, pkb->list); 
	
	//assign the state and ack code and queue it to complete queue
	packet->state = hpsb_complete;
	packet->ack_code = ACKX_TIMEOUT;
	
	//we need to free the tlabel here!
	hpsb_free_tlabel(packet);
	queue_packet_complete(packet);
	
	rtos_spin_unlock_irqrestore(&host->pending_packet_queue.lock, flags);
}


/*!
  * @brief Queue complete transaction packet 
  * 
  * @param[in] packet Packet of which the transaction has completed
  *
  * This function queues the completed packet to the queue of resp_worker.
  *  The order is according to the priority.
  * If the packet has no waiter, it is just freed. 
  */
static void queue_packet_complete(struct hpsb_packet *packet)
{
	if (packet->no_waiter) {
		hpsb_free_packet(packet);
		return;
	}
	if (packet->complete_routine != NULL) {
		rtpkb_prio_queue_tail(&resp_list, (struct rtpkb *)packet);
		rt_request_pend(resp_server, 0, //no parameter needs to be passed to response server 
						0, //delay? NO
						NULL, // NO callback 
						0, NULL); // NO callback data, and NO name
		//dont forget to sync the server
		rt_serv_sync(resp_server);
	}
	return;
}



/* Internal proc for response handling */
void resp_worker(unsigned long dummy)
{
	
	struct rtpkb_prio_queue *list = (struct rtpkb_prio_queue *)&resp_list;
	struct rtpkb *pkb;
	struct hpsb_packet *packet;
	void (*complete_routine)(struct hpsb_packet *, void*);
	void *complete_data;
	
	if ((pkb = rtpkb_prio_dequeue(list)) != NULL) {
			packet = (struct hpsb_packet *)pkb;

			//calculate and log the time elapsecd between request and response
			packet->xmit_time = rtos_get_time() - packet->xmit_time;
			HPSB_NOTICE("%s:req2resp latency is %d ns\n", __FUNCTION__, (int)packet->xmit_time);
				
			complete_routine = packet->complete_routine;
			complete_data = packet->complete_data;
			
			packet->complete_routine = packet->complete_data = NULL;
			
			if(complete_routine)
				complete_routine(packet, complete_data);
			
			hpsb_free_packet(packet);
	}
}
		
	



struct proc_dir_entry *rtfw_procfs_entry;
	
/**
 * @ingroup kernel
 * @anchor ieee1394_core_init
 */
int ieee1394_core_init(void)
{
	int ret=0;
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
	
	
	
	rtpkb_prio_queue_init(&resp_list);
	name = "resp1394";
	resp_server = rt_serv_init(name, RESP_SERVER_PRI,  resp_worker, -1);
	if(!resp_server){
		HPSB_ERR("response server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_resp_server;
	}
	
	rtpkb_queue_init(&bis_req_list);
	rtpkb_pool_init(&bis_req_pool, 16);
	bis_req_list.pool = &bis_req_pool;
	name = "bis1394";
	bis_req_server = rt_serv_init(name, BIS_SERVER_PRI, req_worker, -1);
	if(!bis_req_server){
		HPSB_ERR("Bus internal request server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_bis_req_server;
	}

	rtpkb_prio_queue_init(&rt_req_list);
	rtpkb_pool_init(&rt_req_pool, 16);
	rt_req_list.pool = &rt_req_pool;
	name = "rt1394";
	rt_req_server = rt_serv_init(name, RT1394_SERVER_PRI,  req_worker, -1);
	if(!rt_req_server){
		HPSB_ERR("Real-Time request server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_rt_req_server;
	}

	rtpkb_queue_init(&nrt_req_list);
	rtpkb_pool_init(&nrt_req_pool, 16);
	nrt_req_list.pool = &nrt_req_pool;
	name = "nrt1394";
	nrt_req_server = rt_serv_init(name, -1,  req_worker, -1);//we are in linux
	if(!nrt_req_server){
		HPSB_ERR("Non Real-Time request server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_nrt_req_server;
	}
	
	name = "timeout";
	timeout_server = rt_serv_init(name, TIMEOUT_SERVER_PRI, abort_timedouts, -1);
	if(!timeout_server){
		HPSB_ERR("Timeout server initialization failed\n");
		ret = -ENOMEM;
		goto error_exit_timeout_server;
	}
	
	ret = init_csr();
	if(ret) {
		HPSB_INFO("init csr failed");
		ret = -ENOMEM;
		goto error_exit_init_csr;
	}
	
	return ret;

error_exit_init_csr:
	rt_serv_delete(timeout_server);
error_exit_timeout_server:
	rt_serv_delete(nrt_req_server);
error_exit_nrt_req_server:
	rtpkb_pool_release(&nrt_req_pool);
	rt_serv_delete(rt_req_server);
error_exit_rt_req_server:
	rtpkb_pool_release(&rt_req_pool);
	rt_serv_delete(bis_req_server);
error_exit_bis_req_server:
	rtpkb_pool_release(&bis_req_pool);
	rt_serv_delete(resp_server);
error_exit_resp_server:
	hpsb_cleanup_config_roms();
	remove_proc_entry("rt-firewire",0);
	return ret;
}

/**
 * @ingroup kernel
 * @anchor ieee1394_core_cleanup
 */
void ieee1394_core_cleanup(void)
{
	cleanup_csr();
	
	rt_serv_delete(timeout_server);
	rt_serv_delete(nrt_req_server);
	rt_serv_delete(rt_req_server);
	rt_serv_delete(bis_req_server);
	rt_serv_delete(resp_server);
	rtpkb_pool_release(&bis_req_pool);
	rtpkb_pool_release(&nrt_req_pool);
	rtpkb_pool_release(&rt_req_pool);
	
	hpsb_cleanup_config_roms();
	remove_proc_entry("rt-firewire",0);
}

