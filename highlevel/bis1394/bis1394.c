/**
 * @ingroup bis
 * @file
 * implementation of bus internal service module
 */
 
 /**
  * @defgroup bis bus internal service on FireWire
  *
 * Runing raw packet transmission on FireWire for
  * testing and bus management purpose:
  * - asynchronous request and response
  * - asynchronous stream
  * - isochronous stream
  * - physical packet
  * 
  * interface to user through char device
  */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <rtpc.h>
#include <rtos_primitives.h>
#include <ieee1394_chrdev.h>
#include <ieee1394_core.h>
#include <highlevel.h>
#include <hosts.h>
#include <bis1394.h>
#include <ieee1394.h>
#include <ieee1394_transactions.h>
#include <asm/uaccess.h>
#include <iso.h>

static void add_host(struct hpsb_host *host);
static void remove_host(struct hpsb_host *host);

static struct hpsb_highlevel bis_highlevel = {
	.name =		"Bus Internal Service on FireWire",
	.add_host =	add_host,
	.remove_host =	remove_host,
};

struct hpsb_iso *bis1394_iso;
	
void bis_queue_echo_request(struct rt_proc_call *call)
{
	unsigned long 	flags;
	struct bis_host_info	*hi;
		
	hi = (struct bis_host_info *)hpsb_get_hostinfo(&bis_highlevel, ((struct bis_cmd *)call->priv_data)->host);
	
	rtos_spin_lock_irqsave(&hi->echo_calls_lock, flags);
	list_add_tail(&call->list_entry, &hi->echo_calls);
	rtos_spin_unlock_irqrestore(&hi->echo_calls_lock, flags);
}

void bis_cleanup_echo_requests(struct hpsb_host *host)
{
	unsigned long flags;
	struct list_head 	*entry;
	struct list_head	*next;

	struct bis_host_info	*hi = (struct bis_host_info *)hpsb_get_hostinfo(&bis_highlevel, host);
	entry = &hi->echo_calls;	
	rtos_spin_lock_irqsave(&hi->echo_calls_lock, flags);
	entry = hi->echo_calls.next;
	INIT_LIST_HEAD(&hi->echo_calls);
	rtos_spin_unlock_irqrestore(&hi->echo_calls_lock, flags);
	
	while(entry != &hi->echo_calls) {
		next = entry->next;
		rtpc_complete_call_nrt((struct rt_proc_call *)entry, -EINTR);
		entry = next;	
	}
}

static void bis_echo_reply(struct hpsb_packet *packet, void *data)
{
	
	unsigned long	flags;
	struct rt_proc_call	*call = NULL;
	struct bis_cmd	*cmd;
	
	struct bis_host_info	*hi = (struct bis_host_info *)hpsb_get_hostinfo(&bis_highlevel,packet->host);
	
	if(!hi) {
		rtos_print("%s: hi is NULL\n", __FUNCTION__);
		return;
	}
		
	rtos_spin_lock_irqsave(&hi->echo_calls_lock, flags);
	
	
	if(!list_empty(&hi->echo_calls)) {
		
		call = (struct rt_proc_call *)(hi->echo_calls.next);
		list_del(&call->list_entry);
		rtos_spin_unlock_irqrestore(&hi->echo_calls_lock, flags);
	}else {
		
		rtos_spin_unlock_irqrestore(&hi->echo_calls_lock, flags);
		goto echo_fail;
	}	
		
	int	ret = 0;
	ret = hpsb_packet_success(packet);
	if(ret<0){
		
		goto echo_fail;
	}
	
	cmd = rtpc_get_priv(call, struct bis_cmd);
	cmd->args.ping.rtt = packet->xmit_time;
	
echo_fail:
	rtpc_complete_call(call, ret);
	return;	
}


int bis_send_echo(struct hpsb_host *host, nodeid_t node, size_t msg_size, 
						int pri, struct rt_proc_call *call)
{
	
	unsigned int generation = atomic_read(&host->generation);
	int ret = 0;
	
	if(msg_size == 0)
		return -EINVAL;
	
	/** make packet with highest priority **/
	struct hpsb_packet *packet = hpsb_make_readpacket(host, node, BIS1394_REGION_ADDR_BASE, msg_size,pri);
	if(!packet) {
		
		return -ENOMEM;
	}
	
	#ifdef CONFIG_IEEE1394_VERBOSEDEBUG
	int i;
	rtos_print("%s:", __FUNCTION__);
	for (i = 0; i < packet->header_size; i++)
		rtos_print(" %08x", packet->header[i]);
	rtos_print("\n");
	#endif
	
	packet->generation = generation;
	
	hpsb_set_packet_complete_task(packet, bis_echo_reply,0);
	ret = hpsb_send_packet(packet);
	if (ret<0) {
		
		hpsb_free_tlabel(packet);
		hpsb_free_packet(packet);
	}
		
	return ret;
	
}



static int ping_handler(struct rt_proc_call *call)
{
	struct bis_cmd *cmd;
	int err;
	
	cmd = rtpc_get_priv(call, struct bis_cmd);
	
	bis_queue_echo_request(call);

	err = bis_send_echo(cmd->host, LOCAL_BUS | cmd->args.ping.destid, cmd->args.ping.msg_size, 
						cmd->args.ping.pri, call);
	if(err<0) {
		bis_cleanup_echo_requests(cmd->host);
		return err;
	}
	
	return -CALL_PENDING;
}

static void ping_complete_handler(struct rt_proc_call *call, void *priv_data)
{
	struct bis_cmd *cmd;
	struct bis_cmd *usr_cmd  = (struct bis_cmd *)priv_data;

	
	if(rtpc_get_result(call) < 0)
		return;
	
	cmd = rtpc_get_priv(call, struct bis_cmd);
	usr_cmd->args.ping.destid = cmd->args.ping.destid;
	usr_cmd->args.ping.rtt = cmd->args.ping.rtt;	
}

static int bis_ioctl(struct hpsb_host *host, unsigned int request, 
			unsigned long arg)
{
	struct bis_cmd	cmd;
	int ret;
	
	ret = copy_from_user(&cmd, (void *)arg, sizeof(cmd));
	if(ret != 0)
		return -EFAULT;
	cmd.host = host;
	
	switch(request) {
		case IOC_RTFW_PING:
			ret = rtpc_dispatch_call(ping_handler, cmd.args.ping.timeout, &cmd,
							sizeof(cmd), ping_complete_handler, NULL);
			if(ret >= 0) {
				if(copy_to_user((void *)arg, &cmd, sizeof(cmd)) != 0)
					return -EFAULT;
			}else
				bis_cleanup_echo_requests(host);
			break;
			
		case IOC_RTFW_ISO_START:
			if(bis1394_iso){
				ret = -EBUSY;
				break;
			}
			bis1394_iso = hpsb_iso_xmit_init(host, cmd.args.iso.data_buf_size, 1, 
									cmd.args.iso.channel, 2, 1, NULL, 0, "bis1394_iso", 10);
			if(!bis1394_iso)
				ret = -ENOMEM;
			break;
		
		case IOC_RTFW_ISO_SHUTDOWN:
			if(bis1394_iso){
				hpsb_iso_shutdown(bis1394_iso);
				bis1394_iso = NULL;
			}
			ret = 0;
			break;
		
		default:
			ret = -ENOTTY;
	}
	
	return ret;
}


static int bis_read(struct hpsb_host *host, struct hpsb_packet *packet, quadlet_t *data, unsigned int len)
{
	return RCODE_COMPLETE;
}

static struct hpsb_address_ops bis1394_ops = {
	.read = bis_read,
};
  
static void add_host(struct hpsb_host *host)
{
	
	struct bis_host_info *hi;
	int ret;
		
	hi = hpsb_create_hostinfo(&bis_highlevel, host, sizeof(*hi));
	if(!hi) {
		HPSB_ERR("BIS: out of memory in add host");
		return;
	}
	
	hi->host = host;
	rtos_spin_lock_init(&hi->echo_calls_lock);
	INIT_LIST_HEAD(&hi->echo_calls);
	
	//register the addr space for testing asynchronous transaction	
	ret = hpsb_register_addrspace(&bis_highlevel, host, &bis1394_ops,
								BIS1394_REGION_ADDR_BASE,
								BIS1394_REGION_ADDR_BASE + BIS1394_REGION_ADDR_LEN);
	if(ret == 0)
		goto out;
	
	return;
out:
	kfree(hi);	
	return;
}

static void remove_host(struct hpsb_host *host)
{
	unsigned long flags;
	struct list_head *entry;
	struct list_head *next;
	
	struct bis_host_info *hi = (struct bis_host_info *)hpsb_get_hostinfo(&bis_highlevel, host);
		
	// to unregister the address space
	hpsb_unregister_addrspace(&bis_highlevel, host, BIS1394_REGION_ADDR_BASE);
	
	//to clean up all the queued service requests, i.e. force to complete with -EINTR
	if(hi) {
		rtos_spin_lock_irqsave(&hi->echo_calls_lock, flags);
		entry = hi->echo_calls.next;
		INIT_LIST_HEAD(&hi->echo_calls);
		rtos_spin_unlock_irqrestore(&hi->echo_calls_lock, flags);
		
		while(entry != &hi->echo_calls) {
			next = entry->next;
			rtpc_complete_call_nrt((struct rt_proc_call *)entry, -EINTR);
			entry = next;
		}
	}else
		HPSB_ERR("BIS: host %s does not exist, can not remove", 
				host->name);
	
	hpsb_destroy_hostinfo(&bis_highlevel, host);
	
	return;		
}


/** Socket to FireWire stack **/

static struct ioctl_handler bis_ioctls = {
	.service_name 	=	"Bus Internal Service on FireWire",
	.ioctl_type	=	RTFW_IOC_TYPE_BIS,
	.handler	=	bis_ioctl,
};

  
int bis1394_init(void)
{
	hpsb_register_highlevel(&bis_highlevel);
	
	ieee1394_register_ioctls(&bis_ioctls);
	
	rtos_timer_start_oneshot();
	
	return 0;
}
  
void bis1394_exit(void)
{
	hpsb_unregister_highlevel(&bis_highlevel);
	ieee1394_unregister_ioctls(&bis_ioctls);
	rtos_timer_stop();
}

module_init(bis1394_init);
module_exit(bis1394_exit);
MODULE_LICENSE("GPL");


