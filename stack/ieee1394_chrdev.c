/**
 * @ingroup chrdev
 * @file
 * 
 * Implementation of char device module
 */
 
/*
 * ieee1394_chrdev.c - implements char device for management interface for RTnet-Firewire
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
/**
 * @defgroup chrdev Char Device Module
 */
 
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/kmod.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>

#include <ieee1394_chrdev.h>
#include <rtos_primitives.h>


static rwlock_t ioctl_handlers_lock = RW_LOCK_UNLOCKED;

LIST_HEAD(ioctl_handlers);


/**
 * @ingroup chrdev
 * @anchor ieee1394_ioctl
 * Registered in LInux for ioctl on chardev.
 * 
 * @return 0 on success
 * @b -EPERM
 * @b -EFAULT
 * @b -ENODEV
 * @b -ENOTTY
 */
static int ieee1394_ioctl(struct inode *inode, struct file *file,
                       unsigned int request, unsigned long arg)
{
	struct ieee1394_ioctl_head head;
	struct hpsb_host     *host = NULL;
	struct ioctl_handler     *ioctls;
	struct list_head        *lh;
	int                      ret;
    	
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = copy_from_user(&head, (void *)arg, sizeof(head));
	if (ret != 0)
		return -EFAULT;
    
	if ((_IOC_NR(request) & RTFW_IOC_NODEV_PARAM) == 0) {
                host = host_get_by_name(head.if_name);
                if (!host) {
                    return -ENODEV;
                }
	}
	
	read_lock_bh(&ioctl_handlers_lock);
	
	list_for_each(lh, &ioctl_handlers) {
		ioctls = list_entry(lh, struct ioctl_handler, entry);
	
			if (ioctls->ioctl_type == _IOC_TYPE(request)) {
				read_unlock_bh(&ioctl_handlers_lock);
				atomic_inc(&ioctls->ref_count);
				ret = ioctls->handler(host, request, arg);
				atomic_dec(&ioctls->ref_count);
				
				if(host)
					atomic_dec(&host->refcount);
				/*! it's not possible for more than one ioctl_handler to have the same type */
				return ret;
			}
	}
	
	read_unlock_bh(&ioctl_handlers_lock);
	
	if(host)
		atomic_dec(&host->refcount);
	return -ENOTTY;
}

/**
 * @ingroup chrdev
 * @anchor ieee1394_core_ioctl
 * basic ioctl, registered as frist
 * after stack initialization
 */
static int ieee1394_core_ioctl(struct hpsb_host *host, unsigned int request,
                            unsigned long arg)
{
    struct ieee1394_core_cmd   cmd;
    int                     ret;
    
    ret = copy_from_user(&cmd, (void *)arg, sizeof(cmd));
    if (ret != 0)
        return -EFAULT;
	
    switch (request) {
        case IOC_RTFW_IFUP:
            if (down_interruptible(&host->nrt_lock))
                return -ERESTARTSYS;

            set_bit(PRIV_FLAG_UP, &host->priv_flags);

            host->flags |= cmd.args.up.set_dev_flags;
            host->flags &= ~cmd.args.up.clear_dev_flags;

            ret = host_open(host);    /* also = 0 if host already up */
	    
            up(&host->nrt_lock);
            break;

        case IOC_RTFW_IFDOWN:
            if (down_interruptible(&host->nrt_lock))
                return -ERESTARTSYS;
		
	    /**
	     * @todo this is obviously legacy from Ethernet
	     * we should replace it to sthelse, like bus reset
	     */
            if (test_bit(PRIV_FLAG_ADDING_ROUTE, &host->priv_flags)) {
                up(&host->nrt_lock);
                return -EBUSY;
            }
            clear_bit(PRIV_FLAG_UP, &host->priv_flags);

            ret = 0;

	    ret = host_close(host);

            up(&host->nrt_lock);
            break;

        case IOC_RTFW_IFINFO:
		
            if (cmd.args.info.ifindex > 0){
                host = host_get_by_index(cmd.args.info.ifindex);}
            else{
                host = host_get_by_name(cmd.head.if_name);}
            if (!host) 
                return -ENODEV;

            if (down_interruptible(&host->nrt_lock)) {
		atomic_dec(&host->refcount);
                return -ERESTARTSYS;
            }
            memcpy(cmd.head.if_name, host->name, IFNAMSIZ);
            cmd.args.info.ifindex      = host->ifindex;
            cmd.args.info.type         = host->type;
	    cmd.args.info.flags	=	host->flags;
	    memcpy(cmd.args.info.dev_id, host->dev_id, MAX_DEV_ID_LEN);
	    //~ cmd.args.info.rmem_end	= host->rmem_end;
	    //~ cmd.args.info.rmem_start	= host->rmem_start;
	    cmd.args.info.mmio_end	= host->mmio_end;
	    cmd.args.info.mmio_start	= host->mmio_start;
	    cmd.args.info.base_addr	= host->base_addr;
	    cmd.args.info.irq = host->irq;
	    memcpy(cmd.args.info.driver, host->driver->name, MAX_DRV_NAME_LEN);
	    
	    cmd.args.info.max_packet_size = host->max_packet_size;
	    cmd.args.info.pending_packets = host->pending_packet_queue.qlen;
	    cmd.args.info.generation = atomic_read(&host->generation);
	    cmd.args.info.node_id		= host->node_id & 0x3F;
	    cmd.args.info.irm_id	= host->irm_id & 0x3F;
	    cmd.args.info.busmgr_id	= host->busmgr_id & 0x3F;
	    cmd.args.info.bw_remaining = host->csr.bandwidth_available;
	    cmd.args.info.channels = ((u64)host->csr.channels_available_hi<<32) |(host->csr.channels_available_lo);
	    
	    cmd.args.info.nb_iso_xmit_ctx = host->nb_iso_xmit_ctx;
	    cmd.args.info.it_ctx_usage = host->it_ctx_usage;
	    cmd.args.info.nb_iso_rcv_ctx = host->nb_iso_rcv_ctx;
	    cmd.args.info.ir_ctx_usage = host->ir_ctx_usage;

            up(&host->nrt_lock);
	    atomic_dec(&host->refcount);

            if (copy_to_user((void *)arg, &cmd, sizeof(cmd)) != 0)
                return -EFAULT;
            break;
    }
    return ret;
}


/**
 * @ingroup chrdev
 * @anchor ieee1394_register_ioctls
 * To register a new ioctl to char device. 
 */
int ieee1394_register_ioctls(struct ioctl_handler *ioctl)
{
	struct list_head    *entry;
	struct ioctl_handler *registered_ioctls;


	RTOS_ASSERT(ioctl->handler != NULL, return -EINVAL;);

	write_lock_bh(&ioctl_handlers_lock);

	list_for_each(entry, &ioctl_handlers) {
		registered_ioctls = list_entry(entry, struct ioctl_handler, entry);
		if (registered_ioctls->ioctl_type == ioctl->ioctl_type) {
			write_unlock_bh(&ioctl_handlers_lock);
			return -EEXIST;
		}
	}

	list_add_tail(&ioctl->entry, &ioctl_handlers);
	atomic_set(&ioctl->ref_count, 0);

	write_unlock_bh(&ioctl_handlers_lock);
	
	printk("New ioctl %s registered\n", ioctl->service_name);

	return 0;
}


/**
 * @ingroup chrdev
 * @anchor ieee1394_unregister_ioctls
 * To unregister a ioctl. 
 */
void ieee1394_unregister_ioctls(struct ioctl_handler *ioctl)
{
	write_lock_bh(&ioctl_handlers_lock);

	while (atomic_read(&ioctl->ref_count) != 0) {
		write_unlock_bh(&ioctl_handlers_lock);

		printk("Ref counter of ioctl %s is not 0, unregisterration defered!!\n", ioctl->service_name);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(1*HZ); /* wait a second */

		write_lock_bh(&ioctl_handlers_lock);
	}

	list_del(&ioctl->entry);

	write_unlock_bh(&ioctl_handlers_lock);
}



static struct file_operations ieee1394_fops = {
    ioctl:  ieee1394_ioctl,
};

static struct miscdevice ieee1394_chr_misc_dev = {
    minor:  RT1394_MINOR,
    name:   "rt-firewire",
    fops:   &ieee1394_fops,
};

/**
 * @ingroup chrdev
 */
static struct ioctl_handler core_ioctls = {
    service_name:   "RT-Firewire Core",
    ioctl_type:     RTFW_IOC_TYPE_CORE,
    handler:        ieee1394_core_ioctl
};


/**
 * @ingroup chrdev
 * @anchor ieee1394_chrdev_init
 * initialize the char device for RT-Firewire stack 
 */
int __init ieee1394_chrdev_init(void)
{
    int ret = misc_register(&ieee1394_chr_misc_dev);

    if (ret < 0)
        printk("RT-Firewire: unable to register management character device "
               "(error %d)\n", ret);

    ieee1394_register_ioctls(&core_ioctls);

    return ret;
}

/**
 * @ingroup chrdev
 * @anchor ieee1394_chrdev_release
 * release the char device for RT-Firewire stack 
 */
void ieee1394_chrdev_release(void)
{
    misc_deregister(&ieee1394_chr_misc_dev);
}
