struct rt_raw1394_request {
        __u32 type;
        __s32 error;
        __u32 misc;

        __u32 generation;
        __u32 length;

        __u64 address;

        __u64 tag;

        __u64 sendb;
        __u64 recvb;
};

struct pending_request {
        struct list_head list;
        struct rt_raw1394_context *context;
        struct hpsb_packet *packet;
        quadlet_t *data;
        int free_data;
        struct rt_raw1394_request req;
};

struct rt_raw1394_context {
		struct list_head list;

        enum { opened, initialized, connected } state;
        unsigned int protocol_version;

        struct hpsb_host *host;

        struct list_head req_pending;
        struct list_head req_complete;
        //struct semaphore complete_sem;
        
        //we need real-time sync primitives here
        //spinlock_t reqlists_lock;
        //wait_queue_head_t poll_wait_complete;


		//this is used for arm (address range mapping
        struct list_head addr_list;

        u8 __user *fcp_buffer;
        
        u8 notification; /* (busreset-notification) RAW1394_NOTIFY_OFF/ON */
};


int rt_raw1394_open(struct rtdm_dev_context *context,
                  rtdm_user_info_t *user_info, int oflags)
{
 	return 0;
 	
}                 	
  
int rt_raw1394_close(struct rtdm_dev_context *context,
                   rtdm_user_info_t *user_info)
{
	return 0;
}
	                	
int rt_raw1394_ioctl(struct rtdm_dev_context *context,
                   rtdm_user_info_t *user_info, int request, void *arg)
{
	return 0;
	
}

int rt_raw1394_read(struct rtdm_dev_context *context,
                  rtdm_user_info_t *user_info, void *buf, size_t nbyte)
{
	return 0;
	
}

int rt_raw1394_write(struct rtdm_dev_context *context,
                   rtdm_user_info_t *user_info, const void *buf, size_t nbyte)
{
	return 0;
}


static const struct rtdm_device rt_raw1394_dev = {
	struct_version:     RTDM_DEVICE_STRUCT_VER,

    device_flags:       RTDM_NAMED_DEVICE | RTDM_EXCLUSIVE,
    context_size:       sizeof(struct rt_raw1394_context),
    device_name:        "",

    open_rt:            rt_raw1394_open,
    open_nrt:           rt_raw1394_open,

    ops: {
        close_rt:       rt_raw1394_close,
        close_nrt:      rt_raw1394_close,

        ioctl_rt:       rt_raw1394_ioctl,
        ioctl_nrt:      rt_raw1394_ioctl,

        read_rt:        rt_raw1394_read,
        read_nrt:      	rt_raw1394_read,

        write_rt:       rt_raw1394_write,
        write_nrt:      rt_raw1394_write,

        recvmsg_rt:     NULL,
        recvmsg_nrt:    NULL,

        sendmsg_rt:     NULL,
        sendmsg_nrt:    NULL,
    },

    device_class:       RTDM_CLASS_SERIAL,
    device_sub_class:   RTDM_SUBCLASS_16550A,
    driver_name:        "rt_raw1394",
    driver_version:     RTDM_DRIVER_VER(1, 2, 1),
    peripheral_name:    "Raw FireWire Interface",
    provider_name:      "RT-FireWire",
		
}

int __init rtraw1394_init(void)
{
	
	
}

void rtraw1394_exit(void)
{
	
}

