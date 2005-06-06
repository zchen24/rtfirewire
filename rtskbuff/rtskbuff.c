/**
 * @ingroup rtskb
 * @file
 * 
 * Implementation of Real-Time Socket Buffer Module, 
 * @see @ref rtskb
 *
 * @todo add rtskbuff self-containd copy from and to api. 
 */
 
#include <linux/config.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <net/checksum.h>

#include <rtskbuff.h>


static unsigned int global_rtskbs    = DEFAULT_GLOBAL_RTSKBS;
static unsigned int rtskb_cache_size = DEFAULT_RTSKB_CACHE_SIZE;
MODULE_PARM(global_rtskbs, "i");
MODULE_PARM(rtskb_cache_size, "i");
MODULE_PARM_DESC(global_rtskbs, "Number of realtime socket buffers in global pool");
MODULE_PARM_DESC(rtskb_cache_size, "Number of cached rtskbs for creating pools in real-time");


/* Linux slab pool for rtskbs */
static kmem_cache_t *rtskb_slab_pool;

/**
 * @ingroup
 * @anchor rtskb_cache
 */
/* preallocated rtskbs for real-time pool creation */
static struct rtskb_pool rtskb_cache={
	.name = "rtskb cache",
};

/* pool of rtskbs for global use */
struct rtskb_pool global_pool = {
	.name = "global pool",
};

/* pool statistics */
unsigned int rtskb_pools=0;
unsigned int rtskb_pools_max=0;
unsigned int rtskb_amount=0;
unsigned int rtskb_amount_max=0;

/**
 * list of memory pools
 */
LIST_HEAD(pool_list);

/**
 * this is to prevent new pool being created during bottomhalf
 * when the list is being accessed, like thru read_proc
 */
static rwlock_t pool_list_lock = RW_LOCK_UNLOCKED;

/**
 *  skb_over_panic - private function
 *  @skb: buffer
 *  @sz: size
 *  @here: address
 *
 *  Out of line support code for rtskb_put(). Not user callable.
 */
void rtskb_over_panic(struct rtskb *skb, int sz, void *here)
{
    char *name= "";
    if ( skb->dev_name )
        name=skb->dev_name;
    else
        name="<NULL>";
    rtos_print("RTskb: rtskb_put :over: %p:%d put:%d dev:%s\n", here, skb->len,
               sz, name);
}



/**
 *  skb_under_panic - private function
 *  @skb: buffer
 *  @sz: size
 *  @here: address
 *
 *  Out of line support code for rtskb_push(). Not user callable.
 */
void rtskb_under_panic(struct rtskb *skb, int sz, void *here)
{
    char *name = "";
    if ( skb->dev_name )
        name=skb->dev_name;
    else
        name="<NULL>";

    rtos_print("RTskb: rtskb_push :under: %p:%d put:%d dev:%s\n", here,
               skb->len, sz, name);
}

/**
 * @ingroup rtskb management
 * @anchor alloc_rtskb
 * dequeue a skb from memory pool
 * @param size - the length of data required, here it is
 * only used to check it doesnt exceed the limit,i.e.buf_len. 
 */
struct rtskb *alloc_rtskb(unsigned int size,struct rtskb_pool *pool)
{
	struct rtskb *skb;
	
	rtos_time_t probe_a, probe_b;
	rtos_get_time(&probe_a);
	
	if(size!=0)
		RTOS_ASSERT(size <= SKB_DATA_ALIGN(RTSKB_SIZE), return NULL;);
	
	skb = rtskb_dequeue(&pool->queue);
	
	//~ rtos_get_time(&probe_b);
	//~ rtos_time_diff(&probe_b, &probe_b, &probe_a);
	//~ rtos_print("%s: time diff is %d\n", __FUNCTION__, rtos_time_to_nanosecs(&probe_b));

	
	if (!skb)
		return NULL;

	rtskb_clean(skb);
	
	//~ rtos_get_time(&probe_b);
	//~ rtos_time_diff(&probe_b, &probe_b, &probe_a);
	//~ rtos_print("%s: time diff is %d\n", __FUNCTION__, rtos_time_to_nanosecs(&probe_b));

	return skb;
}

/***
 *  kfree_rtskb
 *  @skb    rtskb
 */
void kfree_rtskb(struct rtskb *skb)
{
    RTOS_ASSERT(skb != NULL, return;);
    RTOS_ASSERT(skb->pool != NULL, return;);
	
    rtskb_queue_tail(&skb->pool->queue, skb);
}

/***
 *  rtskb_pool_init
 *  @pool: pool to be initialized
 *  @initial_size: number of rtskbs to allocate
 *  return: number of actually allocated rtskbs
 */
unsigned int rtskb_pool_init(struct rtskb_pool *pool,
                             unsigned int initial_size)
{
    unsigned int i;

    rtskb_queue_head_init(&pool->queue);

    i = rtskb_pool_extend(pool, initial_size);
	
   list_add_tail(&pool->entry, &pool_list);

    rtskb_pools++;
    if (rtskb_pools > rtskb_pools_max)
        rtskb_pools_max = rtskb_pools;

    return i;
}

/***
 *  rtskb_pool_init_rt
 *  @pool: pool to be initialized
 *  @initial_size: number of rtskbs to allocate
 *  return: number of actually allocated rtskbs
 */
unsigned int rtskb_pool_init_rt(struct rtskb_pool *pool,
                                unsigned int initial_size)
{
    unsigned int i;

    rtskb_queue_head_init(&pool->queue);

    i = rtskb_pool_extend_rt(pool, initial_size);
	
   list_add_tail(&pool->entry, &pool_list);

    rtskb_pools++;
    if (rtskb_pools > rtskb_pools_max)
        rtskb_pools_max = rtskb_pools;

    return i;
}

/***
 *  __rtskb_pool_release
 *  @pool: pool to release
 */
void __rtskb_pool_release(struct rtskb_pool *pool)
{
    struct rtskb *skb;


    while ((skb = rtskb_dequeue(&pool->queue)) != NULL) {
        kmem_cache_free(rtskb_slab_pool, skb);
        rtskb_amount--;
    }
    
    list_del(&pool->entry);

    rtskb_pools--;
}



/***
 *  __rtskb_pool_release_rt
 *  @pool: pool to release
 */
void __rtskb_pool_release_rt(struct rtskb_pool *pool)
{
    struct rtskb *skb;


    while ((skb = rtskb_dequeue(&pool->queue)) != NULL) {
        rtskb_queue_tail(&rtskb_cache.queue, skb);
        rtskb_amount--;
    }
    
    list_del(&pool->entry);

    rtskb_pools--;
}



unsigned int rtskb_pool_extend(struct rtskb_pool *pool,
                               unsigned int add_rtskbs)
{
    unsigned int i;
    struct rtskb *skb;

    RTOS_ASSERT(pool != NULL, return -EINVAL;);

    for (i = 0; i < add_rtskbs; i++) {
        /* get rtskb from slab pool */
        if (!(skb = kmem_cache_alloc(rtskb_slab_pool, GFP_KERNEL))) {
            rtos_print(KERN_ERR "RTnet: rtskb allocation from slab pool failed\n");
            break;
        }

        /* fill the header with zero */
        memset(skb, 0, sizeof(struct rtskb));

        skb->pool = pool;
        skb->buf_start = ((char *)skb) + ALIGN_RTSKB_STRUCT_LEN;

        rtskb_queue_tail(&pool->queue, skb);

        rtskb_amount++;
        if (rtskb_amount > rtskb_amount_max)
            rtskb_amount_max = rtskb_amount;
    }

    pool->capc += i;

    return i;
}



unsigned int rtskb_pool_extend_rt(struct rtskb_pool *pool,
                                  unsigned int add_rtskbs)
{
    unsigned int i;
    struct rtskb *skb;

    RTOS_ASSERT(pool != NULL, return -EINVAL;);

    for (i = 0; i < add_rtskbs; i++) {
        /* get rtskb from rtskb cache */
        if (!(skb = rtskb_dequeue(&rtskb_cache.queue))) {
            rtos_print("RTskb: rtskb allocation from real-time cache "
                       "failed\n");
            break;
        }

        skb->pool = pool;

        rtskb_queue_tail(&pool->queue, skb);

        rtskb_amount++;
        if (rtskb_amount > rtskb_amount_max)
            rtskb_amount_max = rtskb_amount;
    }
    
    pool->capc += i;

    return i;
}



unsigned int rtskb_pool_shrink(struct rtskb_pool *pool,
                               unsigned int rem_rtskbs)
{
    unsigned int i;
    struct rtskb *skb;

    for (i = 0; i < rem_rtskbs; i++) {
        if ((skb = rtskb_dequeue(&pool->queue)) == NULL)
            break;

        kmem_cache_free(rtskb_slab_pool, skb);
        rtskb_amount--;
    }
    
    pool->capc -= i;

    return i;
}



unsigned int rtskb_pool_shrink_rt(struct rtskb_pool *pool,
                                  unsigned int rem_rtskbs)
{
    unsigned int i;
    struct rtskb *skb;

    for (i = 0; i < rem_rtskbs; i++) {
        if ((skb = rtskb_dequeue(&pool->queue)) == NULL)
            break;
	
        rtskb_queue_tail(&rtskb_cache.queue, skb);
        rtskb_amount--;
    }

    pool->capc -= i;
    
    return i;
}


int rtskb_acquire(struct rtskb *rtskb, struct rtskb_pool *comp_pool)
{
    struct rtskb *comp_rtskb;

    comp_rtskb = alloc_rtskb(0, comp_pool);

    if (!comp_rtskb)
        return -ENOMEM;

    comp_rtskb->pool = rtskb->pool;//do the hack here
    kfree_rtskb(comp_rtskb);

    rtskb->pool = comp_pool;

    return 0;
}

#define PUTF(fmt, args...)				\
do {							\
	len += sprintf(page + len, fmt, ## args);	\
	pos = begin + len;				\
	if (pos < off) {				\
		len = 0;				\
		begin = pos;				\
	}						\
	if (pos > off + count)				\
		goto done_proc;				\
} while (0)

static int rtskb_read_proc(char *page, char **start, off_t off, int count,
					int *eof, void *data)
{
	struct rtskb_pool *pool;
	
	struct list_head *lh;
	off_t begin=0, pos=0;
	int len=0;
	
	unsigned int rtskb_len = ALIGN_RTSKB_STRUCT_LEN + SKB_DATA_ALIGN(RTSKB_SIZE);
	
	read_lock_bh(&pool_list_lock);
	
	PUTF("Statistics\t\tCurrent\tMaximum\n"
					"rtskb pools\t\t%d\t%d\n"
					"rtskbs\t\t%d\t%d\n"
					"rtskb memory needed\t\t\%d\t%d\n",
					rtskb_pools, rtskb_pools_max,
					rtskb_amount, rtskb_amount_max,
					rtskb_amount * rtskb_len, rtskb_amount_max * rtskb_len);
	
	PUTF("Pools\t\tCurrent Balance\tMaximum Balance\n");

	list_for_each(lh, &pool_list) {
		pool = list_entry(lh, struct rtskb_pool, entry);
		PUTF("%s\t\t%d\t%d\n", pool->name, pool->queue.qlen, pool->capc);
	}
done_proc:
	read_unlock_bh(&pool_list_lock);

	*start = page + (off - begin);
	len -= (off - begin);
	if (len > count)
		len = count;
	else {
		*eof = 1;
		if (len <= 0)
			return 0;
	}

	return len;
}
#undef PUTF
 
int  rtskb_pools_init(void)
{
	struct proc_dir_entry *proc_entry;
	
	rtskb_slab_pool = kmem_cache_create("rtskb_slab_pool",
		ALIGN_RTSKB_STRUCT_LEN + SKB_DATA_ALIGN(RTSKB_SIZE),
		0, SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (rtskb_slab_pool == NULL)
		return -ENOMEM;
	
	proc_entry = create_proc_entry("rtskb", S_IFREG | S_IRUGO | S_IWUSR, 0);
	if(!proc_entry) {
		printk("RTskb:failed to create proc entry!\n");
		goto err_out1;
	}
	proc_entry->read_proc = rtskb_read_proc;
	
	/* reset the statistics (cache is accounted separately) */
	rtskb_pools      = 0;
	rtskb_pools_max  = 0;
	rtskb_amount     = 0;
	rtskb_amount_max = 0;
	
	/* create the rtskb cache like a normal pool */
	if (rtskb_pool_init(&rtskb_cache, rtskb_cache_size) < rtskb_cache_size)
		goto err_out2;

	/* create the global rtskb pool */
	if (rtskb_pool_init(&global_pool, global_rtskbs) < global_rtskbs)
		goto err_out3;
	
	printk("RTskb:Real-Time Socket Buffer Module Initialized!\n");

	return 0;

err_out3:
	rtskb_pool_release(&global_pool);
	rtskb_pool_release(&rtskb_cache);
err_out2:
	remove_proc_entry("rtskb", 0);

err_out1:
	kmem_cache_destroy(rtskb_slab_pool);

	return -ENOMEM;
}

void rtskb_pools_release(void)
{
    struct list_head *lh;
    struct rtskb_pool *pool;

    rtskb_pool_release(&global_pool);
    rtskb_pool_release(&rtskb_cache);
    
    list_for_each(lh, &pool_list){
	    pool = list_entry(lh, struct rtskb_pool, entry);
	    printk("RTskb: Memory Pool %s is still in use!!!\n", pool->name);
    }

    remove_proc_entry("rtskb",0);

    if (kmem_cache_destroy(rtskb_slab_pool) != 0)
        printk(KERN_CRIT "RTskb: memory leakage detected "
               "- reboot required!\n");
    else
	    printk("RTskb: Real-Time Socket Buffer Module unloaded\n");
}

module_init(rtskb_pools_init);
module_exit(rtskb_pools_release);

MODULE_LICENSE("GPL");
