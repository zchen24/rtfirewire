/**
 * @ingroup rtskb
 * @file
 *
 * data structure and interfaces of rtskb module
 */
 
#ifndef __RTSKBUFF_H_
#define __RTSKBUFF_H_

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <rt1394_sys.h>

/**
 * @addtogroup rtskb
 *@{*/
struct rtskb_head {
	/* These two members must be first. */
	struct rtskb	* next;
	struct rtskb	* prev;

	__u32		qlen;
	spinlock_t	lock;
	
	rtos_event_t 	*event; //this is needed when request is queued for server. 
	struct rtskb_pool	 *pool;
	
	unsigned char name[32];
};

struct rtskb_pool {
	struct rtskb_head queue;
			
	struct list_head entry;
	/**
	 * when pool get released, it must be checked that
	 * capc==queun->qlen, otherwise some buffer leakage 
	 * happened.
	*/
	__u32		capc;
	
	unsigned char name[32];
};

struct rtskb {
	/* These two members must be first. */
	struct rtskb	* next;			/* Next buffer in list 				*/
	struct rtskb	* prev;			/* Previous buffer in list 			*/

	struct rtskb_head * list;		/* List we are on now				*/
	struct rtskb_pool * pool;		/* where we are from and should come back when things are done */

	unsigned char	*head;			/* Head of buffer 				*/
	unsigned char	*data;			/* Data head pointer				*/
	unsigned char	*tail;			/* Tail pointer					*/
	unsigned char 	*end;			/* End pointer					*/
	unsigned int	len;

	void 		(*destructor)(struct rtskb *);	/* Destruct function		*/
	
	unsigned char *buf_start;
	
	unsigned char *dev_name;
	
	unsigned int pri;
};

/* default values for the module parameter */
#define DEFAULT_RTSKB_CACHE_SIZE    16      /* default number of cached rtskbs for new pools */
#define DEFAULT_GLOBAL_RTSKBS       16       /* default number of rtskb's in global pool */
#define DEFAULT_DEVICE_RTSKBS       16      /* default additional rtskbs per network adapter */
#define DEFAULT_SOCKET_RTSKBS       16      /* default number of rtskb's in socket pools */

#define ALIGN_RTSKB_STRUCT_LEN      SKB_DATA_ALIGN(sizeof(struct rtskb))
#define RTSKB_SIZE                  1544 /*maximum buffer load */

extern unsigned int socket_rtskbs;      /* default number of rtskb's in socket pools */

extern unsigned int rtskb_pools;        /* current number of rtskb pools      */
extern unsigned int rtskb_pools_max;    /* maximum number of rtskb pools      */
extern unsigned int rtskb_amount;       /* current number of allocated rtskbs */
extern unsigned int rtskb_amount_max;   /* maximum number of allocated rtskbs */

extern void rtskb_over_panic(struct rtskb *skb, int len, void *here);
extern void rtskb_under_panic(struct rtskb *skb, int len, void *here);

extern struct rtskb *alloc_rtskb(unsigned int size, struct rtskb_pool *pool);
#define dev_alloc_rtskb(len, pool)  alloc_rtskb(len, pool)

extern void kfree_rtskb(struct rtskb *skb);
#define dev_kfree_rtskb(a)  kfree_rtskb(a)

/**
 *	rtskb_queue_empty - check if a queue is empty
 *	@list: queue head
 *
 *	Returns true if the queue is empty, false otherwise.
 */
 
static inline int rtskb_queue_empty(struct rtskb_head *list)
{
	return (list->next == (struct rtskb *) list);
}

/**
 *	skb_peek
 *	@list_: list to peek at
 *
 *	Peek an &rtskb. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the head element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */
 
static inline struct rtskb *rtskb_peek(struct rtskb_head *list_)
{
	struct rtskb *list = ((struct rtskb *)list_)->next;
	if (list == (struct rtskb *)list_)
		list = NULL;
	return list;
}

/**
 *	rtskb_peek_tail
 *	@list_: list to peek at
 *
 *	Peek an &rtskb. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the tail element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */

static inline struct rtskb *rtskb_peek_tail(struct rtskb_head *list_)
{
	struct rtskb *list = ((struct rtskb *)list_)->prev;
	if (list == (struct rtskb *)list_)
		list = NULL;
	return list;
}

/**
 *	rtskb_queue_len	- get queue length
 *	@list_: list to measure
 *
 *	Return the length of an &rtskb queue. 
 */
 
static inline __u32 rtskb_queue_len(struct rtskb_head *list_)
{
	return(list_->qlen);
}

static inline void rtskb_queue_head_init(struct rtskb_head *list)
{
	rtos_spin_lock_init(&list->lock);
	list->prev = (struct rtskb *)list;
	list->next = (struct rtskb *)list;
	list->qlen = 0;
}

/*
 *	Insert an rtskb at the start of a list.
 *
 *	The "__skb_xxxx()" functions are the non-atomic ones that
 *	can only be called with interrupts disabled.
 */

/**
 *	__rtskb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 
static inline void __rtskb_queue_head(struct rtskb_head *list, struct rtskb *newsk)
{
	struct rtskb *prev, *next;

	newsk->list = list;
	list->qlen++;
	prev = (struct rtskb *)list;
	next = prev->next;
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
}


/**
 *	rtskb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of the list. This function takes the
 *	list lock and can be used safely with other locking &rtskb functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	

static inline void rtskb_queue_head(struct rtskb_head *list, struct rtskb *newsk)
{
	unsigned long flags;

	rtos_spin_lock_irqsave(&list->lock, flags);
	__rtskb_queue_head(list, newsk);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	
	if(list->event) rtos_event_signal(list->event);
}

/**
 *	__rtskb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the end of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 

static inline void __rtskb_queue_tail(struct rtskb_head *list, struct rtskb *newsk)
{
	struct rtskb *prev, *next;
		
	newsk->list = list;
	list->qlen++;
	next = (struct rtskb *)list;
	prev = next->prev;
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
}

/**
 *	rtskb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the tail of the list. This function takes the
 *	list lock and can be used safely with other locking &rtskb functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	

static inline void rtskb_queue_tail(struct rtskb_head *list, struct rtskb *newsk)
{
	unsigned long flags;
	
	rtos_spin_lock_irqsave(&list->lock, flags);
	__rtskb_queue_tail(list, newsk);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	
	if(list->event) rtos_event_signal(list->event);
		
}

static inline void __rtskb_queue_pri(struct rtskb_head *list, struct rtskb *newsk)
{
	struct rtskb *prev, *next;

	newsk->list = list;
	list->qlen++;
	
	for(next=list->next, prev=(struct rtskb*)list; next!=(struct rtskb*)list; prev=next, next=next->next) {
		if(next->pri > newsk->pri){
			newsk->next = next;
			newsk->prev = prev;
			next->prev = newsk;
			prev->next = newsk;
			break;
		}
	}
	if(next==(struct rtskb *)list) {
		newsk->next = next;
		newsk->prev = prev;
		next->prev = newsk;
		prev->next = newsk;
	}
}

static inline void rtskb_queue_pri(struct rtskb_head *list, struct rtskb *newsk)
{
	unsigned long flags;
	
	rtos_spin_lock_irqsave(&list->lock, flags);
	__rtskb_queue_pri(list, newsk);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	
	if(list->event) rtos_event_signal(list->event);
}
	

/**
 *	__skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The head item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtskb *__rtskb_dequeue(struct rtskb_head *list)
{
	struct rtskb *next, *prev, *result;

	prev = (struct rtskb *) list;
	next = prev->next;
	result = NULL;
	if (next != prev) {
		result = next;
		next = next->next;
		list->qlen--;
		next->prev = prev;
		prev->next = next;
		result->next = NULL;
		result->prev = NULL;
		result->list = NULL;
	}
	return result;
}

/**
 *	skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The head item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtskb *rtskb_dequeue(struct rtskb_head *list)
{
	unsigned long flags;
	struct rtskb *result;
	rtos_spin_lock_irqsave(&list->lock, flags);
	result = __rtskb_dequeue(list);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	return result;
}

/*
 *	Insert a packet on a list.
 */

static inline void __rtskb_insert(struct rtskb *newsk,
	struct rtskb * prev, struct rtskb *next,
	struct rtskb_head * list)
{
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
	newsk->list = list;
	list->qlen++;
}

/**
 *	skb_insert	-	insert a buffer
 *	@old: buffer to insert before
 *	@newsk: buffer to insert
 *
 *	Place a packet before a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls
 *	A buffer cannot be placed on two lists at the same time.
 */

static inline void rtskb_insert(struct rtskb *old, struct rtskb *newsk)
{
	unsigned long flags;

	rtos_spin_lock_irqsave(&old->list->lock, flags);
	__rtskb_insert(newsk, old->prev, old, old->list);
	rtos_spin_unlock_irqrestore(&old->list->lock, flags);
}

/*
 *	Place a packet after a given packet in a list.
 */

static inline void __rtskb_append(struct rtskb *old, struct rtskb *newsk)
{
	__rtskb_insert(newsk, old, old->next, old->list);
}

/**
 *	skb_append	-	append a buffer
 *	@old: buffer to insert after
 *	@newsk: buffer to insert
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls.
 *	A buffer cannot be placed on two lists at the same time.
 */


static inline void rtskb_append(struct rtskb *old, struct rtskb *newsk)
{
	unsigned long flags;

	rtos_spin_lock_irqsave(&old->list->lock, flags);
	__rtskb_append(old, newsk);
	rtos_spin_unlock_irqrestore(&old->list->lock, flags);
}

/*
 * remove rtskb from list. _Must_ be called atomically, and with
 * the list known..
 */
 
static inline void __rtskb_unlink(struct rtskb *skb, struct rtskb_head *list)
{
	struct rtskb * next, * prev;

	list->qlen--;
	next = skb->next;
	prev = skb->prev;
	skb->next = NULL;
	skb->prev = NULL;
	skb->list = NULL;
	next->prev = prev;
	prev->next = next;
}

/**
 *	rtskb_unlink	-	remove a buffer from a list
 *	@skb: buffer to remove
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls
 *	
 *	Works even without knowing the list it is sitting on, which can be 
 *	handy at times. It also means that THE LIST MUST EXIST when you 
 *	unlink. Thus a list must have its contents unlinked before it is
 *	destroyed.
 */

static inline void rtskb_unlink(struct rtskb *skb)
{
	struct rtskb_head *list = skb->list;

	if(list) {
		unsigned long flags;

		rtos_spin_lock_irqsave(&list->lock, flags);
		if(skb->list == list)
			__rtskb_unlink(skb, skb->list);
		rtos_spin_unlock_irqrestore(&list->lock, flags);
	}
}

/* XXX: more streamlined implementation */

/**
 *	__rtskb_dequeue_tail - remove from the tail of the queue
 *	@list: list to dequeue from
 *
 *	Remove the tail of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The tail item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtskb *__rtskb_dequeue_tail(struct rtskb_head *list)
{
	struct rtskb *skb = rtskb_peek_tail(list); 
	if (skb)
		__rtskb_unlink(skb, list);
	return skb;
}

/**
 *	rtskb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The tail item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtskb *rtskb_dequeue_tail(struct rtskb_head *list)
{
	unsigned long flags;
	struct rtskb *result;

	rtos_spin_lock_irqsave(&list->lock, flags);
	result = __rtskb_dequeue_tail(list);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	return result;
}

#define rtskb_queue_walk(queue,skb) \
		for (skb = (queue)->next; \
			prefetch(skb->next), (skb != (struct rtskb *)(queue)); \
			skb = skb->next)

/***
 *  rtskb_head_purge - clean the queue
 *  @queue
 */
static inline void rtskb_head_purge(struct rtskb_head *queue)
{
    struct rtskb *skb;
    while ( (skb=rtskb_dequeue(queue))!=NULL )
        kfree_rtskb(skb);
}

static inline void rtskb_reserve(struct rtskb *skb, unsigned int len)
{
    skb->data+=len;
    skb->tail+=len;
}

static inline unsigned char *__rtskb_put(struct rtskb *skb, unsigned int len)
{
    unsigned char *tmp=skb->tail;

    skb->tail+=len;
    skb->len+=len;
    return tmp;
}

static inline unsigned char *rtskb_put(struct rtskb *skb, unsigned int len)
{
    unsigned char *tmp=skb->tail;

    skb->tail+=len;
    skb->len+=len;

    RTOS_ASSERT(skb->tail <= skb->end,
        rtskb_over_panic(skb, len, current_text_addr()););

    return tmp;
}

static inline unsigned char *__rtskb_push(struct rtskb *skb, unsigned int len)
{
    skb->data-=len;
    skb->len+=len;
    return skb->data;
}

static inline unsigned char *rtskb_push(struct rtskb *skb, unsigned int len)
{
    skb->data-=len;
    skb->len+=len;

    RTOS_ASSERT(skb->data >= skb->buf_start,
        rtskb_under_panic(skb, len, current_text_addr()););

    return skb->data;
}

static inline char *__rtskb_pull(struct rtskb *skb, unsigned int len)
{
    skb->len-=len;
    if (skb->len < 0)
        BUG();
    return skb->data+=len;
}

static inline unsigned char *rtskb_pull(struct rtskb *skb, unsigned int len)
{
    if (len > skb->len)
        return NULL;

    return __rtskb_pull(skb,len);
}

static inline void rtskb_trim(struct rtskb *skb, unsigned int len)
{
    if (skb->len>len) {
        skb->len = len;
        skb->tail = skb->data+len;
    }
}

/**
 * @ingroup rtskbuff
 * @anchor rtskb_fillin
 * this should be used in place of memcpy
 * @note the len must be in bytes.!!!!
 */
static inline unsigned char *rtskb_fillin(struct rtskb *skb, void *src, unsigned int len)
{
	unsigned char *dest;
	dest = rtskb_put(skb, len);
	memcpy(dest, src, len);
	return dest;
}

/**
 * @ingroup rtskbuff
 * @anchor rtskb_clean
 * to reset all the members of rtskb structure
 */
static inline void rtskb_clean(struct rtskb *skb)
{
	/*! reset the data buffer */
	//~ memset(skb->buf_start, 0, SKB_DATA_ALIGN(RTSKB_SIZE));
	/*! reset the data pointers. */
	skb->head = skb->buf_start;
	skb->data = skb->buf_start;
	skb->tail = skb->buf_start;
	skb->end  = skb->buf_start + SKB_DATA_ALIGN(RTSKB_SIZE);
	/*! and the data length */
	skb->len = 0;
}
	
static inline struct rtskb *rtskb_padto(struct rtskb *rtskb, unsigned int len)
{
    RTOS_ASSERT(len <= (unsigned int)(rtskb->end + 1 - rtskb->data),
                 return NULL;);

    memset(rtskb->data + rtskb->len, 0, len - rtskb->len);

    return rtskb;
}

extern struct rtskb_pool global_pool;

extern unsigned int rtskb_pool_init(struct rtskb_pool *pool,
                                    unsigned int initial_size);
extern unsigned int rtskb_pool_init_rt(struct rtskb_pool *pool,
                                       unsigned int initial_size);
extern void __rtskb_pool_release(struct rtskb_pool *pool);
extern void __rtskb_pool_release_rt(struct rtskb_pool *pool);
	
#if 0
static inline int rtskb_is_nonlinear(const struct rtskb *skb)
{
	return skb->data_len;
}

static inline unsigned int rtskb_headlen(const struct rtskb *skb)
{
	return skb->len - skb->data_len;
}
#endif

#define rtskb_pool_release(pool)                            \
    do {                                                    \
        RTOS_ASSERT((&(pool)->queue)->qlen == (pool)->capc,             \
                     printk("pool: %p\n", (pool)););    \
        __rtskb_pool_release((pool));                       \
    } while (0)
#define rtskb_pool_release_rt(pool)                         \
    do {                                                    \
        RTOS_ASSERT((&(pool)->queue)->qlen == (pool)->capc,             \
                     printk("pool: %p\n", (pool)););    \
        __rtskb_pool_release_rt((pool));                    \
    } while (0)

extern unsigned int rtskb_pool_extend(struct rtskb_pool *pool,
                                      unsigned int add_rtskbs);
extern unsigned int rtskb_pool_extend_rt(struct rtskb_pool *pool,
                                         unsigned int add_rtskbs);
extern unsigned int rtskb_pool_shrink(struct rtskb_pool *pool,
                                      unsigned int rem_rtskbs);
extern unsigned int rtskb_pool_shrink_rt(struct rtskb_pool *pool,
                                         unsigned int rem_rtskbs);
extern int rtskb_acquire(struct rtskb *rtskb, struct rtskb_pool *comp_pool);

extern int rtskb_pools_init(void);
extern void rtskb_pools_release(void);


/*@}*/

#endif /*__KERNEL__ */

#endif /* _RTSKBUFF_H_ */
