/**
 * @ingroup rtpkb
 * @file
 *
 * data structure and interfaces of rtpkb module
 */
 
#ifndef __RTPKBUFF_H_
#define __RTPKBUFF_H_

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <rt1394_sys.h>

/**
 * @addtogroup rtpkb
 *@{*/
struct rtpkb_head {
	/* These two members must be first. */
	struct rtpkb	* next;
	struct rtpkb	* prev;

	__u32		qlen;
	spinlock_t	lock;
	
	rtos_event_t 	*event; //this is needed when request is queued for server. 
	struct rtpkb_pool	 *pool;
	
	unsigned char name[32];
};

struct rtpkb_pool {
	struct rtpkb_head queue;
			
	struct list_head entry;
	/**
	 * when pool get released, it must be checked that
	 * capc==queun->qlen, otherwise some buffer leakage 
	 * happened.
	*/
	__u32		capc;
	
	unsigned char name[32];
};

struct rtpkb {
	/* These two members must be first. */
	struct rtpkb	* next;			/* Next buffer in list 				*/
	struct rtpkb	* prev;			/* Previous buffer in list 			*/

	struct rtpkb_head * list;		/* List we are on now				*/
	struct rtpkb_pool * pool;		/* where we are from and should come back when things are done */

	unsigned char	*head;			/* Head of buffer 				*/
	unsigned char	*data;			/* Data head pointer				*/
	unsigned char	*tail;			/* Tail pointer					*/
	unsigned char 	*end;			/* End pointer					*/
	unsigned int	len;

	void 		(*destructor)(struct rtpkb *);	/* Destruct function		*/
	
	unsigned char *buf_start;
	
	unsigned char *dev_name;
	
	unsigned int pri;
};

/* default values for the module parameter */
#define DEFAULT_RTPKB_CACHE_SIZE    16      /* default number of cached rtpkbs for new pools */
#define DEFAULT_GLOBAL_RTPKBS       16       /* default number of rtpkb's in global pool */
#define DEFAULT_DEVICE_RTPKBS       16      /* default additional rtpkbs per network adapter */
#define DEFAULT_SOCKET_RTPKBS       16      /* default number of rtpkb's in socket pools */

#define ALIGN_RTPKB_STRUCT_LEN      SKB_DATA_ALIGN(sizeof(struct rtpkb))
#define RTPKB_SIZE                  1544 /*maximum buffer load */

extern unsigned int socket_rtpkbs;      /* default number of rtpkb's in socket pools */

extern unsigned int rtpkb_pools;        /* current number of rtpkb pools      */
extern unsigned int rtpkb_pools_max;    /* maximum number of rtpkb pools      */
extern unsigned int rtpkb_amount;       /* current number of allocated rtpkbs */
extern unsigned int rtpkb_amount_max;   /* maximum number of allocated rtpkbs */

extern void rtpkb_over_panic(struct rtpkb *pkb, int len, void *here);
extern void rtpkb_under_panic(struct rtpkb *pkb, int len, void *here);

extern struct rtpkb *alloc_rtpkb(unsigned int size, struct rtpkb_pool *pool);
#define dev_alloc_rtpkb(len, pool)  alloc_rtpkb(len, pool)

extern void kfree_rtpkb(struct rtpkb *pkb);
#define dev_kfree_rtpkb(a)  kfree_rtpkb(a)

/**
 *	rtpkb_queue_empty - check if a queue is empty
 *	@list: queue head
 *
 *	Returns true if the queue is empty, false otherwise.
 */
 
static inline int rtpkb_queue_empty(struct rtpkb_head *list)
{
	return (list->next == (struct rtpkb *) list);
}

/**
 *	pkb_peek
 *	@list_: list to peek at
 *
 *	Peek an &rtpkb. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the head element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */
 
static inline struct rtpkb *rtpkb_peek(struct rtpkb_head *list_)
{
	struct rtpkb *list = ((struct rtpkb *)list_)->next;
	if (list == (struct rtpkb *)list_)
		list = NULL;
	return list;
}

/**
 *	rtpkb_peek_tail
 *	@list_: list to peek at
 *
 *	Peek an &rtpkb. Unlike most other operations you _MUST_
 *	be careful with this one. A peek leaves the buffer on the
 *	list and someone else may run off with it. You must hold
 *	the appropriate locks or have a private queue to do this.
 *
 *	Returns %NULL for an empty list or a pointer to the tail element.
 *	The reference count is not incremented and the reference is therefore
 *	volatile. Use with caution.
 */

static inline struct rtpkb *rtpkb_peek_tail(struct rtpkb_head *list_)
{
	struct rtpkb *list = ((struct rtpkb *)list_)->prev;
	if (list == (struct rtpkb *)list_)
		list = NULL;
	return list;
}

/**
 *	rtpkb_queue_len	- get queue length
 *	@list_: list to measure
 *
 *	Return the length of an &rtpkb queue. 
 */
 
static inline __u32 rtpkb_queue_len(struct rtpkb_head *list_)
{
	return(list_->qlen);
}

static inline void rtpkb_queue_head_init(struct rtpkb_head *list)
{
	rtos_spin_lock_init(&list->lock);
	list->prev = (struct rtpkb *)list;
	list->next = (struct rtpkb *)list;
	list->qlen = 0;
}

/*
 *	Insert an rtpkb at the start of a list.
 *
 *	The "__pkb_xxxx()" functions are the non-atomic ones that
 *	can only be called with interrupts disabled.
 */

/**
 *	__rtpkb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 
static inline void __rtpkb_queue_head(struct rtpkb_head *list, struct rtpkb *newsk)
{
	struct rtpkb *prev, *next;

	newsk->list = list;
	list->qlen++;
	prev = (struct rtpkb *)list;
	next = prev->next;
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
}


/**
 *	rtpkb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of the list. This function takes the
 *	list lock and can be used safely with other locking &rtpkb functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	

static inline void rtpkb_queue_head(struct rtpkb_head *list, struct rtpkb *newsk)
{
	unsigned long flags;

	rtos_spin_lock_irqsave(&list->lock, flags);
	__rtpkb_queue_head(list, newsk);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	
	if(list->event) rtos_event_signal(list->event);
}

/**
 *	__rtpkb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the end of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 

static inline void __rtpkb_queue_tail(struct rtpkb_head *list, struct rtpkb *newsk)
{
	struct rtpkb *prev, *next;
		
	newsk->list = list;
	list->qlen++;
	next = (struct rtpkb *)list;
	prev = next->prev;
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
}

/**
 *	rtpkb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the tail of the list. This function takes the
 *	list lock and can be used safely with other locking &rtpkb functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	

static inline void rtpkb_queue_tail(struct rtpkb_head *list, struct rtpkb *newsk)
{
	unsigned long flags;
	
	rtos_spin_lock_irqsave(&list->lock, flags);
	__rtpkb_queue_tail(list, newsk);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	
	if(list->event) rtos_event_signal(list->event);
		
}

static inline void __rtpkb_queue_pri(struct rtpkb_head *list, struct rtpkb *newsk)
{
	struct rtpkb *prev, *next;

	newsk->list = list;
	list->qlen++;
	
	for(next=list->next, prev=(struct rtpkb*)list; next!=(struct rtpkb*)list; prev=next, next=next->next) {
		if(next->pri > newsk->pri){
			newsk->next = next;
			newsk->prev = prev;
			next->prev = newsk;
			prev->next = newsk;
			break;
		}
	}
	if(next==(struct rtpkb *)list) {
		newsk->next = next;
		newsk->prev = prev;
		next->prev = newsk;
		prev->next = newsk;
	}
}

static inline void rtpkb_queue_pri(struct rtpkb_head *list, struct rtpkb *newsk)
{
	unsigned long flags;
	
	rtos_spin_lock_irqsave(&list->lock, flags);
	__rtpkb_queue_pri(list, newsk);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	
	if(list->event) rtos_event_signal(list->event);
}
	

/**
 *	__pkb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The head item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtpkb *__rtpkb_dequeue(struct rtpkb_head *list)
{
	struct rtpkb *next, *prev, *result;

	prev = (struct rtpkb *) list;
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
 *	pkb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The head item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtpkb *rtpkb_dequeue(struct rtpkb_head *list)
{
	unsigned long flags;
	struct rtpkb *result;
	rtos_spin_lock_irqsave(&list->lock, flags);
	result = __rtpkb_dequeue(list);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	return result;
}

/*
 *	Insert a packet on a list.
 */

static inline void __rtpkb_insert(struct rtpkb *newsk,
	struct rtpkb * prev, struct rtpkb *next,
	struct rtpkb_head * list)
{
	newsk->next = next;
	newsk->prev = prev;
	next->prev = newsk;
	prev->next = newsk;
	newsk->list = list;
	list->qlen++;
}

/**
 *	pkb_insert	-	insert a buffer
 *	@old: buffer to insert before
 *	@newsk: buffer to insert
 *
 *	Place a packet before a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls
 *	A buffer cannot be placed on two lists at the same time.
 */

static inline void rtpkb_insert(struct rtpkb *old, struct rtpkb *newsk)
{
	unsigned long flags;

	rtos_spin_lock_irqsave(&old->list->lock, flags);
	__rtpkb_insert(newsk, old->prev, old, old->list);
	rtos_spin_unlock_irqrestore(&old->list->lock, flags);
}

/*
 *	Place a packet after a given packet in a list.
 */

static inline void __rtpkb_append(struct rtpkb *old, struct rtpkb *newsk)
{
	__rtpkb_insert(newsk, old, old->next, old->list);
}

/**
 *	pkb_append	-	append a buffer
 *	@old: buffer to insert after
 *	@newsk: buffer to insert
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls.
 *	A buffer cannot be placed on two lists at the same time.
 */


static inline void rtpkb_append(struct rtpkb *old, struct rtpkb *newsk)
{
	unsigned long flags;

	rtos_spin_lock_irqsave(&old->list->lock, flags);
	__rtpkb_append(old, newsk);
	rtos_spin_unlock_irqrestore(&old->list->lock, flags);
}

/*
 * remove rtpkb from list. _Must_ be called atomically, and with
 * the list known..
 */
 
static inline void __rtpkb_unlink(struct rtpkb *pkb, struct rtpkb_head *list)
{
	struct rtpkb * next, * prev;

	list->qlen--;
	next = pkb->next;
	prev = pkb->prev;
	pkb->next = NULL;
	pkb->prev = NULL;
	pkb->list = NULL;
	next->prev = prev;
	prev->next = next;
}

/**
 *	rtpkb_unlink	-	remove a buffer from a list
 *	@pkb: buffer to remove
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls
 *	
 *	Works even without knowing the list it is sitting on, which can be 
 *	handy at times. It also means that THE LIST MUST EXIST when you 
 *	unlink. Thus a list must have its contents unlinked before it is
 *	destroyed.
 */

static inline void rtpkb_unlink(struct rtpkb *pkb)
{
	struct rtpkb_head *list = pkb->list;

	if(list) {
		unsigned long flags;

		rtos_spin_lock_irqsave(&list->lock, flags);
		if(pkb->list == list)
			__rtpkb_unlink(pkb, pkb->list);
		rtos_spin_unlock_irqrestore(&list->lock, flags);
	}
}

/* XXX: more streamlined implementation */

/**
 *	__rtpkb_dequeue_tail - remove from the tail of the queue
 *	@list: list to dequeue from
 *
 *	Remove the tail of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The tail item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtpkb *__rtpkb_dequeue_tail(struct rtpkb_head *list)
{
	struct rtpkb *pkb = rtpkb_peek_tail(list); 
	if (pkb)
		__rtpkb_unlink(pkb, list);
	return pkb;
}

/**
 *	rtpkb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The tail item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtpkb *rtpkb_dequeue_tail(struct rtpkb_head *list)
{
	unsigned long flags;
	struct rtpkb *result;

	rtos_spin_lock_irqsave(&list->lock, flags);
	result = __rtpkb_dequeue_tail(list);
	rtos_spin_unlock_irqrestore(&list->lock, flags);
	return result;
}

#define rtpkb_queue_walk(queue,pkb) \
		for (pkb = (queue)->next; \
			prefetch(pkb->next), (pkb != (struct rtpkb *)(queue)); \
			pkb = pkb->next)

/***
 *  rtpkb_head_purge - clean the queue
 *  @queue
 */
static inline void rtpkb_head_purge(struct rtpkb_head *queue)
{
    struct rtpkb *pkb;
    while ( (pkb=rtpkb_dequeue(queue))!=NULL )
        kfree_rtpkb(pkb);
}

static inline void rtpkb_reserve(struct rtpkb *pkb, unsigned int len)
{
    pkb->data+=len;
    pkb->tail+=len;
}

static inline unsigned char *__rtpkb_put(struct rtpkb *pkb, unsigned int len)
{
    unsigned char *tmp=pkb->tail;

    pkb->tail+=len;
    pkb->len+=len;
    return tmp;
}

static inline unsigned char *rtpkb_put(struct rtpkb *pkb, unsigned int len)
{
    unsigned char *tmp=pkb->tail;

    pkb->tail+=len;
    pkb->len+=len;

    RTOS_ASSERT(pkb->tail <= pkb->end,
        rtpkb_over_panic(pkb, len, current_text_addr()););

    return tmp;
}

static inline unsigned char *__rtpkb_push(struct rtpkb *pkb, unsigned int len)
{
    pkb->data-=len;
    pkb->len+=len;
    return pkb->data;
}

static inline unsigned char *rtpkb_push(struct rtpkb *pkb, unsigned int len)
{
    pkb->data-=len;
    pkb->len+=len;

    RTOS_ASSERT(pkb->data >= pkb->buf_start,
        rtpkb_under_panic(pkb, len, current_text_addr()););

    return pkb->data;
}

static inline char *__rtpkb_pull(struct rtpkb *pkb, unsigned int len)
{
    pkb->len-=len;
    if (pkb->len < 0)
        BUG();
    return pkb->data+=len;
}

static inline unsigned char *rtpkb_pull(struct rtpkb *pkb, unsigned int len)
{
    if (len > pkb->len)
        return NULL;

    return __rtpkb_pull(pkb,len);
}

static inline void rtpkb_trim(struct rtpkb *pkb, unsigned int len)
{
    if (pkb->len>len) {
        pkb->len = len;
        pkb->tail = pkb->data+len;
    }
}

/**
 * @ingroup rtpkbuff
 * @anchor rtpkb_fillin
 * this should be used in place of memcpy
 * @note the len must be in bytes.!!!!
 */
static inline unsigned char *rtpkb_fillin(struct rtpkb *pkb, void *src, unsigned int len)
{
	unsigned char *dest;
	dest = rtpkb_put(pkb, len);
	memcpy(dest, src, len);
	return dest;
}

/**
 * @ingroup rtpkbuff
 * @anchor rtpkb_clean
 * to reset all the members of rtpkb structure
 */
static inline void rtpkb_clean(struct rtpkb *pkb)
{
	/*! reset the data buffer */
	//~ memset(pkb->buf_start, 0, PKB_DATA_ALIGN(RTPKB_SIZE));
	/*! reset the data pointers. */
	pkb->head = pkb->buf_start;
	pkb->data = pkb->buf_start;
	pkb->tail = pkb->buf_start;
	pkb->end  = pkb->buf_start + SKB_DATA_ALIGN(RTPKB_SIZE);
	/*! and the data length */
	pkb->len = 0;
}
	
static inline struct rtpkb *rtpkb_padto(struct rtpkb *rtpkb, unsigned int len)
{
    RTOS_ASSERT(len <= (unsigned int)(rtpkb->end + 1 - rtpkb->data),
                 return NULL;);

    memset(rtpkb->data + rtpkb->len, 0, len - rtpkb->len);

    return rtpkb;
}

extern struct rtpkb_pool global_pool;

extern unsigned int rtpkb_pool_init(struct rtpkb_pool *pool,
                                    unsigned int initial_size);
extern unsigned int rtpkb_pool_init_rt(struct rtpkb_pool *pool,
                                       unsigned int initial_size);
extern void __rtpkb_pool_release(struct rtpkb_pool *pool);
extern void __rtpkb_pool_release_rt(struct rtpkb_pool *pool);
	
#if 0
static inline int rtpkb_is_nonlinear(const struct rtpkb *pkb)
{
	return pkb->data_len;
}

static inline unsigned int rtpkb_headlen(const struct rtpkb *pkb)
{
	return pkb->len - pkb->data_len;
}
#endif

#define rtpkb_pool_release(pool)                            \
    do {                                                    \
        RTOS_ASSERT((&(pool)->queue)->qlen == (pool)->capc,             \
                     printk("pool: %p\n", (pool)););    \
        __rtpkb_pool_release((pool));                       \
    } while (0)
#define rtpkb_pool_release_rt(pool)                         \
    do {                                                    \
        RTOS_ASSERT((&(pool)->queue)->qlen == (pool)->capc,             \
                     printk("pool: %p\n", (pool)););    \
        __rtpkb_pool_release_rt((pool));                    \
    } while (0)

extern unsigned int rtpkb_pool_extend(struct rtpkb_pool *pool,
                                      unsigned int add_rtpkbs);
extern unsigned int rtpkb_pool_extend_rt(struct rtpkb_pool *pool,
                                         unsigned int add_rtpkbs);
extern unsigned int rtpkb_pool_shrink(struct rtpkb_pool *pool,
                                      unsigned int rem_rtpkbs);
extern unsigned int rtpkb_pool_shrink_rt(struct rtpkb_pool *pool,
                                         unsigned int rem_rtpkbs);
extern int rtpkb_acquire(struct rtpkb *rtpkb, struct rtpkb_pool *comp_pool);

extern int rtpkb_pools_init(void);
extern void rtpkb_pools_release(void);


/*@}*/

#endif /*__KERNEL__ */

#endif /* _RTPKBUFF_H_ */
