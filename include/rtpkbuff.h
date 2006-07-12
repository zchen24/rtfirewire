/* rtfirewire/rtpkbuff/rtpkbuff.c
 * Generic Real-Time Memory Object Management Module
 * 	adapted from rtskb management in RTnet (Jan Kiszka <jan.kiszka@web.de>)
 *
 *  Copyright (C)  2005 Zhang Yuchen <y.zhang-4@student.utwente.nl>
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


/***

rtpkb Management - A Short Introduction
---------------------------------------

1. rtpkbs (Real-Time Socket Buffers)

A rtpkb consists of a management structure (struct rtpkb) and a fixed-sized
(RTSKB_SIZE) data buffer. It is used to store network packets on their way from
the API routines through the stack to the NICs or vice versa. rtpkbs are
allocated as one chunk of memory which contains both the managment structure
and the buffer memory itself.


2. rtpkb Queues

A rtpkb queue is described by struct rtpkb_queue. A queue can contain an
unlimited number of rtpkbs in an ordered way. A rtpkb can either be added to
the head (rtpkb_queue_head()) or the tail of a queue (rtpkb_queue_tail()). When
a rtpkb is removed from a queue (rtpkb_dequeue()), it is always taken from the
head. Queues are normally spin lock protected unless the __variants of the
queuing functions are used.


3. Prioritized rtpkb Queues

A prioritized queue contains a number of normal rtpkb queues within an array.
The array index of a sub-queue correspond to the priority of the rtpkbs within
this queue. For enqueuing a rtpkb (rtpkb_prio_queue_head()), its priority field
is evaluated and the rtpkb is then placed into the appropriate sub-queue. When
dequeuing a rtpkb, the first rtpkb of the first non-empty sub-queue with the
highest priority is returned. The current implementation supports 32 different
priority levels, the lowest if defined by QUEUE_MIN_PRIO, the highest by
QUEUE_MAX_PRIO.


4. rtpkb Pools

As rtpkbs must not be allocated by a normal memory manager during runtime,
preallocated rtpkbs are kept ready in several pools. Most packet producers
(Called device, e.g. NICs, sockets, etc.) have their own pools in order to be independent of the
load situation of other parts of the stack.

When a pool is created (rtpkb_pool_init()), the required rtpkbs are allocated
from a Linux slab cache. Pools can be extended (rtpkb_pool_extend()) or
shrinked (rtpkb_pool_shrink()) during runtime. When shutting down the
program/module, every pool has to be released (rtpkb_pool_release()). All these
commands demand to be executed within a non real-time context.

To support real-time pool manipulation, a tunable number of rtpkbs can be
preallocated in a dedicated pool. When every a real-time-safe variant of the
commands mentioned above is used (postfix: _rt), rtpkbs are taken from or
returned to that real-time pool. Note that real-time and non real-time commands
must not be mixed up when manipulating a pool.

Pools are organized as normal rtpkb queues (struct rtpkb_queue). When a rtpkb
is allocated (alloc_rtpkb()), it is actually dequeued from the pool's queue.
When freeing a rtpkb (kfree_rtpkb()), the rtpkb is enqueued to its owning pool.
rtpkbs can be exchanged between pools (rtpkb_acquire()). In this case, the
passed rtpkb switches over to from its owning pool to a given pool, but only if
this pool can pass an empty rtpkb from its own queue back.


5. rtpkb Chains

To ease the defragmentation of larger object e.g. network packets, several rtpkbs can form a
chain. For these purposes, the first rtpkb (and only the first!) provides a
pointer to the last rtpkb in the chain. When enqueuing the first rtpkb of a
chain, the whole chain is automatically placed into the destined queue. But,
to dequeue a complete chain specialized calls are required (postfix: _chain).
While chains also get freed en bloc (kfree_rtpkb()) when passing the first
rtpkbs, it is not possible to allocate a chain from a pool (alloc_rtpkb()); a
newly allocated rtpkb is always reset to a "single rtpkb chain". Furthermore,
the acquisition of complete chains is NOT supported (rtpkb_acquire()).

**/

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
#include <rtdm/rtdm_driver.h>

#define RTPKB_ASSERT(expr, func) \
	if (!(expr))	\
	{ \
		rtdm_printk("Assertion failed! %s:%s:%d:%s\n", \
		__FILE__, __FUNCTION__, __LINE__, (#expr)); \
		func \
	}

/**
 * @addtogroup rtpkb
 *@{*/

struct rtpkb_base {
	/* really common elements for generic memory operation*/
	/* these two members must be first, to comply with rtpkb_queue*/
	struct rtpkb	* next;			/* Next buffer in list 				*/
	struct rtpkb	* prev;			/* Previous buffer in list 			*/
	struct rtpkb        *chain_end; 		/* marks the end of a rtpkb chain starting
								with this very rtpkb */

	struct rtpkb_queue * list;			/* List we are on now				*/
	struct rtpkb_pool * pool;			/* where we are from and should come back when things are done */

	unsigned char	*head;			/* Head of buffer 				*/
	unsigned char	*data;			/* Data head pointer				*/
	unsigned char	*tail;				/* Data tail pointer					*/
	unsigned char 	*end;			/* End of buffer					*/
	unsigned int	len;

	void 		(*destructor)(struct rtpkb *);	/* Destruct function		*/

	unsigned int priority;
};

struct rtpkb {
	/* really common elements for generic memory operation*/
	/* these two members must be first, to comply with rtpkb_queue*/
	struct rtpkb	* next;			/* Next buffer in list 				*/
	struct rtpkb	* prev;			/* Previous buffer in list 			*/
	struct rtpkb        *chain_end; 		/* marks the end of a rtpkb chain starting
								with this very rtpkb */

	struct rtpkb_queue * list;			/* List we are on now				*/
	struct rtpkb_pool * pool;			/* where we are from and should come back when things are done */

	unsigned char	*head;			/* Head of buffer 				*/
	unsigned char	*data;			/* Data head pointer				*/
	unsigned char	*tail;				/* Data tail pointer					*/
	unsigned char 	*end;			/* End of buffer					*/
	unsigned int	len;

	void 		(*destructor)(struct rtpkb *);	/* Destruct function		*/

	unsigned int priority;

	/*protocol-specific stuff goes here, size agreed among all exsiting protocols, cant be exceeded!!! */
	char		meta_stuff[256];
	
	struct rtpkb_pool	*comp_pool;			/* the compensating packet */
	struct rtpkb	*next_cap;		/* the next captured packet */
};

struct rtpkb_queue_base {
	/* These two members must be first. */
	struct rtpkb	* next;
	struct rtpkb	* prev;
		
	__u32		qlen;
	spinlock_t	lock;
};

struct rtpkb_queue {
	/* These two members must be first. */
	struct rtpkb	* next;
	struct rtpkb	* prev;
		
	__u32		qlen;
	spinlock_t	lock;
	
	struct rtpkb_pool	 *pool;
	
	unsigned char name[32];
};


struct rtpkb_pool {
	struct rtpkb_queue queue;
			
	struct list_head entry;
	/**
	 * when pool get released, it must be checked that
	 * capc==queun->qlen, otherwise some buffer leakage 
	 * happened.
	*/
	__u32		capc;
	
	unsigned char name[32];
};

#define QUEUE_MAX_PRIO          0
#define QUEUE_MIN_PRIO          31

struct rtpkb_prio_queue {
    unsigned char name[32];
    struct rtpkb_pool	 *pool;		
    spinlock_t     lock;
    unsigned long       usage;  /* bit array encoding non-empty sub-queues */
    struct rtpkb_queue_base  queue[QUEUE_MIN_PRIO+1];
};

#define RTSKB_PRIO_MASK         0x0000FFFF  /* bits  0..15: xmit prio    */
#define RTSKB_CHANNEL_MASK      0xFFFF0000  /* bits 16..31: xmit channel */
#define RTSKB_CHANNEL_SHIFT     16

/* default values for the module parameter */
#define DEFAULT_RTPKB_CACHE_SIZE    16      /* default number of cached rtpkbs for new pools */
#define DEFAULT_DEVICE_RTPKBS       16      /* default additional rtpkbs per network adapter */

#define ALIGN_RTPKB_STRUCT_LEN      SKB_DATA_ALIGN(sizeof(struct rtpkb))
#define RTPKB_SIZE                  SKB_DATA_ALIGN(4096) /*maximum buffer load */

extern unsigned int device_rtpkbs;      /* default number of rtpkb's in socket pools */

extern unsigned int rtpkb_pools;        /* current number of rtpkb pools      */
extern unsigned int rtpkb_pools_max;    /* maximum number of rtpkb pools      */
extern unsigned int rtpkb_amount;       /* current number of allocated rtpkbs */
extern unsigned int rtpkb_amount_max;   /* maximum number of allocated rtpkbs */

extern void rtpkb_over_panic(struct rtpkb *pkb, int len, void *here);
extern void rtpkb_under_panic(struct rtpkb *pkb, int len, void *here);

extern struct rtpkb *alloc_rtpkb(unsigned int size, struct rtpkb_pool *pool);
extern void kfree_rtpkb(struct rtpkb *pkb);

static inline void rtpkb_queue_init(struct rtpkb_queue *list)
{
	rtdm_lock_init(&list->lock);
	list->prev = (struct rtpkb *)list;
	list->next = (struct rtpkb *)list;
	list->qlen = 0;
}

/***
 *  rtpkb_prio_queue_init - initialize the prioritized queue
 *  @prioqueue
 */
static inline void rtpkb_prio_queue_init(struct rtpkb_prio_queue *prioqueue)
{
    int i;
    rtdm_lock_init(&prioqueue->lock);
    for(i=0; i<=QUEUE_MIN_PRIO; i++)
    {
	    rtpkb_queue_init((struct rtpkb_queue *)&prioqueue->queue[i]);
    }
}

/**
 *	rtpkb_queue_empty - check if a queue is empty
 *	@list: queue head
 *
 *	Returns true if the queue is empty, false otherwise.
 */
 
static inline int rtpkb_queue_empty(struct rtpkb_queue *list)
{
	return (list->next == (struct rtpkb *) list);
}

/***
 *  rtpkb_prio_queue_empty
 *  @queue
 */
static inline int rtpkb_prio_queue_empty(struct rtpkb_prio_queue *prioqueue)
{
    return (prioqueue->usage == 0);
}

/**
 *	rtpkb_peek
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
 
static inline struct rtpkb *rtpkb_peek(struct rtpkb_queue *list_)
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

static inline struct rtpkb *rtpkb_peek_tail(struct rtpkb_queue *list_)
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
 
static inline __u32 rtpkb_queue_len(struct rtpkb_queue *list_)
{
	return(list_->qlen);
}


/**
 *	__rtpkb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newpk: buffer to queue
 *
 *	Queue a buffer (or a chain of buffer) at the start of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 
static inline void __rtpkb_queue_head(struct rtpkb_queue *list, struct rtpkb *newpk)
{
	struct rtpkb *prev, *next;

	newpk->list = list;
	list->qlen++;
	prev = (struct rtpkb *)list;
	next = prev->next;
	newpk->chain_end->next = next;
	newpk->prev = prev;
	next->prev = newpk->chain_end;
	prev->next = newpk;
}


/**
 *	rtpkb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newpk: buffer to queue
 *
 *	Queue a buffer at the start of the list. This function takes the
 *	list lock and can be used safely with other locking &rtpkb functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	

static inline void rtpkb_queue_head(struct rtpkb_queue *list, struct rtpkb *newpk)
{
	unsigned long flags;

	rtdm_lock_get_irqsave(&list->lock, flags);
	__rtpkb_queue_head(list, newpk);
	rtdm_lock_put_irqrestore(&list->lock, flags);
	
}

/***
 *  __rtpkb_prio_queue_head - insert a buffer at the prioritized queue head
 *                            (w/o locks)
 *  @queue: queue to use
 *  @pkb: buffer to queue
 */
static inline void __rtpkb_prio_queue_head(struct rtpkb_prio_queue *prioqueue,
                                           struct rtpkb *pkb)
{
    unsigned int prio = pkb->priority & RTSKB_PRIO_MASK;

    RTPKB_ASSERT(prio <= 31, prio = 31;);

    __rtpkb_queue_head((struct rtpkb_queue *)&prioqueue->queue[prio], pkb);
    __set_bit(prio, &prioqueue->usage);
}

/***
 *  rtpkb_prio_queue_head - insert a buffer at the prioritized queue head
 *                          (lock protected)
 *  @queue: queue to use
 *  @pkb: buffer to queue
 */
static inline void rtpkb_prio_queue_head(struct rtpkb_prio_queue *prioqueue,
                                         struct rtpkb *pkb)
{
    unsigned long flags;

    rtdm_lock_get_irqsave(&prioqueue->lock, flags);
    __rtpkb_prio_queue_head(prioqueue, pkb);
    rtdm_lock_put_irqrestore(&prioqueue->lock, flags);
}


/**
 *	__rtpkb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newpk: buffer to queue
 *
 *	Queue a buffer (or a chain of buffer) at the end of a list. This function takes no locks
 *	and you must therefore hold required locks before calling it.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	
 

static inline void __rtpkb_queue_tail(struct rtpkb_queue *list, struct rtpkb *newpk)
{
	struct rtpkb *prev, *next;
		
	newpk->list = list;
	list->qlen++;
	next = (struct rtpkb *)list;
	prev = next->prev;
	newpk->chain_end->next = next;
	newpk->prev = prev;
	next->prev = newpk->chain_end;
	prev->next = newpk;
}

/**
 *	rtpkb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newpk: buffer to queue
 *
 *	Queue a buffer at the tail of the list. This function takes the
 *	list lock and can be used safely with other locking &rtpkb functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */	

static inline void rtpkb_queue_tail(struct rtpkb_queue *list, struct rtpkb *newpk)
{
	unsigned long flags;
	
	rtdm_lock_get_irqsave(&list->lock, flags);
	__rtpkb_queue_tail(list, newpk);
	rtdm_lock_put_irqrestore(&list->lock, flags);
	
}

/***
 *  __rtpkb_prio_queue_tail - insert a buffer at the prioritized queue tail
 *                            (w/o locks)
 *  @prioqueue: queue to use
 *  @pkb: buffer to queue
 */
static inline void __rtpkb_prio_queue_tail(struct rtpkb_prio_queue *prioqueue,
                                           struct rtpkb *pkb)
{
    unsigned int prio = pkb->priority & RTSKB_PRIO_MASK;

    RTPKB_ASSERT(prio <= 31, prio = 31;);

    __rtpkb_queue_tail((struct rtpkb_queue *)&prioqueue->queue[prio], pkb);
    __set_bit(prio, &prioqueue->usage);
}

/***
 *  rtpkb_prio_queue_tail - insert a buffer at the prioritized queue tail
 *                          (lock protected)
 *  @prioqueue: queue to use
 *  @pkb: buffer to queue
 */
static inline void rtpkb_prio_queue_tail(struct rtpkb_prio_queue *prioqueue,
                                         struct rtpkb *pkb)
{
    unsigned long flags;

    rtdm_lock_get_irqsave(&prioqueue->lock, flags);
    __rtpkb_prio_queue_tail(prioqueue, pkb);
    rtdm_lock_put_irqrestore(&prioqueue->lock, flags);
}

/**
 *	__pkb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. This function does not take any locks
 *	so must be used with appropriate locks held only. The head item is
 *	returned or %NULL if the list is empty.
 */

static inline struct rtpkb *__rtpkb_dequeue(struct rtpkb_queue *list)
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

static inline struct rtpkb *rtpkb_dequeue(struct rtpkb_queue *list)
{
	unsigned long flags;
	struct rtpkb *result;
	rtdm_lock_get_irqsave(&list->lock, flags);
	result = __rtpkb_dequeue(list);
	rtdm_lock_put_irqrestore(&list->lock, flags);
	return result;
}

/***
 *  __rtpkb_prio_dequeue - remove from the head of the prioritized queue
 *                         (w/o locks)
 *  @prioqueue: queue to remove from
 */
static inline struct rtpkb *
    __rtpkb_prio_dequeue(struct rtpkb_prio_queue *prioqueue)
{
    int prio;
    struct rtpkb *result = NULL;
    struct rtpkb_queue *sub_queue;

    if (prioqueue->usage) {
        prio      = ffz(~prioqueue->usage);
        sub_queue = (struct rtpkb_queue *)&prioqueue->queue[prio];
        result    = __rtpkb_dequeue(sub_queue);
        if (rtpkb_queue_empty(sub_queue))
            __change_bit(prio, &prioqueue->usage);
    }

    return result;
}

/***
 *  rtpkb_prio_dequeue - remove from the head of the prioritized queue
 *                       (lock protected)
 *  @prioqueue: queue to remove from
 */
static inline struct rtpkb *
    rtpkb_prio_dequeue(struct rtpkb_prio_queue *prioqueue)
{
    unsigned long flags;
    struct rtpkb *result;

    rtdm_lock_get_irqsave(&prioqueue->lock, flags);
    result = __rtpkb_prio_dequeue(prioqueue);
    rtdm_lock_put_irqrestore(&prioqueue->lock, flags);

    return result;
}


/***
 *  __rtpkb_dequeue_chain - remove a chain from the head of the queue
 *                          (w/o locks)
 *  @queue: queue to remove from
 */
static inline struct rtpkb *__rtpkb_dequeue_chain(struct rtpkb_queue *queue)
{
    struct rtpkb *result;
    struct rtpkb *chain_end;

    if ((result = queue->next) != queue->prev) {
        chain_end = result->chain_end;
        queue->next = chain_end->next;
	chain_end->next->prev = (struct rtpkb *)queue;
        chain_end->next = NULL;
    }

    return result;
}

/***
 *  rtpkb_dequeue_chain - remove a chain from the head of the queue
 *                        (lock protected)
 *  @queue: queue to remove from
 */
static inline struct rtpkb *rtpkb_dequeue_chain(struct rtpkb_queue *queue)
{
    unsigned long flags;
    struct rtpkb *result;

    rtdm_lock_get_irqsave(&queue->lock, flags);
    result = __rtpkb_dequeue_chain(queue);
    rtdm_lock_put_irqrestore(&queue->lock, flags);

    return result;
}

/***
 *  rtpkb_prio_dequeue_chain - remove a chain from the head of the
 *                             prioritized queue
 *  @prioqueue: queue to remove from
 */
static inline
    struct rtpkb *rtpkb_prio_dequeue_chain(struct rtpkb_prio_queue *prioqueue)
{
    unsigned long flags;
    int prio;
    struct rtpkb *result = NULL;
    struct rtpkb_queue *sub_queue;

    rtdm_lock_get_irqsave(&prioqueue->lock, flags);
    if (prioqueue->usage) {
        prio      = ffz(~prioqueue->usage);
        sub_queue = (struct rtpkb_queue *)&prioqueue->queue[prio];
        result    = __rtpkb_dequeue_chain(sub_queue);
        if (rtpkb_queue_empty(sub_queue))
            __change_bit(prio, &prioqueue->usage);
    }
    rtdm_lock_put_irqrestore(&prioqueue->lock, flags);

    return result;
}

/*
 *	Insert a packet on a list.
 */

static inline void __rtpkb_insert(struct rtpkb *newpk,
	struct rtpkb *prev, struct rtpkb *next,
	struct rtpkb_queue *list)
{
	newpk->next = next;
	newpk->prev = prev;
	next->prev = newpk;
	prev->next = newpk;
	newpk->list = list;
	list->qlen++;
}

/**
 *	pkb_insert	-	insert a buffer
 *	@old: buffer to insert before
 *	@newpk: buffer to insert
 *
 *	Place a packet before a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls
 *	A buffer cannot be placed on two lists at the same time.
 */

static inline void rtpkb_insert(struct rtpkb *old, struct rtpkb *newpk)
{
	unsigned long flags;

	rtdm_lock_get_irqsave(&old->list->lock, flags);
	__rtpkb_insert(newpk, old->prev, old, old->list);
	rtdm_lock_put_irqrestore(&old->list->lock, flags);
}

/*
 *	Place a packet after a given packet in a list.
 */

static inline void __rtpkb_append(struct rtpkb *old, struct rtpkb *newpk)
{
	__rtpkb_insert(newpk, old,  old->next, old->list);
}

/**
 *	pkb_append	-	append a buffer
 *	@old: buffer to insert after
 *	@newpk: buffer to insert
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls.
 *	A buffer cannot be placed on two lists at the same time.
 */


static inline void rtpkb_append(struct rtpkb *old, struct rtpkb *newpk)
{
	unsigned long flags;

	rtdm_lock_get_irqsave(&old->list->lock, flags);
	__rtpkb_append(old, newpk);
	rtdm_lock_put_irqrestore(&old->list->lock, flags);
}

/*
 * remove rtpkb from list. _Must_ be called atomically, and with
 * the list known..
 */
 
static inline void __rtpkb_unlink(struct rtpkb *pkb, struct rtpkb_queue *list)
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
	struct rtpkb_queue *list = pkb->list;

	if(list) {
		unsigned long flags;

		rtdm_lock_get_irqsave(&list->lock, flags);
		if(pkb->list == list)
			__rtpkb_unlink(pkb, pkb->list);
		rtdm_lock_put_irqrestore(&list->lock, flags);
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

static inline struct rtpkb *__rtpkb_dequeue_tail(struct rtpkb_queue *list)
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

static inline struct rtpkb *rtpkb_dequeue_tail(struct rtpkb_queue *list)
{
	unsigned long flags;
	struct rtpkb *result;

	rtdm_lock_get_irqsave(&list->lock, flags);
	result = __rtpkb_dequeue_tail(list);
	rtdm_lock_put_irqrestore(&list->lock, flags);
	return result;
}


#define rtpkb_queue_walk(queue,pkb) \
		for (pkb = (queue)->next; \
			(pkb != (struct rtpkb *)(queue)); \
			pkb = pkb->next)

/***
 *  rtpkb_head_purge - clean the queue
 *  @queue
 */
static inline void rtpkb_head_purge(struct rtpkb_queue *queue)
{
    struct rtpkb *pkb;
    while ( (pkb=rtpkb_dequeue(queue))!=NULL )
        kfree_rtpkb(pkb);
}

static inline void rtpkb_reserve(struct rtpkb *pkb, unsigned int len)
{
    RTPKB_ASSERT(pkb->tail+len <= pkb->end, 
			rtpkb_over_panic(pkb, len, current_text_addr()););
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

    RTPKB_ASSERT(pkb->tail <= pkb->end,
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

    RTPKB_ASSERT(pkb->data >= pkb->head,
        rtpkb_under_panic(pkb, len, current_text_addr()););

    return pkb->data;
}

static inline char *__rtpkb_pull(struct rtpkb *pkb, unsigned int len)
{
    pkb->len-=len;
    RTPKB_ASSERT(pkb->len<0,
        rtpkb_under_panic(pkb, len, current_text_addr()););
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
	//~ memset(pkb->head, 0, PKB_DATA_ALIGN(RTPKB_SIZE));
	/*! reset the data pointers. */
	pkb->head = (u8 *)pkb + ALIGN_RTPKB_STRUCT_LEN;
	pkb->data = pkb->head;
	pkb->tail = pkb->head;
	pkb->end  = pkb->head + RTPKB_SIZE;
	/*! and the data length */
	pkb->len = 0;
	pkb->chain_end = pkb;
}
	
static inline struct rtpkb *rtpkb_padto(struct rtpkb *rtpkb, unsigned int len)
{
    RTPKB_ASSERT(len <= (unsigned int)(rtpkb->end + 1 - rtpkb->data),
                 return NULL;);

    memset(rtpkb->data + rtpkb->len, 0, len - rtpkb->len);

    return rtpkb;
}

extern unsigned int rtpkb_pool_init(struct rtpkb_pool *pool,
                                    unsigned int initial_size);
extern unsigned int rtpkb_pool_init_rt(struct rtpkb_pool *pool,
                                       unsigned int initial_size);
extern void __rtpkb_pool_release(struct rtpkb_pool *pool);
extern void __rtpkb_pool_release_rt(struct rtpkb_pool *pool);

static inline unsigned int rtpkb_headlen(const struct rtpkb *pkb)
{
	return pkb->len;
}

#define rtpkb_pool_release(pool)                            \
    do {                                                    \
        RTPKB_ASSERT((&(pool)->queue)->qlen == (pool)->capc,             \
                     rtdm_printk("pool: %s\n", ((pool)->name)););    \
        __rtpkb_pool_release((pool));                       \
    } while (0)
#define rtpkb_pool_release_rt(pool)                         \
    do {                                                    \
        RTPKB_ASSERT((&(pool)->queue)->qlen == (pool)->capc,             \
                     rtdm_printk("pool: %s\n", ((pool)->name)););    \
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

extern void rtpkbuff_Caphandler(struct rtpkb *);
extern void rtpkbuff_SetCap(void (*)(struct rtpkb *),struct rtpkb_pool *);
extern void rtpkbuff_UnsetCap(void);
/*@}*/

#endif /*__KERNEL__ */

#endif /* _RTPKBUFF_H_ */
