/* rtfirewire/include/rtos_primitives.h
 * Header file for primitives from underlying rtos. 
 *
 *  Copyright (C) 2005 Zhang Yuchen
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
 
#ifndef __RTOS_PRIMITIVES_H_
#define __RTOS_PRIMITIVES_H_


#define RTOS_ASSERT(expr, func) \
	if (!(expr))	\
	{ \
		rtos_print("Assertion failed! %s:%s:%d:%s\n", \
		__FILE__, __FUNCTION__, __LINE__, (#expr)); \
		func \
	}
	
#define RTOS_SET_MODULE_OWNER(some_struct)	\
	do {(some_struct)->rt_owner = THIS_MODULE; } while (0)

typedef __u64 nanosecs_t; /*used for time calculations and I/O */

#define RTOS_TIME_LIMIT	0x7FFFFFFFFFFFFFFFLL //copied from rtai_hal.h 

#if defined(CONFIG_RTAI_24) || defined(CONFIG_RTAI_30) || \
    defined(CONFIG_RTAI_31) || defined(CONFIG_RTAI_32)

#include <linux/spinlock.h>

#ifdef CONFIG_RTAI_24
# define INTERFACE_TO_LINUX	/* makes RT_LINUX_PRIORITY visible */
#endif

#include <rtai.h>
#include <rtai_sched.h>
#include <asm/rtai_sched.h>
#include <rtai_schedcore.h>


/* RTAI-3.x only headers */
#ifdef HAVE_RTAI_MALLOC_H
# include <rtai_malloc.h>
#endif
#ifdef HAVE_RTAI_SEM_H
# include <rtai_sem.h>
#endif
#include <rtai_fifos.h>



/* basic types */
/**
 * @addtogroup 
 *@{*/
typedef spinlock_t rtos_spinlock_t;   /* spin locks with hard IRQ locks */
typedef RT_TASK    rtos_task_t;       /* hard real-time task */
typedef SEM        rtos_event_t;      /* to signal events (non-storing) */
typedef SEM        rtos_event_sem_t;  /* to signal events (storing) */
typedef SEM        rtos_res_lock_t;   /* resource lock with prio inheritance*/
typedef int        rtos_nrt_signal_t; /* async signal to non-RT world */
typedef struct {
    int minor;
} rtos_fifo_t;                        /* fifo descriptor */
typedef int        rtos_irq_t;        /* handle to requested IRQ */
typedef void       (*rtos_irq_handler_t)(unsigned int irq, void *arg);

#define ALIGN_RTOS_TASK         16  /* RT_TASK requires 16-bytes alignment */



/* print output messages */
#define rtos_print              rt_printk



/* time handling */
static inline RTIME rtos_get_time()
{
   return rt_get_time();
}


static inline RTIME rtos_nanosecs_to_time(nanosecs_t nano)
{
     return nano2count(nano);
}

static inline nanosecs_t rtos_time_to_nanosecs(RTIME time)
{
    return (nanosecs_t)count2nano(time);
}


/* real-time spin locks */
#define RTOS_SPIN_LOCK_UNLOCKED     SPIN_LOCK_UNLOCKED  /* init */
#define rtos_spin_lock_init(lock)   spin_lock_init(lock)

#define rtos_spin_lock(lock)        rt_spin_lock(lock)
#define rtos_spin_unlock(lock)      rt_spin_unlock(lock)

#define rtos_spin_lock_irqsave(lock, flags) \
    flags = rt_spin_lock_irqsave(lock)
#define rtos_spin_unlock_irqrestore(lock, flags) \
    rt_spin_unlock_irqrestore(flags, lock)

#define rtos_local_irqsave(flags)   hard_save_flags_and_cli(flags)
#define rtos_local_irqrestore(flags) \
    hard_restore_flags(flags)

#define rtos_saveflags(flags)       hard_save_flags(flags)



/* RT-tasks */
#ifdef CONFIG_RTAI_24
#define RTOS_HIGHEST_RT_PRIORITY    RT_HIGHEST_PRIORITY
#define RTOS_LOWEST_RT_PRIORITY     RT_LOWEST_PRIORITY
#define RTOS_LINUX_PRIORITY         RT_LINUX_PRIORITY
#else
#define RTOS_HIGHEST_RT_PRIORITY    RT_SCHED_HIGHEST_PRIORITY
#define RTOS_LOWEST_RT_PRIORITY     RT_SCHED_LOWEST_PRIORITY
#define RTOS_LINUX_PRIORITY         RT_SCHED_LINUX_PRIORITY
#endif
#define RTOS_RAISE_PRIORITY         (-1)
#define RTOS_LOWER_PRIORITY         (+1)


static inline int rtos_task_init(rtos_task_t *task, void (*task_proc)(int),
                                 int arg, int stack_size, int priority, int use_fpu)
{
	int ret;
	
	ret = rt_task_init(task, task_proc, arg, stack_size, priority, use_fpu, NULL);
	if(ret < 0)
		return ret;
	
	ret = rt_task_resume(task);
	if(ret < 0)
		rt_task_delete(task);
	
	return ret;
}
				 
static inline int rtos_task_init_fast(rtos_task_t *task, void (*task_proc)(int),
                                 int arg, int priority)
{
    int ret;

    ret = rt_task_init(task, task_proc, arg, 4096, priority, 0, NULL);
    if (ret < 0)
        return ret;

    ret = rt_task_resume(task);
    if (ret < 0)
        rt_task_delete(task);

    return ret;
}

static inline int rtos_task_init_periodic(rtos_task_t *task,
                                          void (*task_proc)(int), int arg,
                                          int priority, rtos_time_t *period)
{
    int ret;

    ret = rt_task_init(task, task_proc, arg, 4096, priority, 0, NULL);
    if (ret < 0)
        return ret;

    ret = rt_task_make_periodic(task, rt_get_time(), period->val);
    if (ret < 0)
        rt_task_delete(task);

    return ret;
}

static inline int rtos_task_init_suspended(rtos_task_t *task,
                                           void (*task_proc)(int),
                                           int arg, int priority)
{
    return rt_task_init(task, task_proc, arg, 4096, priority, 0, NULL);
}

static inline int rtos_task_resume(rtos_task_t *task)
{
    return rt_task_resume(task);
}

static inline int rtos_task_suspend(rtos_task_t *task)
{
    return rt_task_suspend(task);
}

static inline int rtos_task_wakeup(rtos_task_t *task)
{
    return rt_task_wakeup_sleeping(task);
}

static inline void rtos_task_delete(rtos_task_t *task)
{
    rt_task_delete(task);
}

static inline int rtos_task_set_priority(rtos_task_t *task, int priority)
{
    return rt_change_prio(task, priority);
}

#define CONFIG_RTOS_STARTSTOP_TIMER 1

static inline void rtos_timer_start_oneshot(void)
{
    rt_set_oneshot_mode();
    start_rt_timer(0);
}

static inline void rtos_timer_stop(void)
{
    stop_rt_timer();
}

#define rtos_task_wait_period()     rt_task_wait_period()
#define rtos_busy_sleep(nanosecs)   rt_busy_sleep(nanosecs)

static inline void rtos_task_sleep_until(rtos_time_t *wakeup_time)
{
    rt_sleep_until(wakeup_time->val);
}

static inline void rtos_task_sleep(int time)
{
	rt_sleep(nano2count(time));
}

static inline int rtos_in_rt_context(void)
{
    return (rt_whoami()->priority != RTOS_LINUX_PRIORITY);
}



/* event signaling */
#define RTOS_EVENT_TIMEOUT          SEM_TIMOUT
#define RTOS_EVENT_ERROR(result)    ((result) == 0xFFFF /* SEM_ERR */)

/* note: event is initially set to a non-signaled state */
static inline int rtos_event_init(rtos_event_t *event)
{
    rt_typed_sem_init(event, 0, CNT_SEM);
    return 0;
}

/* note: event is initially set to a non-signaled state */
static inline int rtos_event_sem_init(rtos_event_sem_t *event)
{
    rt_typed_sem_init(event, 0, CNT_SEM);
    return 0;
}

static inline void rtos_event_delete(rtos_event_t *event)
{
    rt_sem_delete(event);
}

static inline void rtos_event_sem_delete(rtos_event_sem_t *event)
{
    rt_sem_delete(event);
}


/* note: wakes all waiting tasks, does NOT store events if no one is
 *       listening */
static inline void rtos_event_broadcast(rtos_event_t *event)
{
    rt_sem_broadcast(event);
}

static inline void rtos_event_signal(rtos_event_t *event)
{
    rt_sem_signal(event);
}

/* note: wakes up a single waiting task, must store events if no one is
 *       listening */
static inline void rtos_event_sem_signal(rtos_event_sem_t *event)
{
    rt_sem_signal(event);
}


static inline int rtos_event_wait(rtos_event_t *event)
{
    return rt_sem_wait(event);
}

static inline int rtos_event_sem_wait(rtos_event_sem_t *event)
{
    return rt_sem_wait(event);
}

static inline int rtos_event_sem_wait_timed(rtos_event_sem_t *event,
                                            rtos_time_t *timeout)
{
    return rt_sem_wait_timed(event, timeout->val);
}



/* resource locks */
static inline int rtos_res_lock_init(rtos_res_lock_t *lock)
{
    rt_typed_sem_init(lock, 1, RES_SEM);
    return 0;
}

static inline int rtos_res_lock_delete(rtos_res_lock_t *lock)
{
    rt_sem_delete(lock);
    return 0;
}


static inline void rtos_res_lock(rtos_res_lock_t *lock)
{
    rt_sem_wait(lock);
}

static inline void rtos_res_unlock(rtos_res_lock_t *lock)
{
    rt_sem_signal(lock);
}


/* non-RT signals */
static inline int rtos_nrt_signal_init(rtos_nrt_signal_t *nrt_sig,
                                       void (*handler)(void))
{
    *nrt_sig = rt_request_srq(0, handler, 0);
    return *nrt_sig;
}

static inline void rtos_nrt_signal_delete(rtos_nrt_signal_t *nrt_sig)
{
    rt_free_srq(*nrt_sig);
}


static inline void rtos_nrt_signal_pend(rtos_nrt_signal_t *nrt_sig)
{
    rt_pend_linux_srq(*nrt_sig);
}

/* Fifo management */
static inline int rtos_fifo_create(rtos_fifo_t *fifo, int minor, int size)
{
    fifo->minor = minor;
    return rtf_create(minor, size);
}

static inline void rtos_fifo_destroy(rtos_fifo_t *fifo)
{
    rtf_destroy(fifo->minor);
}

static inline int rtos_fifo_put(rtos_fifo_t *fifo, void *buf, int size)
{
    return rtf_put(fifo->minor, buf, size);
}

/* RT memory management */
#define rtos_malloc(size)           rt_malloc(size)
#define rtos_free(buffer)           rt_free(buffer)



/* IRQ management */
#define RTOS_IRQ_HANDLER_PROTO(name)    void name(unsigned int irq, void *arg)
#define RTOS_IRQ_GET_ARG()              (arg)
#define RTOS_IRQ_RETURN_HANDLED()       return
#define RTOS_IRQ_RETURN_UNHANDLED()     return

static inline int rtos_irq_request(rtos_irq_t *irq_handle, unsigned int irq,
                                   rtos_irq_handler_t handler, void *arg)
{
    *irq_handle = irq;

#if defined(CONFIG_ARCH_I386)
    return rt_request_global_irq_ext(irq,
        (void (*)(void))handler, (unsigned long)arg);
#elif defined(CONFIG_ARCH_PPC)
    return rt_request_global_irq_ext(irq,
        (int (*)(unsigned int, unsigned long))handler, (unsigned long)arg);
#else
    #error Unsupported architecture.
#endif
}

static inline int rtos_irq_free(rtos_irq_t *irq_handle)
{
    return rt_free_global_irq(*irq_handle);
}

static inline void rtos_irq_enable(rtos_irq_t *irq_handle)
{
    rt_enable_irq(*irq_handle);
}

static inline void rtos_irq_disable(rtos_irq_t *irq_handle)
{
    rt_disable_irq(*irq_handle);
}

static inline void rtos_irq_end(rtos_irq_t *irq_handle)
{
#if defined(CONFIG_ARCH_I386)
    rt_enable_irq(*irq_handle);
#elif defined(CONFIG_ARCH_PPC)
    rt_unmask_irq(*irq_handle);
#else
# error Unsupported architecture.
#endif
}

static inline void rtos_irq_release_lock(void)
{
    rt_sched_lock();
    hard_sti();
}

static inline void rtos_irq_reacquire_lock(void)
{
    hard_cli();
    rt_sched_unlock();
}
/*@}*/
#endif /* CONFIG_RTAI_24) || defined(CONFIG_RTAI_30) || (CONFIG_RTAI_31) || defined(CONFIG_RTAI_32)*/


#if defined(CONFIG_FUSION_090)

#include <nucleus/pod.h>
#include <rtdm/rtdm_driver.h>


/* basic types */
typedef rtdm_lock_t                 rtos_spinlock_t;
typedef rtdm_task_t                 rtos_task_t;
typedef rtdm_event_t                rtos_event_t;
typedef rtdm_sem_t                  rtos_sem_t;
typedef rtdm_mutex_t                rtos_res_lock_t;
typedef rtdm_nrtsig_t               rtos_nrt_signal_t;
typedef rtdm_irq_t                  rtos_irq_t;
typedef rtdm_irq_handler_t          rtos_irq_handler_t;

#define ALIGN_RTOS_TASK             16  /* alignment of rtdm_tast_t */


/* print output messages */
#define rtos_print                  rtdm_printk


/* time handling */
static inline __u64 rtos_get_time(void)
{
    return rtdm_clock_read();
}

static inline void rtos_ns_to_timeval(__u64 time, struct timeval *tval)
{
    tval->tv_sec = rthal_ulldiv(time, 1000000000,
                                (unsigned long *)&tval->tv_usec);
    tval->tv_usec /= 1000;
}


/* real-time spin locks */
#define RTOS_SPIN_LOCK_UNLOCKED     RTDM_LOCK_UNLOCKED  /* init */
#define rtos_spin_lock_init(lock)   rtdm_lock_init(lock)

#define rtos_spin_lock(lock)        rtdm_lock_get(lock)
#define rtos_spin_unlock(lock)      rtdm_lock_put(lock)

#define rtos_spin_lock_irqsave(lock, flags) \
    rtdm_lock_get_irqsave(lock, flags)
#define rtos_spin_unlock_irqrestore(lock, flags) \
    rtdm_lock_put_irqrestore(lock, flags)

#define rtos_local_irqsave(flags)   \
    rtdm_lock_irqsave(flags)
#define rtos_local_irqrestore(flags) \
    rtdm_lock_irqrestore(flags)


/* RT-tasks */
#define RTOS_LOWEST_RT_PRIORITY     RTDM_TASK_LOWEST_PRIORITY
#define RTOS_HIGHEST_RT_PRIORITY    RTDM_TASK_HIGHEST_PRIORITY
#define RTOS_RAISE_PRIORITY         (+1)
#define RTOS_LOWER_PRIORITY         (-1)

static inline int rtos_task_init(rtos_task_t *task, unsigned char *name, void (*task_proc)(void *),
                                 void *arg, int priority, int arb)
{
    return rtdm_task_init(task, name, task_proc, arg, priority, 0);
}

static inline int rtos_task_init_periodic(rtos_task_t *task,
                                          void (*task_proc)(void *),
                                          void *arg, int priority,
                                          __u64 period)
{
    return rtdm_task_init(task, NULL, task_proc, arg, priority, period);
}

#define rtos_task_wakeup(task)      rtdm_task_unblock(task)
#define rtos_task_delete(task)      rtdm_task_destroy(task)
#define rtos_task_set_priority(task, priority)  \
    rtdm_task_set_priority(task, priority)

#define CONFIG_RTOS_STARTSTOP_TIMER 1

static inline int rtos_timer_start_oneshot(void)
{
    return xnpod_start_timer(XN_APERIODIC_TICK, XNPOD_DEFAULT_TICKHANDLER);
}

static inline void rtos_timer_stop(void)
{
    xnpod_stop_timer();
}

#define rtos_task_wait_period(task)         rtdm_task_wait_period()
#define rtos_busy_sleep(nanosecs)           rtdm_task_busy_sleep(nanosecs)

#define rtos_task_sleep_until(wakeup_time)  rtdm_task_sleep_until(wakeup_time)

#define rtos_in_rt_context()                rtdm_in_rt_context()


/* event signaling */
#define rtos_event_init(event)              rtdm_event_init(event, 0)
#define rtos_event_delete(event)            rtdm_event_destroy(event)
#define rtos_event_broadcast(event)         rtdm_event_pulse(event)
#define rtos_event_signal(event)            rtdm_event_signal(event)
#define rtos_event_wait(event)              rtdm_event_wait(event)


/* semaphores */
#define rtos_sem_init(sem)                  rtdm_sem_init(sem, 0)
#define rtos_sem_delete(sem)                rtdm_sem_destroy(sem)
#define rtos_sem_down(sem, timeout)         rtdm_sem_down(sem, timeout)
#define rtos_sem_up(sem)                    rtdm_sem_up(sem)


/* resource locks */
#define rtos_res_lock_init(lock)            rtdm_mutex_init(lock)
#define rtos_res_lock_delete(lock)          rtdm_mutex_destroy(lock)
#define rtos_res_lock(lock)                 rtdm_mutex_lock(lock)
#define rtos_res_unlock(lock)               rtdm_mutex_unlock(lock)


/* non-RT signals */
#define rtos_nrt_signal_init(nrt_sig, handler)  \
    rtdm_nrtsig_init(nrt_sig, (rtdm_nrtsig_handler_t)handler)
#define rtos_nrt_signal_delete(nrt_sig)     rtdm_nrtsig_destroy(nrt_sig)
#define rtos_nrt_signal_pend(nrt_sig)       rtdm_nrtsig_pend(nrt_sig)


/* RT memory management */
#define rtos_malloc(size)                   rtdm_malloc(size)
#define rtos_free(buffer)                   rtdm_free(buffer)


/* IRQ management */
#define RTOS_IRQ_HANDLER_PROTO(name)        int name(rtdm_irq_t *irq_handle)
#define RTOS_IRQ_GET_ARG(type)              rtdm_irq_get_arg(irq_handle, type)
#define RTOS_IRQ_RETURN_HANDLED()           return RTDM_IRQ_ENABLE
#define RTOS_IRQ_RETURN_UNHANDLED()         return 0 /* mask, don't propgt. */

#define rtos_irq_request(irq_handle, irq_no, handler, arg)  \
    rtdm_irq_request(irq_handle, irq_no, handler, 0, NULL, arg)
#define rtos_irq_free(irq_handle)           rtdm_irq_free(irq_handle)
#define rtos_irq_enable(irq_handle)         rtdm_irq_enable(irq_handle)
#define rtos_irq_disable(irq_handle)        rtdm_irq_disable(irq_handle)

#define rtos_irq_end(irq_handle)    /* done by returning RT_INTR_ENABLE */

static inline void rtos_irq_release_lock(void)
{
    xnpod_set_thread_mode(xnpod_current_thread(), 0, XNLOCK);
    rthal_local_irq_enable_hw();
}

static inline void rtos_irq_reacquire_lock(void)
{
    rthal_local_irq_disable_hw();
    xnpod_set_thread_mode(xnpod_current_thread(), XNLOCK, 0);
}

#endif /*CONFIG_FUSION_072) || defined(CONFIG_FUSION_074*/

#endif /* __RTOS_PRIMITIVES_H_*/



