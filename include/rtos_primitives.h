/* rtfirewire/include/rtos_primitives.h
 * Header file for primitives from underlying rtos. 
 * NOTE: dont include this file explicitly, use rt1394_sys.h instead.
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

typedef __s64 nanosecs_t; /*used for time calculations and I/O */

/* basic types */
/**
 * @addtogroup 
 *@{*/
typedef struct {
    RTIME          val;               /* high precision time */
} rtos_time_t;
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
static inline void rtos_get_time(rtos_time_t *time)
{
    time->val = rt_get_time();
}


static inline void rtos_nanosecs_to_time(nanosecs_t nano, rtos_time_t *time)
{
    time->val = nano2count(nano);
}

static inline nanosecs_t rtos_time_to_nanosecs(rtos_time_t *time)
{
    return (nanosecs_t)count2nano(time->val);
}


static inline void rtos_time_to_timeval(rtos_time_t *time,
                                        struct timeval *tval)
{
    count2timeval(time->val, tval);
}


static inline void rtos_time_sum(rtos_time_t *result,
                                 rtos_time_t *a, rtos_time_t *b)
{
    result->val = a->val + b->val;
}


static inline void rtos_time_diff(rtos_time_t *result,
                                  rtos_time_t *a, rtos_time_t *b)
{
    result->val = a->val - b->val;
}

#define RTOS_TIME_IS_ZERO(time)     ((time) == 0)
#define RTOS_TIME_IS_BEFORE(a, b)   ((a) < (b))
#define RTOS_TIME_EQUALS(a, b)      ((a) == (b))



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

#define RTOS_TIME_LIMIT	0x7FFFFFFFFFFFFFFFLL //copied from rtai_hal.h 

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


static inline void rtos_pend_nrt_signal(rtos_nrt_signal_t *nrt_sig)
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


#if defined(CONFIG_FUSION_072) || defined(CONFIG_FUSION_074)

#include <nucleus/heap.h>
#include <nucleus/pod.h>
#include <rtai/task.h>
#include <rtai/sem.h>
#include <rtai/mutex.h>
#include <rtai/pipe.h>
#include <rtai/intr.h>

typedef __s64 nanosecs_t; /*used for time calculations and I/O */

/* basic types */
typedef struct {
    RTIME          val;               /* high precision time */
} rtos_time_t;
typedef spinlock_t rtos_spinlock_t;   /* spin locks with hard IRQ locks */
typedef RT_TASK    rtos_task_t;       /* hard real-time task */
typedef RT_SEM     rtos_event_t;      /* to signal events (non-storing) */
typedef RT_SEM     rtos_event_sem_t;  /* to signal events (storing) */
typedef RT_MUTEX   rtos_res_lock_t;   /* resource lock with prio inheritance */
typedef int        rtos_nrt_signal_t; /* async signal to non-RT world */
typedef RT_PIPE    rtos_fifo_t;       /* fifo descriptor */
typedef RT_INTR    rtos_irq_t;        /* handle to requested IRQ */
typedef rt_isr_t   rtos_irq_handler_t;/* IRQ handler prototype */

#define ALIGN_RTOS_TASK   16  /* RT_TASK requires 16-bytes alignment */


/* print output messages */
#define rtos_print              printk


/* time handling */
static inline void rtos_get_time(rtos_time_t *time)
{
    time->val = rt_timer_read();
}


static inline void rtos_nanosecs_to_time(nanosecs_t nano, rtos_time_t *time)
{
    time->val = nano;
}

static inline nanosecs_t rtos_time_to_nanosecs(rtos_time_t *time)
{
    return time->val;
}


static inline void rtos_time_to_timeval(rtos_time_t *time,
                                        struct timeval *tval)
{
    tval->tv_sec = rthal_ulldiv(time->val, 1000000000,
                                (unsigned long *)&tval->tv_usec);
    tval->tv_usec /= 1000;
}


static inline void rtos_time_sum(rtos_time_t *result,
                                 rtos_time_t *a, rtos_time_t *b)
{
    result->val = a->val + b->val;
}


static inline void rtos_time_diff(rtos_time_t *result,
                                  rtos_time_t *a, rtos_time_t *b)
{
    result->val = a->val - b->val;
}

#define RTOS_TIME_IS_ZERO(time)     ((time)->val == 0)
#define RTOS_TIME_IS_BEFORE(a, b)   ((a)->val < (b)->val)
#define RTOS_TIME_EQUALS(a, b)      ((a)->val == (b)->val)



/* real-time spin locks */
#define RTOS_SPIN_LOCK_UNLOCKED     SPIN_LOCK_UNLOCKED  /* init */
#define rtos_spin_lock_init(lock)   spin_lock_init(lock)

#define rtos_spin_lock(lock)        rthal_spin_lock(lock)
#define rtos_spin_unlock(lock)      rthal_spin_unlock(lock)

#define rtos_spin_lock_irqsave(lock, flags) \
    rthal_spin_lock_irqsave(lock, flags)
#define rtos_spin_unlock_irqrestore(lock, flags) \
    rthal_spin_unlock_irqrestore(lock, flags)

#define rtos_local_irqsave(flags)   \
    rthal_local_irq_save(flags)
#define rtos_local_irqrestore(flags) \
    rthal_local_irq_restore(flags)

#define rtos_saveflags(flags) \
    rthal_local_irq_flags(flags)



/* RT-tasks */
#define RTOS_LOWEST_RT_PRIORITY     T_LOPRIO
#define RTOS_HIGHEST_RT_PRIORITY    T_HIPRIO
#define RTOS_RAISE_PRIORITY         (+1)
#define RTOS_LOWER_PRIORITY         (-1)

static inline int rtos_task_init(rtos_task_t *task, void (*task_proc)(int),
                                 int arg, int priority)
{
    int ret;

    ret = rt_task_create(task, NULL, 4096, priority, 0);

    if (ret)
        return ret;

    ret = rt_task_start(task, (void (*)(void *))task_proc, (void *)arg);

    if (ret)
        rt_task_delete(task);

    return ret;
}

static inline int rtos_task_init_periodic(rtos_task_t *task,
                                          void (*task_proc)(int), int arg,
                                          int priority, rtos_time_t *period)
{
    int ret;

    ret = rt_task_create(task, NULL, 4096, priority, 0);

    if (ret)
        return ret;

    ret = rt_task_set_periodic(task, TM_INFINITE, period->val);

    if (!ret)
        ret = rt_task_start(task, (void (*)(void *))task_proc, (void *)arg);

    if (ret)
        rt_task_delete(task);

    return ret;
}

static inline int rtos_task_init_suspended(rtos_task_t *task,
                                           void (*task_proc)(int),
                                           int arg, int priority)
{
    int ret;

    ret = rt_task_create(task, NULL, 4096, priority, T_SUSP);

    if (ret)
        return ret;

    ret = rt_task_start(task, (void (*)(void *))task_proc, (void *)arg);

    if (ret)
        rt_task_delete(task);

    return ret;
}

static inline int rtos_task_resume(rtos_task_t *task)
{
    return rt_task_resume(task);
}

static inline int rtos_task_wakeup(rtos_task_t *task)
{
    return rt_task_unblock(task);
}

static inline void rtos_task_delete(rtos_task_t *task)
{
    rt_task_delete(task);
}

static inline int rtos_task_set_priority(rtos_task_t *task, int priority)
{
    return rt_task_set_priority(task, priority);
}

#define CONFIG_RTOS_STARTSTOP_TIMER 1

static inline int rtos_timer_start_oneshot(void)
{
    return rt_timer_start(TM_ONESHOT);
}

static inline void rtos_timer_stop(void)
{
    rt_timer_stop();
}

#define rtos_task_wait_period(task) rt_task_wait_period()
#define rtos_busy_sleep(nanosecs)   rt_timer_spin(nanosecs)

static inline void rtos_task_sleep_until(rtos_time_t *wakeup_time)
{
    rt_task_sleep_until(wakeup_time->val);
}


static inline int rtos_in_rt_context(void)
{
    return adp_current != adp_root; /* Ask Adeos. */
}



/* event signaling */
#define RTOS_EVENT_TIMEOUT          -ETIMEDOUT
#define RTOS_EVENT_ERROR(result)    ((result) < 0)

/* note: event is initially set to a non-signaled state */
static inline int rtos_event_init(rtos_event_t *event)
{
    return rt_sem_create(event, NULL, 0, S_FIFO);
}

/* note: event is initially set to a non-signaled state */
static inline int rtos_event_sem_init(rtos_event_sem_t *event)
{
    return rt_sem_create(event, NULL, 0, S_FIFO);
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

/* note: wakes up a single waiting task, must store events if no one is
 *       listening */
static inline void rtos_event_sem_signal(rtos_event_sem_t *event)
{
    rt_sem_v(event);
}

static inline void rtos_event_signal(rtos_event_t *event)
{
    rt_sem_v(event);
}


static inline int rtos_event_wait(rtos_event_t *event)
{
    return rt_sem_p(event, TM_INFINITE);
}

static inline int rtos_event_sem_wait(rtos_event_sem_t *event)
{
    return rt_sem_p(event, TM_INFINITE);
}

static inline int rtos_event_sem_wait_timed(rtos_event_sem_t *event,
                                            rtos_time_t *timeout)
{
    return rt_sem_p(event, timeout->val);
}



/* resource locks */
static inline int rtos_res_lock_init(rtos_res_lock_t *lock)
{
    return rt_mutex_create(lock, NULL);
}

static inline void rtos_res_lock_delete(rtos_res_lock_t *lock)
{
    rt_mutex_delete(lock);
}


static inline void rtos_res_lock(rtos_res_lock_t *lock)
{
    rt_mutex_lock(lock);
}

static inline void rtos_res_unlock(rtos_res_lock_t *lock)
{
    rt_mutex_unlock(lock);
}


/* non-RT signals */
static inline int rtos_nrt_signal_init(rtos_nrt_signal_t *nrt_sig,
                                       void (*handler)(void))
{
    *nrt_sig = adeos_alloc_irq();

    if (*nrt_sig > 0)
        adeos_virtualize_irq_from(adp_root,
                                  *nrt_sig,
                                  (void (*)(unsigned))handler,
                                  NULL,
                                  IPIPE_HANDLE_MASK);
    else
        *nrt_sig = -EBUSY;

    return *nrt_sig;
}

static inline void rtos_nrt_signal_delete(rtos_nrt_signal_t *nrt_sig)
{
    adeos_free_irq(*nrt_sig);
}


static inline void rtos_pend_nrt_signal(rtos_nrt_signal_t *nrt_sig)
{
    adeos_trigger_irq(*nrt_sig);
}


/* Fifo management */
#if defined(CONFIG_FUSION_072)

static inline int rtos_fifo_create(rtos_fifo_t *fifo, int minor, int size)
{
    return rt_pipe_open(fifo, minor);
}

static inline void rtos_fifo_destroy(rtos_fifo_t *fifo)
{
    rt_pipe_close(fifo);
}

#else /* !CONFIG_FUSION_072 */

static inline int rtos_fifo_create(rtos_fifo_t *fifo, int minor, int size)
{
    return rt_pipe_create(fifo, NULL, minor);
}

static inline void rtos_fifo_destroy(rtos_fifo_t *fifo)
{
    rt_pipe_delete(fifo);
}

#endif /* !CONFIG_FUSION_072 */

static inline int rtos_fifo_put(rtos_fifo_t *fifo, void *buf, int size)
{
    return rt_pipe_stream(fifo,buf,size);
}

/* RT memory management */
#define rtos_malloc(size)           xnmalloc(size) /* Ask the nucleus. */
#define rtos_free(buffer)           xnfree(buffer)



/* IRQ management */
#define RTOS_IRQ_HANDLER_PROTO(name)    int name(xnintr_t *cookie)
#define RTOS_IRQ_GET_ARG()              (I_DESC(cookie)->private_data)
#define RTOS_IRQ_RETURN_HANDLED()       return (RT_INTR_HANDLED|RT_INTR_ENABLE)
#define RTOS_IRQ_RETURN_UNHANDLED()     return 0; /* mask, don't propagate */

static inline int rtos_irq_request(rtos_irq_t *irq_handle, unsigned int irq,
                                   rtos_irq_handler_t handler, void *arg)
{
    int ret;

    ret = rt_intr_create(irq_handle, irq, handler);
    irq_handle->private_data = arg;
    return ret;
}

static inline int rtos_irq_free(rtos_irq_t *irq_handle)
{
    return rt_intr_delete(irq_handle);
}

static inline void rtos_irq_enable(rtos_irq_t *irq_handle)
{
    rt_intr_enable(irq_handle);
}

static inline void rtos_irq_disable(rtos_irq_t *irq_handle)
{
    rt_intr_disable(irq_handle);
}

#define rtos_irq_end(irq_handle)    /* done by returning RT_INTR_ENABLE */

static inline void rtos_irq_release_lock(void)
{
    rt_task_set_mode(0,T_LOCK,NULL);
    rthal_hw_enable();
}

static inline void rtos_irq_reacquire_lock(void)
{
    rthal_hw_disable();
    rt_task_set_mode(T_LOCK,0,NULL);
}
#endif /*CONFIG_FUSION_072) || defined(CONFIG_FUSION_074*/

#endif /* __RTOS_PRIMITIVES_H_*/



