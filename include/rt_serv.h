/**
 * @ingroup serv
 * @file 
 *
 * Data structure and interfaces of the real-time server module
 */
#ifndef RT_IRQBH_H
#define RT_IRQBH_H

#include <linux/list.h>
#include <rt1394_sys.h>

//~ #define SERVER_MODULE_CHECKED

struct rt_serv_struct {
	struct list_head entry;
	struct list_head hook;
	
	void (*routine)(unsigned long);
	unsigned long data;
	
	rtos_event_t event;
		
	rtos_task_t task;
	int priority, uses_fpu, stack_size;
#ifdef SERVER_MODULE_CHECKED
	volatile int resp_nr;
	volatile RTIME max_exec_time;
	volatile RTIME min_exec_time;
#endif
	unsigned char name[32];
};

struct rt_event_struct {
	struct list_head hook;
	rtos_event_t *sync;
};
		
extern struct rt_serv_struct *rt_serv_init( unsigned char *name, void (*routine)(unsigned long), unsigned long data, 
								int priority);
extern void rt_serv_delete(struct rt_serv_struct *srv);

extern void rt_event_pend(struct rt_event_struct *evt);
extern void rt_event_delete(struct rt_event_struct *evt);
	
extern void rt_irq_broker_wake(void);
#endif
	