/**
 * @file 
 * Data Structure and Service Interfaces of Real-Time Server Module
 *
 * @note Copyright (C) 2005 Zhang Yuchen <yuchen623@gmail.com>
 * 
 * @ingroup rtserver
 */
 
 /**
 * @defgroup serv Real-Time Server module 
 * 
 */
 
#ifndef 	RT_SERVER_H
#define 	RT_SERVER_H

#include <linux/list.h>
#include <rt1394_sys.h>

/*Internal structure of request*/
struct rt_request_struct {
	struct rt_request_struct *next;
	struct rt_request_struct *prev;
		
	//parameter passed to server	
	unsigned long data;
	
	//when this reqeust should be answered
	__u64	firing_time;
	
	//callback proc and data after service
	void (*callback)(struct rt_request_struct *, unsigned long);
	unsigned long callback_data;
	
	char name[32];
};


/*Internal structure of Server */
struct rt_serv_struct {

	struct list_head entry;
	
	atomic_t	pending_req;

	rtos_task_t task;
	int priority;
	
	void (*proc)(unsigned long);
	struct rt_request_struct requests_list;
	rtos_spinlock_t	requests_list_lock;
	
	unsigned char name[32];
	
	struct rt_request_struct reqobj_pool_head;
	int max_req;
		
	__u64 	firing_time;
	
};

/*Internal structure of interrupt event*/
struct rt_event_struct {
	char name[32];
	void (*proc)(unsigned long);
	unsigned long data;
};
		
extern struct rt_serv_struct *rt_serv_init( unsigned char *name, int priority, void (*proc)(unsigned long), int max_req);
extern void rt_serv_delete(struct rt_serv_struct *srv);

extern struct rt_request_struct *rt_request_pend(struct rt_serv_struct *srv, unsigned long data, 
					__u64	delay_time,
					void (*callback)(struct rt_request_struct *, unsigned long),
					unsigned long callback_data, unsigned char *name);

extern void rt_request_delete(struct rt_serv_struct *srv, struct rt_request_struct *req);
extern void rt_serv_sync(struct rt_serv_struct *server);
	
extern void rt_event_init(struct rt_event_struct *evt, char *name, 
					void (*proc)(unsigned long), 
					unsigned long data);
extern void rt_event_pend(struct rt_event_struct *evt);
	
extern void rt_irq_broker_sync(void);

#endif 	/*RT__SERVER_H */
	


