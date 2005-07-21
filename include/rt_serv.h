/**
 * @ingroup serv
 * @file 
 *
 * Data structure and interfaces of the real-time server module
 */
#ifndef 	RT_SERVER_H
#define 	RT_SERVER_H

#define	RTSERV_ERR(fmt, args...) \
rtos_print("RT_SERV:"fmt, ## args)

#ifdef	CONFIG_RTSERV_DEBUG
#define	RTSERV_NOTICE(fmt, args...)\
rtos_print("RT_SERV:"fmt, ## args)
#else
#define	RTSERV_NOTICE(fmt,args...)
#endif

#include <linux/list.h>
#include <rt1394_sys.h>
#include <rtos_primitives.h>

#define MAX_REQ 10	//max number of request to be queued to each server

struct rt_request_struct {
	struct rt_request_struct *next;
	struct rt_request_struct *prev;
		
	//parameter passed to server	
	unsigned long data;
	
	//when this reqeust should be answered
	rtos_time_t	firing_time;
	
	//callback after service
	void (*callback)(struct rt_request_struct *, unsigned long);
	unsigned long callback_data;
	
	char name[32];
};

static inline void rt_request_init(struct rt_request_struct *req, char *name, 
						unsigned long data, nanosecs_t  time,
						void (*callback)(struct rt_request_struct *, unsigned long),
						unsigned long callback_data)
{
	rtos_time_t	now;
	rtos_get_time(&now);
	
	rtos_nanosecs_to_time(time, &req->firing_time);
	req->firing_time.val = now.val + req->firing_time.val;
	
	req->data = data;
	req->callback = callback;
	req->callback_data = callback_data;
	strncpy(req->name, name, 32);
}

struct rt_serv_struct {
	//for proc
	struct list_head entry;
	
	atomic_t	pending_req;
		
	rtos_task_t task;
	int priority, use_fpu, stack_size;
	
	void (*routine)(unsigned long);
	struct rt_request_struct requests_list;
	rtos_spinlock_t	requests_list_lock;
	
	unsigned char name[32];
	
	struct rt_request_struct reqobj_pool_head;
	
#ifdef CONFIG_RTSERVER_CHECKED
	volatile int resp_nr;
	volatile RTIME max_exec_time;
	volatile RTIME min_exec_time;
#endif
};

/**
 * Initialize the request list (for server).
 * The request list is the head of the list, 
 * with a firing time infinitly far, so the server
 * will not get suspended, but go to idleness for 
 * infinitly long until new request comes. 
 */
static inline void requests_list_init(struct rt_request_struct *list)
{
	if(list==NULL)
		RTSERV_ERR("list null\n");
	
	list->next = list->prev = list;
	list->firing_time.val = RTOS_TIME_LIMIT;
	sprintf(list->name, "list head");
}

struct rt_event_struct {
	char name[32];
	struct list_head hook;
	void (*routine)(unsigned long);
	unsigned long data;
};
		
extern struct rt_serv_struct *rt_serv_init( unsigned char *name, int priority, 
									int stack_size, int use_fpu,
									void (*routine)(unsigned long));
extern void rt_serv_delete(struct rt_serv_struct *srv);

extern struct rt_request_struct *rt_request_pend(struct rt_serv_struct *srv, unsigned long data, 
					nanosecs_t	time,
					void (*callback)(struct rt_request_struct *, unsigned long),
					unsigned long callback_data, unsigned char *name);
extern void rt_request_delete(struct rt_serv_struct *srv, struct rt_request_struct *req);
extern void rt_serv_sync(struct rt_serv_struct *server);
	
extern void rt_event_init(struct rt_event_struct *evt, char *name, 
					void (*routine)(unsigned long), 
					unsigned long data);
extern void rt_event_pend(struct rt_event_struct *evt);
extern void rt_event_delete(struct rt_event_struct *evt);
	
extern void rt_irq_broker_sync(void);

#endif 	/*RT__SERVER_H */
	


