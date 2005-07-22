/*rt-firewire/rt_serv/rt_serv.c
 * Implementation of generic server module, used by RT-FireWire
 *
 * Copyright (C)  2005 Zhang Yuchen <y.zhang-4@student.utwente.nl>
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


/**
 * @ingroup serv
 * @file
 *
 * Implementation of the real-time server module. 
 */
 
/**
 * @defgroup serv Real-Time Server module 
 * 
 */
 #include <rt1394_sys.h>
 
 #include <linux/module.h>
 #include <linux/init.h>
 #include <linux/slab.h>
 #include <linux/list.h>
 #include <linux/proc_fs.h>
 #include <linux/spinlock.h>
 
 #include <rt_serv.h>
 #include <rtos_primitives.h>
 
  #define IRQ_BROKER_PRI 	2+RTOS_HIGHEST_RT_PRIORITY
  
 LIST_HEAD(rt_servers_list);
 LIST_HEAD(nrt_servers_list);
 LIST_HEAD(event_list);
 
 static rwlock_t servers_list_lock = RW_LOCK_UNLOCKED;
 static int nrt_serv_srq;

#define DEFAULT_STACK_SIZE	4096
#define DEFAULT_USE_FPU	0

rtos_event_t irq_brk_sync;

spinlock_t event_list_lock = SPIN_LOCK_UNLOCKED;
rtos_task_t irq_brk;
 
void irqbrk_worker(int data)
{
	struct list_head *lh, *tmp;
	struct rt_event_struct *evt;
	unsigned long flags;
		
	rtos_print("RT-Serv:irq broker started\n");
	while(1){
		if (RTOS_EVENT_ERROR(rtos_event_wait(&irq_brk_sync)))
			return;
		
		rtos_spin_lock_irqsave(&event_list_lock,flags);
		list_for_each_safe(lh, tmp, &event_list){
			evt = list_entry(lh, struct rt_event_struct, hook);
		#ifdef CONFIG_IEEE1394_DEBUG
			rtos_print("RT-Serv:event %s is being handled\n", evt->name);
		#endif
			if(evt->routine)
				evt->routine(evt->data);
			else
				rtos_print("RT-Serv:event has no routine!!!\n");
		}
		INIT_LIST_HEAD(&event_list);
		rtos_spin_unlock_irqrestore(&event_list_lock,flags);
	}
}

void rt_event_init(struct rt_event_struct *evt, char *name, 
					void (*routine)(unsigned long), 
					unsigned long data)
{
	INIT_LIST_HEAD(&evt->hook);
	evt->data = data;
	evt->routine = routine;
	strncpy(evt->name, name, 32);
}
	
void rt_event_pend(struct rt_event_struct *evt)
{
	rtos_spin_lock(&event_list_lock);
	list_add_tail(&evt->hook, &event_list);
	rtos_spin_unlock(&event_list_lock);
}

void rt_event_delete(struct rt_event_struct *evt)
{
	rtos_spin_lock(&event_list_lock);
	list_del(&evt->hook);
	rtos_spin_unlock(&event_list_lock);
}
	
void rt_irq_broker_sync(void)
{
	rtos_event_signal(&irq_brk_sync);
}

 /**
  * Synchronize the server with its requests list
  * for non real-time server, just pending a srq to Linux, where 
  * the server is.
  * For real-time server, we need to reschedule it if the server is 
  * in sleep. If it is currently running. we need to do nothing. 
  */
 void rt_serv_sync(struct rt_serv_struct *srv)
 {
	struct rt_request_struct *req;
	req = srv->requests_list.next;
	if(req==&srv->requests_list){
		//fake sync
		RTSERV_ERR("fake sync!\n");
	}
	
	DEBUG_PRINT("sync server %s\n", srv->name);
	 if(srv->priority==RTOS_LINUX_PRIORITY){
		//non real-time server in Linux, use srq to sync
		rt_pend_linux_srq(nrt_serv_srq);
	}else{
		unsigned long flags;
		//real-time server in rtai
		if(req->firing_time.val <= rt_get_time()){
			flags = rt_global_save_flags_and_cli();
			//this request needs to be taken immediately
			if(srv->task.state & RT_SCHED_DELAYED){
				rem_timed_task(&srv->task);
				enq_ready_task(&srv->task);
				rt_schedule();
			}
			rt_global_restore_flags(flags); //otherwise the server is taking some request, 
								   //it can reach a rescheduling point itself
								  // so we need to do nothing for rescheduling it. 
		}else{
			flags = rt_global_save_flags_and_cli();
			//this request needs to be taken within a delay
			srv->task.resume_time = req->firing_time.val;
			if(srv->task.state & RT_SCHED_DELAYED){
				rem_timed_task(&srv->task);
				enq_timed_task(&srv->task);
				rt_schedule();
			}//as above
			rt_global_restore_flags(flags);
		}
	}
}

/**
 * This function pends the request to a certain server.
 * If the server is in normal mode, only immediate request can be queued 
 * can only queuing is done.
 * If the server is in timed mode, only delayed request can be queued.
 * Beside queuing, the resume time for the server is also checked. If the new request
 * asks for closer resume time, the resume time of server is changed and server is rescheduled.
 * If the server is suspended, 
 *
 * @note thie function only do the pending of request, the synchronization work between server
 * is done by @ref rt_serv_sync.
 */
struct rt_request_struct *rt_request_pend(struct rt_serv_struct *srv, unsigned long data, 
					nanosecs_t	time,
					void (*callback)(struct rt_request_struct *, unsigned long),
					unsigned long callback_data,
					unsigned char *name)
{
	int id = atomic_read(&srv->pending_req);
	if(id == MAX_REQ){
		RTSERV_ERR("server[%s] reaches max request number\n", srv->name);
		return NULL;
	}
	
	//allocate request object
	struct rt_request_struct *req = srv->reqobj_pool_head.next;
	req->prev->next = req->next;
	req->next->prev = req->prev;
	
	if(time){
		rtos_nanosecs_to_time(time, &req->firing_time);
		req->firing_time.val = rt_time_h + req->firing_time.val;
	}else{
		req->firing_time.val = 0;
	}
	
	req->data = data;
	req->callback = callback;
	req->callback_data = callback_data;
	if(name)
		strncpy(req->name, name, 32);
	
	unsigned long flags;
	if(srv->priority == RTOS_LINUX_PRIORITY){
		//non real-time server
		//so it gets very easy, just add it to tail
		rtos_spin_lock_irqsave(&srv->requests_list_lock,flags);
		req->next = &srv->requests_list;
		req->prev = srv->requests_list.prev;
		req->prev->next = req->next->prev = req;
		rtos_spin_unlock_irqrestore(&srv->requests_list_lock,flags);
		atomic_inc(&srv->pending_req);
	}else{
		//real-time server
		//so it gets relatively complex
		rtos_spin_lock_irqsave(&srv->requests_list_lock,flags);
		
		struct rt_request_struct *tmpreq = srv->requests_list.next;
		
		//find the previous request which requires just later service
		//than the request in concern. 
		do {
			if(tmpreq->firing_time.val > req->firing_time.val)
				break;
			
			tmpreq = tmpreq->next;
		}while(tmpreq != &srv->requests_list);
		
		//add new request before tmpreq
		req->next = tmpreq;
		req->prev = tmpreq->prev;
		req->prev->next = req->next->prev = req;
		
		rtos_spin_unlock_irqrestore(&srv->requests_list_lock, flags);
		atomic_inc(&srv->pending_req);
	}
	
	return req;				
}

/**
 * Delete a request from a server
 * This function may needs rescheduling of the 
 * server task, if the server is real-time.
 */
void rt_request_delete(struct rt_serv_struct *srv, struct rt_request_struct *req)
{
	unsigned long flags;
	rtos_spin_lock_irqsave(&srv->requests_list_lock, flags);
	//get request out of chain	 
	req->prev->next = req->next;
	req->next->prev = req->prev;
	
	atomic_dec(&srv->pending_req);
	
	rtos_spin_unlock_irqrestore(&srv->requests_list_lock, flags);
	
	if(srv->priority != -1 && req->prev == &srv->requests_list && srv->task.state & RT_SCHED_DELAYED){
		//we deleted the frist request in queue,
		// and the server is in idleness
		//so we need to check the rescheduling manually
		struct rt_request_struct *req_head = srv->requests_list.next;
		
		unsigned long flags;

		//real-time server in rtai
		if(req_head->firing_time.val <= rt_time_h){
			flags = rt_global_save_flags_and_cli();
			//this next request needs to be taken immediately
			//but this is not possible!
			if(srv->task.state & RT_SCHED_DELAYED){
				rem_timed_task(&srv->task);
				enq_ready_task(&srv->task);
				rt_schedule();
			}//otherwise the server is taking some request, 
			//it can reach a rescheduling point itself
			// so we need to do nothing for rescheduling it. 
			rt_global_restore_flags(flags);
		}else{
			flags = rt_global_save_flags_and_cli();
			//this next request needs to be taken within a delay
			//so we need to change the resume time
			srv->task.resume_time = req_head->firing_time.val;
			if(srv->task.state & RT_SCHED_DELAYED){
				rem_timed_task(&srv->task);
				enq_timed_task(&srv->task);
				rt_schedule();
			}//as above
			rt_global_restore_flags(flags);
		}
	}
	
	//finally, queue the req object back to our free object pool
	req->next = &srv->reqobj_pool_head;
	req->prev = srv->reqobj_pool_head.prev;
	req->next->prev = req->prev->next = req;
}

/**
 * real-time server worker
 * The processing routine of real-time sever
 * as a real-time task in rtai.
 */
 void rt_serv_worker(int data)
 {
	struct rt_serv_struct *srv = (struct rt_serv_struct*)data;
		
#ifdef CONFIG_RTSERVER_CHECKED
	RTIME start_job, end_job,last_exec_time;
#endif
	while(1){
		struct rt_request_struct *req = srv->requests_list.next;
			if(req->firing_time.val > rt_time_h){
			//we need to sleep a while due to the delayed request
			//~ srv->task.resume_time = req->firing_time.val;
			//~ rem_ready_task(&srv->task);
			//~ enq_timed_task(&srv->task);
			//~ rt_schedule();
			rt_sleep_until(req->firing_time.val);
			DEBUG_PRINT("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
		}//otherwise, the request is immediate request,
		  //so we just go on. 
			
	#ifdef CONFIG_RTSERVER_CHECKED
			start_job = rt_get_time();
	#endif
			//we need to refind the address of first request in the list
		        //since it may be changed by other requests that jumped in later
		       //but has a earlier due time. 
			req = srv->requests_list.next;
			
			if(srv->routine)
				srv->routine(req->data);
			else
				RTSERV_ERR("%s has no routine!!!\n", srv->name);
			
			//get request out of chain	 
			req->prev->next = req->next;
			req->next->prev = req->prev;
		
			//call the callback 
			if(req->callback)
				req->callback(req, req->callback_data);
			
			//return object to pool
			req->next = &srv->reqobj_pool_head;
			req->prev = srv->reqobj_pool_head.prev;
			req->next->prev = req->prev->next = req;
		
			atomic_dec(&srv->pending_req);
		
	#ifdef CONFIG_RTSERVER_CHECKED
			end_job = rt_get_time();
			last_exec_time = end_job - start_job;
			if(last_exec_time > srv->max_exec_time)
				srv->max_exec_time = last_exec_time;
			else
				if(last_exec_time < srv->min_exec_time)
					srv->min_exec_time = last_exec_time;
		
			srv->resp_nr++;
	#endif
	}
 }
 
 /**
  * The non real-time server processing routine.
  * Acutally it is the hanler for Linux srq. 
  */
 void nrt_serv_worker(void)
 {
	 struct rt_serv_struct *srv;
	 struct list_head *lh;
	 list_for_each(lh, &nrt_servers_list){
		 srv = list_entry(lh, struct rt_serv_struct, entry);
		
		 struct rt_request_struct *req;
		 req = srv->requests_list.next;
		 
		if(srv->routine)
				srv->routine(req->data);
			else
				RTSERV_ERR("%s has no routine!!!\n", srv->name);
		 
		//get request out of chain	 
		 req->prev->next = req->next;
		 req->next->prev = req->prev;
		
		 //call the callback 
		 if(req->callback)
		 req->callback(req, req->callback_data);
		 
		 //return request object to pool
		req->next = &srv->reqobj_pool_head;
		req->prev = srv->reqobj_pool_head.prev;
		req->next->prev = req->prev->next = req;
		
		atomic_dec(&srv->pending_req);
	}			 
 }


/**
 * Delete a server
 * @param the pointer to server
 * 
 * Before deleting, check if there are still some 
 * pending requests. Currently, only error message 
 * is printed out. 
 * @Todo, add callback to deal with
 *  these leftover pending request. 
 * If the server is in real-time context, e.g. rtai,
 * delete the real-time task associated. 
 */
void rt_serv_delete(struct rt_serv_struct *srv)
{
	if(srv){
		if(atomic_read(&srv->pending_req) != 0)
			RTSERV_ERR("server %s still has %d requests unanswered!\n", srv->name, 
							atomic_read(&srv->pending_req));
		if(srv->priority>-1)
			rtos_task_delete(&srv->task);
		list_del(&srv->entry);
		RTSERV_NOTICE("server %s removed\n", srv->name);
		kfree(srv);
	}
}


 /**
 * Initialize a server
 *
 * @param name is the name of the new server
 *
 * @param priority is the priority of realtime task in rtai
 * @param stack size and use_fpu is for the server, 
 * use -1 to choose default settings here. I.e. 
 * default stack size is 4096 bytes
 * default use fpu is NO (0). 
 * 
 * @param routine is the execution path for requests. 
 * Note that only non-block code can be put to the routine. 
 *  
 * @return the pointer to bh_task struct on success
 *	 - @b NULL on failure.
 */ 
struct rt_serv_struct *rt_serv_init(unsigned char *name, int priority, int stack_size, int use_fpu, 
								void (*routine)(unsigned long))
{
	if(priority<-1){
		RTSERV_ERR("illegal priority %d\n", priority);
		return NULL;
	}

	struct rt_serv_struct *srv;
	srv = kmalloc(sizeof(struct rt_serv_struct), GFP_KERNEL);
	if(!srv){
		RTSERV_ERR("out of memory\n");
		return NULL;
	}
	strcpy(srv->name, name);
	srv->reqobj_pool_head.next = 
			srv->reqobj_pool_head.prev =
					&srv->reqobj_pool_head;
	
	srv->stack_size = (stack_size==-1) ? DEFAULT_STACK_SIZE:stack_size;
	srv->use_fpu = (use_fpu==-1) ? DEFAULT_USE_FPU:use_fpu;
	srv->priority = (priority==-1) ? RTOS_LINUX_PRIORITY : priority;
	
	srv->routine = routine;
	
	atomic_set(&srv->pending_req, 0);
	
	//to allocate the request object pool,
	//so we also have static memory allocation 
	//for reqeust object
	int i;
	struct rt_request_struct *req;
	for(i=0; i<MAX_REQ; i++){
		req=kmalloc(sizeof(*req), GFP_KERNEL);
		req->next = &srv->reqobj_pool_head;
		req->prev = srv->reqobj_pool_head.prev;
		req->next->prev = req->prev->next = req;
	}
	
	if(priority == -1){
		// non real-time server in Linux
		spin_lock(&servers_list_lock);
		list_add_tail(&srv->entry, &nrt_servers_list);
		spin_unlock(&servers_list_lock);
		
		requests_list_init(&srv->requests_list);
		srv->requests_list_lock = RTOS_SPIN_LOCK_UNLOCKED;
	}else{
		//real time server in rtai
		spin_lock(&servers_list_lock);
		list_add_tail(&srv->entry, &rt_servers_list);
		spin_unlock(&servers_list_lock);
		
		requests_list_init(&srv->requests_list);
		srv->requests_list_lock = RTOS_SPIN_LOCK_UNLOCKED;
	
		if(rtos_task_init(&srv->task, rt_serv_worker, (int)srv, srv->stack_size, srv->priority + RTOS_HIGHEST_RT_PRIORITY,
				srv->use_fpu)) {
			RTSERV_ERR("failed to initialize server %s!!\n", srv->name);
			rt_serv_delete(srv);
			return NULL;
		}	
	}

	RTSERV_NOTICE("server %s in %s created\n", srv->name, (priority==-1)?"Linux":"RTAI");
	
	return srv;
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

static int serv_read_proc(char *page, char **start, off_t off, int count,
					int *eof, void *data)
{
	struct rt_serv_struct *srv;
	
	struct list_head *lh;
	off_t begin=0, pos=0;
	int len=0;
	
	read_lock(&servers_list_lock);

#ifdef CONFIG_RTSERVER_CHECKED
	PUTF("server name\t\tpriority\tmaxet\tminet\tresponses\n");
	list_for_each(lh, &rt_servers_list) {
		srv = list_entry(lh, struct rt_serv_struct, entry);
		PUTF("%s\t\t%d\t%llx\t%llx\t%d\n", srv->name, srv->priority,
							srv->max_exec_time, srv->min_exec_time, srv->resp_nr);
	}
	
	list_for_each(lh, &nrt_servers_list) {
		srv = list_entry(lh, struct rt_serv_struct, entry);
		PUTF("%s\t\t%d\t%llx\t%llx\t%d\n", srv->name, srv->priority,
							srv->max_exec_time, srv->min_exec_time, srv->resp_nr);
	}
#else
	PUTF("server name\t\tpriority\tpending_req\n");
	list_for_each(lh, &rt_servers_list) {
		srv = list_entry(lh, struct rt_serv_struct, entry);
		PUTF("%s\t\t%d\t%d\n", srv->name, srv->priority, atomic_read(&srv->pending_req));
	}

	list_for_each(lh, &nrt_servers_list) {
		srv = list_entry(lh, struct rt_serv_struct, entry);
		PUTF("%s\t\t%d\t%d\n", srv->name, srv->priority, atomic_read(&srv->pending_req));
	}
#endif
		
done_proc:
	read_unlock(&servers_list_lock);

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


int serv_module_init(void)
{
	struct proc_dir_entry *proc_entry;

	rtos_event_init(&irq_brk_sync);
	
	if(rtos_task_init_fast(&irq_brk, irqbrk_worker, 0, IRQ_BROKER_PRI)){
		printk("RT-Serv:Failed to init irq broker task\n");
		rtos_event_delete(&irq_brk_sync);
		return -ENOMEM;
	}
	
	//srq for server in LInux
	if((nrt_serv_srq = rt_request_srq(0, nrt_serv_worker, 0))<0){
		printk("RT-Serv:no srq available in rtai\n");
		return -ENOMEM;
	}
	
	proc_entry = create_proc_entry("servers", S_IFREG | S_IRUGO | S_IWUSR, 0);
	if(!proc_entry) {
		printk("RT-Serv:failed to create proc entry!\n");
		rt_free_srq(nrt_serv_srq);
		return -ENOMEM;
	}
	proc_entry->read_proc = serv_read_proc;
	
	printk("RT-Serv:Real-Time Server Module Initialized!\n");

	return 0;
}

void serv_module_exit(void)
{
	struct list_head *lh;
	struct rt_serv_struct *srv;
	int unclean=0;
	
	printk("Going to release RT-Serv module....\n");
	
	list_for_each(lh, &rt_servers_list){
	    srv = list_entry(lh, struct rt_serv_struct, entry);
	    printk("RT-Serv: Server %s is still in use!!!\n",srv->name);
	    unclean++;
	}
	
	list_for_each(lh, &nrt_servers_list){
	    srv = list_entry(lh, struct rt_serv_struct, entry);
	    printk("RT-Serv: Server %s is still in use!!!\n",srv->name);
	    unclean++;
	}
	
	remove_proc_entry("servers",0);
	rt_free_srq(nrt_serv_srq);
	rtos_task_delete(&irq_brk);
	rtos_event_delete(&irq_brk_sync);
	
	if (unclean)
		printk("RT-Serv:%d Servers were not cleaned,\
					system reboot required!!!\n", unclean);
	else
		printk("RT-Serv: Real-Time Server Module unmounted\n");
}

module_init(serv_module_init);
module_exit(serv_module_exit);

MODULE_LICENSE("GPL");

#ifdef CONFIG_KBUILD
EXPORT_SYMBOL(rt_serv_init);
EXPORT_SYMBOL(rt_serv_delete);
EXPORT_SYMBOL(rt_serv_sync);
EXPORT_SYMBOL(rt_request_pend);
EXPORT_SYMBOL(rt_request_delete);
EXPORT_SYMBOL(rt_event_init);
EXPORT_SYMBOL(rt_event_pend);
EXPORT_SYMBOL(rt_irq_broker_sync);
#endif /* CONFIG_KBUILD */






