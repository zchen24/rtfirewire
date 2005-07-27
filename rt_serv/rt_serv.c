/**
 * @file 
 * Implementation of Real-Time Server Module
 *
 * @note Copyright (C) 2005 Zhang Yuchen <yuchen623@gmail.com>
 * 
 * @ingroup rtserver
 */

 #include <linux/module.h>
 #include <linux/init.h>
 #include <linux/slab.h>
 #include <linux/list.h>
 #include <linux/proc_fs.h>
 #include <linux/spinlock.h>
 
 #include <rtdm/rtdm_driver.h>
 
 #include <rt_serv.h>
 
 /*!
   *@anchor irq_broker_pri @name irq_broker_pri
   * Priority of Interrupt Service Broker
   */
 #define IRQ_BROKER_PRI 	RTDM_TASK_HIGHEST_PRIORITY+2
 
 #define RTOS_LINUX_PRIORITY	0xFFFF
 
 #define RTOS_TIME_LIMIT 0x7FFFFFFFFFFFFFFFLL 
  
 LIST_HEAD(rt_servers_list);
 LIST_HEAD(nrt_servers_list);
 LIST_HEAD(event_list);
 
 static rwlock_t servers_list_lock = RW_LOCK_UNLOCKED;
 //~ static int nrt_serv_srq;

 rtdm_event_t irq_brk_sync;

 spinlock_t event_list_lock = SPIN_LOCK_UNLOCKED;
 rtdm_task_t irq_brk;
 
 /* Internal Proc of irq broker */
 void irqbrk_worker(void *data)
 {
	struct list_head *lh, *tmp;
	struct rt_event_struct *evt;
	unsigned long flags;
		
	RTSERV_NOTICE("irq broker started\n");
	while(1){
		int ret = rtdm_event_wait(&irq_brk_sync, 0);
		if(ret < 0){
			RTSERV_ERR("interrupt broker encountered err: %d\n", ret);
			return;
		}
			
		rtdm_lock_get_irqsave(&event_list_lock, flags);
		list_for_each_safe(lh, tmp, &event_list){
			evt = list_entry(lh, struct rt_event_struct, hook);

			RTSERV_NOTICE("interrupt event %s is being handled\n", evt->name);

			if(evt->proc)
				evt->proc(evt->data);
			else
				RTSERV_ERR("interrupt event has no routine!!!\n");
		}
		INIT_LIST_HEAD(&event_list);
		rtdm_lock_put_irqrestore(&event_list_lock,flags);
	}
 } 

 /*!
   * @brief Initialize interrupt event.
   * 
   * @param[in, out] evt Address of event structure.
   * @param[in] name. Name of the event, normally indicating the interruptting device. 
   * @param[in] proc. BottomHalf Interrupt handler
   * @param[in] data. Parameter to pass to the BottomHalf handler.
   */
 void rt_event_init(struct rt_event_struct *evt, char *name, 
					void (*proc)(unsigned long), 
					unsigned long data)
 {
	INIT_LIST_HEAD(&evt->hook);
	evt->data = data;
	evt->proc = proc;
	strncpy(evt->name, name, 32);
 }

/*!
   * @brief Pend a new interrupt event.
   *
   * @param[in] evt. Address of the event strucutre.
   */ 
 void rt_event_pend(struct rt_event_struct *evt)
 {
	rtdm_lock_get(&event_list_lock);
	list_add_tail(&evt->hook, &event_list);
	rtdm_lock_put(&event_list_lock);
 }

 /*!
   * @brief Delete an interrupt event.
   *
   * @param[in] evt. Address of the event strucutre.
   */ 
 void rt_event_delete(struct rt_event_struct *evt)
 {
	rtdm_lock_get(&event_list_lock);
	list_del(&evt->hook);
	rtdm_lock_put(&event_list_lock);
 }
	
 /*!
   * @brief Synchronize the irq broker.
   */
 void rt_irq_broker_sync(void)
 {
	rtdm_event_signal(&irq_brk_sync);
 } 

/*!
  *@brief Synchronize the server.
  * 
  *@param[in] srv Address of the server structure.
  * 
  * In case the Server is a non real-time one in Linux,
  * this function only pend a SRQ(Software Request) 
  * from real-time domain to Linux; while if the Server
  * is real-time one, this function unblockes the Server
  * task. 
  */
 void rt_serv_sync(struct rt_serv_struct *srv)
 {
	struct rt_request_struct *req;
	req = srv->requests_list.next;
	if(req==&srv->requests_list){
		//fake sync
		RTSERV_ERR("fake sync!\n");
	}
	
	RTSERV_NOTICE("sync server %s\n", srv->name);
	 if(srv->priority==RTOS_LINUX_PRIORITY){
		 RTSERV_NOTICE("non real-time server in Linux not supported yet\n");
		//~ rt_pend_linux_srq(nrt_serv_srq);
	}else{
		int err = rtdm_task_unblock(&srv->task);
		if(!err)
			RTSERV_ERR("unblocking server %s failed:%d\n",
						srv->name, err);
	}
}

/*!
  * @brief Pend a request to server.
  * 
  * @param[in,out] req, Address of allocated request structure
  * @param[in] name, Name of the request
  * @param[in] data, Parameter to pass to the proc of server.
  * @param[in] delay_time, Time between queuing the request and servicing it. 
  * @param[in] callback, Callback proc after servicing the request.
  * @param[in] callback_data, Parameter to pass to the callback proc. 
  *
  * @return Address of Request Object on Success; otherwise NULL. 
  *
  * The Request object is fetched from the object pool of Server to avoid undeterministic 
  * run-time allocation. In case the Server is non real-time in Linux, this function only queues
  * the Request to the end; while in case the Server is real-time, this function queues the Request
  * in a position with respect to the firing time. 
  * 
  * Environments:
  *
  * This service can be called from:
  *
  * - Kernel module initialization/cleanup code
  * - Kernel-based task
  * - User-space task (RT, non-RT)
  *
  * Rescheduling: never.
  */
struct rt_request_struct *rt_request_pend(struct rt_serv_struct *srv, unsigned long data, 
					__s64	delay_time,
					void (*callback)(struct rt_request_struct *, unsigned long),
					unsigned long callback_data,
					unsigned char *name)
{
	int id = atomic_read(&srv->pending_req);
	if(id == MAX_REQ){
		RTSERV_ERR("server[%s] reaches max request number\n", srv->name);
		return NULL;
	}
	
	struct rt_request_struct *req = srv->reqobj_pool_head.next;
	req->prev->next = req->next;
	req->next->prev = req->prev;
	
	if(delay_time > 0){
		req->firing_time = rtdm_clock_read() + delay_time;
	}else{
		req->firing_time = rtdm_clock_read();
	}
	
	req->data = data;
	req->callback = callback;
	req->callback_data = callback_data;
	if(name)
		strncpy(req->name, name, 32);
	
	unsigned long flags;
	if(srv->priority == RTOS_LINUX_PRIORITY){
		rtdm_lock_get_irqsave(&srv->requests_list_lock,flags);
		req->next = &srv->requests_list;
		req->prev = srv->requests_list.prev;
		req->prev->next = req->next->prev = req;
		rtdm_lock_put_irqrestore(&srv->requests_list_lock,flags);
		atomic_inc(&srv->pending_req);
	}else{
		rtdm_lock_get_irqsave(&srv->requests_list_lock,flags);
		
		struct rt_request_struct *tmpreq = srv->requests_list.next;
		
		//find the previous request which requires just later service
		//than the request in concern. 
		do {
			if(tmpreq->firing_time > req->firing_time)
				break;
			
			tmpreq = tmpreq->next;
		}while(tmpreq != &srv->requests_list);
		
		//add new request before tmpreq
		req->next = tmpreq;
		req->prev = tmpreq->prev;
		req->prev->next = req->next->prev = req;
		
		rtdm_lock_put_irqrestore(&srv->requests_list_lock,flags);
		atomic_inc(&srv->pending_req);
	}
	
	return req;				
}

/*!
 * @brief Delate a request from the queue of Server
 * 
 * @param[in] srv Address of the Server
 * @param[in] req Address of the Request
 *
 * In case the Server is real-time one and the Request deleted is the head of 
 * the queue, this function unblockes the Server task and possibly is followed by
 * a rescheduling. 
 *
 * @note the deleted Request object is returned to the pool.
 * 
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task (RT, non-RT)
 *
 * Rescheduling: possible.
 * 
 */
void rt_request_delete(struct rt_serv_struct *srv, struct rt_request_struct *req)
{
	unsigned long flags;
	
	rtdm_lock_get_irqsave(&srv->requests_list_lock,flags);
	//get request out of the pending queue	 
	req->prev->next = req->next;
	req->next->prev = req->prev;
	atomic_dec(&srv->pending_req);
	rtdm_lock_put_irqrestore(&srv->requests_list_lock,flags);
	
	if(srv->priority != RTOS_LINUX_PRIORITY && req->prev == &srv->requests_list) {
		rtdm_task_unblock(&srv->task);
	}
	
	//finally, queue the req object back to our free object pool
	req->next = &srv->reqobj_pool_head;
	req->prev = srv->reqobj_pool_head.prev;
	req->next->prev = req->prev->next = req;
}


/*Internal working routine of real-time Servers*/
 void rt_serv_worker(void *data)
 {
	struct rt_serv_struct *srv = (struct rt_serv_struct*)data;

	while(1){	
		if(srv->firing_time > rtdm_clock_read())
					rtdm_task_sleep_until(srv->firing_time);

		while(1){
					struct rt_request_struct *req = srv->requests_list.next;
							
					if(req->firing_time > rtdm_clock_read()){
						srv->firing_time = req->firing_time;
						break;
					}
					
					//get request out of pending queue	 
					req->prev->next = req->next;
					req->next->prev = req->prev;
								
					if(srv->proc)
						srv->proc(req->data);
					else
						RTSERV_ERR("%s has no routine!!!\n", srv->name);
		
					//call the callback 
					if(req->callback)
						req->callback(req, req->callback_data);
			
					//return object to pool
					req->next = &srv->reqobj_pool_head;
					req->prev = srv->reqobj_pool_head.prev;
					req->next->prev = req->prev->next = req;
		
					atomic_dec(&srv->pending_req);
								
		}
	}
 }
 
/*Internal working routine of non real-time Servers in Linux*/
 void nrt_serv_worker(void)
 {
	 struct rt_serv_struct *srv;
	 struct list_head *lh;
	 list_for_each(lh, &nrt_servers_list){
		 srv = list_entry(lh, struct rt_serv_struct, entry);
		
		 struct rt_request_struct *req;
		 req = srv->requests_list.next;
		 
		 //get request out of pending queue	 
		 req->prev->next = req->next;
		 req->next->prev = req->prev;
		 
		if(srv->proc)
				srv->proc(req->data);
			else
				RTSERV_ERR("%s has no routine!!!\n", srv->name);
		 
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


/*!
  * @brief Delete a Server
  * 
  * @param[in] srv Address of the Server
  *
  * @todo How to deal with un-serviced Request?
 */
void rt_serv_delete(struct rt_serv_struct *srv)
{
	if(srv){
		if(atomic_read(&srv->pending_req) != 0)
			RTSERV_ERR("server %s still has %d requests unanswered!\n", srv->name, 
							atomic_read(&srv->pending_req));
		if(srv->priority !=RTOS_LINUX_PRIORITY)
			rtdm_task_destroy(&srv->task);
		list_del(&srv->entry);
		RTSERV_NOTICE("server %s removed\n", srv->name);
		kfree(srv);
	}
}



/*!
  * @brief Initialize a Server
  *
  * @param[in] name. Name of the Server.
  * @param[in] priority. Priority of ther Server task
  * @param[in] proc. Process routine of ther Server.
  *
  * @return Address of new Server on Success; otherwise NULL. 
  */
struct rt_serv_struct *rt_serv_init(unsigned char *name, int priority, void (*proc)(unsigned long))
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
	
	srv->priority = (priority==-1) ? RTOS_LINUX_PRIORITY : priority;
	
	srv->proc = proc;
	
	atomic_set(&srv->pending_req, 0);
	
	srv->requests_list.next = srv->requests_list.prev = &srv->requests_list;
	srv->requests_list.firing_time = RTOS_TIME_LIMIT;
	sprintf(srv->requests_list.name, "list head");
	srv->requests_list_lock = SPIN_LOCK_UNLOCKED;
	
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
	}else{
		//real time server in rtai
		spin_lock(&servers_list_lock);
		list_add_tail(&srv->entry, &rt_servers_list);
		spin_unlock(&servers_list_lock);
	
		if(rtdm_task_init(&srv->task, name, rt_serv_worker, (void *)srv, srv->priority + RTDM_TASK_HIGHEST_PRIORITY,0)) {
			RTSERV_ERR("failed to initialize server %s!!\n", srv->name);
			rt_serv_delete(srv);
			return NULL;
		}	
	}

	RTSERV_NOTICE("%s in %s created\n", srv->name, (priority==-1)?"Linux":"RTAI");
	
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

	PUTF("server name\t\tpriority\tpending_req\n");
	list_for_each(lh, &rt_servers_list) {
		srv = list_entry(lh, struct rt_serv_struct, entry);
		PUTF("%s\t\t%d\t%d\n", srv->name, srv->priority, atomic_read(&srv->pending_req));
	}

	list_for_each(lh, &nrt_servers_list) {
		srv = list_entry(lh, struct rt_serv_struct, entry);
		PUTF("%s\t\t%d\t%d\n", srv->name, srv->priority, atomic_read(&srv->pending_req));
	}

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

	rtdm_event_init(&irq_brk_sync, 0);
	
	if(rtdm_task_init(&irq_brk, "irqbroker", irqbrk_worker, 0, IRQ_BROKER_PRI, 0)){
		RTSERV_ERR("failed to init irq broker task\n");
		rtdm_event_destroy(&irq_brk_sync);
		return -ENOMEM;
	}
	
	//srq for server in LInux
	//~ if((nrt_serv_srq = rt_request_srq(0, nrt_serv_worker, 0))<0){
		//~ RTSERV_ERR("no srq available in rtai\n");
		//~ return -ENOMEM;
	//~ }
	
	proc_entry = create_proc_entry("servers", S_IFREG | S_IRUGO | S_IWUSR, 0);
	if(!proc_entry) {
		RTSERV_ERR("failed to create proc entry!\n");
		//~ rt_free_srq(nrt_serv_srq);
		return -ENOMEM;
	}
	proc_entry->read_proc = serv_read_proc;
	
	RTSERV_NOTICE("real-Time Server Module Initialized!\n");

	return 0;
}

void serv_module_exit(void)
{
	struct list_head *lh;
	struct rt_serv_struct *srv;
	int unclean=0;
	
	list_for_each(lh, &rt_servers_list){
	    srv = list_entry(lh, struct rt_serv_struct, entry);
	    RTSERV_ERR("server %s is still in use!!!\n",srv->name);
	    unclean++;
	}
	
	list_for_each(lh, &nrt_servers_list){
	    srv = list_entry(lh, struct rt_serv_struct, entry);
	    RTSERV_ERR("server %s is still in use!!!\n",srv->name);
	    unclean++;
	}
	
	remove_proc_entry("servers",0);
	//~ rt_free_srq(nrt_serv_srq);
	rtdm_task_destroy(&irq_brk);
	rtdm_event_destroy(&irq_brk_sync);
	
	if (unclean)
		RTSERV_NOTICE("%d Servers were not cleaned,\
					system reboot required!!!\n", unclean);
	else
		RTSERV_NOTICE("real-Time Server Module unmounted\n");
}

module_init(serv_module_init);
module_exit(serv_module_exit);

MODULE_LICENSE("GPL");

EXPORT_SYMBOL(rt_serv_init);
EXPORT_SYMBOL(rt_serv_delete);
EXPORT_SYMBOL(rt_serv_sync);
EXPORT_SYMBOL(rt_request_pend);
EXPORT_SYMBOL(rt_request_delete);
EXPORT_SYMBOL(rt_event_init);
EXPORT_SYMBOL(rt_event_pend);
EXPORT_SYMBOL(rt_irq_broker_sync);






