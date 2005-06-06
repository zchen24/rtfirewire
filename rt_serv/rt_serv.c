/**
 * @ingroup serv
 * @file
 *
 * Implementation of the real-time server module. 
 */
 
/**
 * @defgroup serv Real-Time Server module 
 * 
 * (This is legacy documentation)
 * Interrupt handler consists of two parts: TopHalf and BottomHalf. 
 * The former stays in the ISR context, which means the scheduler is blocked, 
 * therefore it only contains minimum code which is necessary to 
 * deliver the task to BottomHalf. It is the BottomHalf that does the main task 
 * of processing hardware interrupt. 
 *
 * This module implements the server for dealing with BH of different priority in a 
 * real-time context. All the BH is represented via the bh_task struct, which is prioritized. 
 *  
 * To write a driver using irqbh_server, one needs to initialize one bh_task struct for each bottomhalf
 * routine (of each irq event) in the initialization phase of the driver, Also to assign each bh_task a appropriate
 * priority, according to the realtime needs of the irq event. 
 *
 * All the bh_task structs are registered in the global viewable bh_list, which can be monitored via /proc/rtai/bh_tasks
 * 
 * A user space real-time monitoring tool is being planned to be designed, properly intergated into the 
 * monitoring tool for the whole FireWire Stack. 
 */
 
 #include <linux/module.h>
 #include <linux/init.h>
 #include <linux/slab.h>
 #include <linux/list.h>
 #include <linux/proc_fs.h>
 #include <linux/spinlock.h>
 
 #include <rtos_primitives.h> 
 #include <rt_serv.h>
 
 #define IRQ_BROKER_PRI 10
 #define SERVER_BASE_PRI 20
 
 LIST_HEAD(server_list);
 LIST_HEAD(event_list);
 static rwlock_t server_list_lock = RW_LOCK_UNLOCKED;
 spinlock_t event_list_lock = SPIN_LOCK_UNLOCKED;
 rtos_event_t irq_brk_sync;
 
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
			rtos_event_signal(evt->sync);
		}
		INIT_LIST_HEAD(&event_list);
		rtos_spin_unlock_irqrestore(&event_list_lock,flags);
	}
}

 void srv_worker(int data)
 {
	struct rt_serv_struct *srv = (struct rt_serv_struct*)data;
#ifdef SERVER_MODULE_CHECKED
	RTIME start_job, end_job,last_exec_time;
#endif
	
	while(1){
		if (RTOS_EVENT_ERROR(rtos_event_wait(&srv->event)))
			return;
		
		//~ rtos_print("%s:take a request\n", srv->name);
#ifdef SERVER_MODULE_CHECKED
		start_job = rt_get_time();
#endif
		srv->routine(srv->data);
#ifdef SERVER_MODULE_CHECKED
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
 * @ingroup serv
 * @anchor rt_serv_init
 * Initialize a server
 *
 * @param name is the name of the newly allocated bh struct
 * @param routine is the real routine for server
 * @param data is the parameter of bh_routine
 * @param priority is the priority of realtime task in rtai
 * @param stack_size is the stack_size of realtime task in rtai
 * @param uses_fpu is the fpu usage flag of realtime task in rtai
 *  
 * @return the pointer to bh_task struct on success
 *	 - @b NULL on failure.
 */ 
struct rt_serv_struct *rt_serv_init(unsigned char *name, void (*routine)(unsigned long), 
						unsigned long data, int priority)
{
	struct rt_serv_struct *srv;
	srv = kmalloc(sizeof(struct rt_serv_struct), GFP_KERNEL);
	if(!srv)
		return NULL;
	
	srv->routine = routine;
	srv->data = data;
	
	srv->priority = SERVER_BASE_PRI + priority;
	strcpy(srv->name, name);
	rtos_event_init(&srv->event);
	list_add_tail(&srv->entry, &server_list);
	
	if(rtos_task_init(&srv->task, srv_worker, (int)srv, srv->priority)) {
		rtos_print("RT-Serv: failed to initialize server %s!!\n", srv->name);
		kfree(srv);
		return NULL;
	}

	rtos_print("RT-Serv: server %s created\n", srv->name);
	
	return srv;
}

void rt_serv_delete(struct rt_serv_struct *srv)
{
	if(srv){
		rtos_task_delete(&srv->task);
		list_del(&srv->entry);
		rtos_print("RT-Serv:server %s removed\n", srv->name);
		kfree(srv);
	}
}

struct rt_event_struct *rt_event_init(void)
{
	struct rt_event_struct *evt;
	evt = kmalloc(sizeof(*evt), GFP_KERNEL);
	if(!evt)
		return NULL;
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
	kfree(evt);
}
	
void rt_irq_broker_wake(void)
{
	rtos_event_signal(&irq_brk_sync);
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
	
	read_lock(&server_list_lock);

#ifdef SERVER_MODULE_CHECKED
	PUTF("server\t\tpriority\tmaxet\tminet\tresponses\n");
	list_for_each(lh, &server_list) {
		srv = list_entry(lh, struct rt_serv_struct, entry);
		PUTF("%s\t\t%d\t%llx\t%llx\t%d\n", srv->name, srv->priority,
							srv->max_exec_time, srv->min_exec_time, srv->resp_nr);
	}
#else
	PUTF("server\t\tpriority\n");
	list_for_each(lh, &server_list) {
		srv = list_entry(lh, struct rt_serv_struct, entry);
		PUTF("%s\t\t%d\n", srv->name, srv->priority);
	}
#endif
	
done_proc:
	read_unlock(&server_list_lock);

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
	const unsigned char *name="IRQ Broker";
	
	rtos_event_init(&irq_brk_sync);
	
	if(rtos_task_init(&irq_brk, irqbrk_worker, 0, IRQ_BROKER_PRI)){
		printk("RT-Serv:Failed to init irq broker task\n");
		return -ENOMEM;
	}
	
	proc_entry = create_proc_entry("rt-server", S_IFREG | S_IRUGO | S_IWUSR, 0);
	if(!proc_entry) {
		printk("RT-Serv:failed to create proc entry!\n");
		rtos_task_delete(&irq_brk);
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
	
	list_for_each(lh, &server_list){
	    srv = list_entry(lh, struct rt_serv_struct, entry);
	    printk("RT-Serv: Server %s is still in use!!!\n",srv->name);
	    unclean++;
	}
	
	remove_proc_entry("rt-server",0);
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

EXPORT_SYMBOL(rt_serv_init);
EXPORT_SYMBOL(rt_serv_delete);
EXPORT_SYMBOL(rt_event_init);
EXPORT_SYMBOL(rt_event_pend);
EXPORT_SYMBOL(rt_event_delete);
EXPORT_SYMBOL(rt_irq_broker_wake);






