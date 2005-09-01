#ifndef __CROSS_LINUX_H
#define  __CROSS_LINUX_H

#include <rt1394_config.h>
#include <linux/list.h>

#ifdef LINUX_VERSION_24

struct work_struct {
	unsigned long pending;
	struct list_head entry;
	void (*func) (void *);
	void *data;
	void *wq_data;
	struct timer_list timer;
};


/**
 * initialize a work struct's function and data 
 */
#define PREAPRE_WORK(_work, _func, _data) \
	do {\
		(_work)->func = _func; \
		(_work)->data = _data; \
	} while(0)

/**
 * initialize all of a work struct
 */
#define INIT_WORK(_work, _func, _data) \
	do { \
		INIT_LIST_HEAD(&(_work)->entry); \
		(_work)->pending = 0; \
		PREPARE_WORK((_work), (_func), (_data)); \
		init_timer(&(_work)->timer); \
	} while(0)
	


#define irqs_diabled() 	\
({	\
	unsigned long flags;	\
	local_save_flags(flags); \
	!(flags & (1<<9));	\
})

#define in_atomic

#endif /*LINUX_VERSION_24*/
#endif /*__CROSS_LINUX_H*/

