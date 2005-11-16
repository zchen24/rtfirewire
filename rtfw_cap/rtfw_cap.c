/*  Real-Time Packet Capturing module for RT-FireWire network
 * 	adapted from rtcap in RTnet (Jan Kiszka <jan.kiszka@web.de>)
 *
 *  Copyright (C)  2005 Zhang Yuchen <yuchen623@gmail.com>
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
 
 
 #include <linux/config.h>
 #include <linux/module.h>
 #include <rtpkbuff.h>
 
 static int pool_capc = 100;
 MODULE_PARM(pool_capc, "i");
 MODULE_PARM_DESC(pool_capc, "Capacity of memory pool in Cap module (default = 100)");
 
 struct rtpkb_pool Cap_pool;
 
 struct rtpkb *queue_head;
 struct rtpkb *queue_tail;
 int queue_length;
 
 void rtcap_Capturepacket(struct rtpkb *pkb){
 	if(queue_head == NULL)
 		queue_head = queue_tail = pkb;
 	else
 		queue_tail->next_cap = pkb;
 		
 	queue_length++;	
 }
 
 struct rtpkb* rtcap_Requestpacket(void){
 	struct rtpkb *ret = NULL;
 	if(queue_head != NULL){
		ret = queue_head;
		queue_head = queue_head->next;
		if(queue_head ==  NULL)
			queue_tail = NULL;
 	}
 	return ret;	
 }
 
 
 int __init rtcap_init(void)
 {
 	int ret=0, i;
 	
 	i = rtpkb_pool_init(&Cap_pool,pool_capc);
 	if(i < pool_capc){
 		//there are not enough memory to build up the Cap pool
 		printk("Cap: Only %d buffers have been allocated, module exits\n", i);
 		rtpkb_pool_release(&Cap_pool);
 		goto error;	
 	}
	
	rtpkbuff_SetCap(rtcap_Capturepacket,&Cap_pool);
	
	printk("Packet Capturing module successfully loaded!\n");
	return 0;
	
 error:
 	return ret;	
 }
 
 void rtcap_cleanup(void)
 {
 	struct rtpkb *temp;
 	
 	for(temp = queue_head; temp != NULL; temp = temp->next)
 	{
 		kfree_rtpkb(temp);	
 	}
 	rtpkb_pool_release(&Cap_pool);
 	
 	rtpkbuff_UnsetCap();
 	
 	printk("Packet Capturing module successfully unloaded\n");
 			
 }
 
 module_init(rtcap_init);
 module_exit(rtcap_cleanup);
 
 EXPORT_SYMBOL(rtcap_Requestpacket);
 