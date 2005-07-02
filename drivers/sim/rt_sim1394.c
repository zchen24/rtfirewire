/* rtfirewire/drivers/fake/rt_sim1394.c
 * simulated FireWire adapter for RT-FireWire stack. 
 *
 * Copyright (C) 2005 Zhang Yuchen <y.zhang-4@student.utwente.nl>
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
 #include <linux/module.h>
 #include <linux/config.h>
 #include <linux/init.h>
 
 #include <hosts.h>
 #include <rt1394_sys.h>
  
 static struct hpsb_host *simfwhost;
	
 static int sim1394_transmit_packet(struct hpsb_host *h, struct hpsb_packet *p)
{
        return 0;
}

static int sim1394_devctl(struct hpsb_host *h, enum devctl_cmd c, int arg)
{
        return -1;
}

static int sim1394_isoctl(struct hpsb_iso *iso, enum isoctl_cmd command, unsigned long arg)
{
	return -1;
}

 static struct hpsb_host_driver sim1394_driver = {
	 .owner	=	THIS_MODULE,
	 .name	=	"Simulated FireWire adapter",
	 .transmit_packet	=	sim1394_transmit_packet,
	 .devctl	=	sim1394_devctl,
	 .isoctl	=	sim1394_isoctl,
 };
  
 static int sim1394_init(void)
 {
	 int ret;
	
	 simfwhost=host_alloc(sizeof(sim1394_driver));
	 if(simfwhost==NULL)
		 return -ENOMEM;
	 
	 simfwhost->driver = &sim1394_driver;
	 host_alloc_name(simfwhost,"sim_host");
	 RTOS_SET_MODULE_OWNER(simfwhost);
	 simfwhost->vers=RTDEV_VERS_2_1;
	 simfwhost->type = HOST_TYPE_SIM1394;
	 simfwhost->node_id = 0xffc0; //bus address is all "1". 
	 
	 ret=host_register(simfwhost);
	 if(ret)
		 return -EBUSY;
	 
	 return ret;
 }
 
 static void sim1394_exit(void)
 {
	 host_unregister(simfwhost);
	 host_free(simfwhost);
 }
 
 module_init(sim1394_init);
 module_exit(sim1394_exit);
 
 MODULE_LICENSE("GPL");
 
 
 
 
 