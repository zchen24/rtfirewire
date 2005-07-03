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
 #include <ieee1394_core.h>
 #include <ieee1394.h>
 
 #define CONFIG_SIMNET_VERBOSE 1 //this should be an option in auto configuration. 

#ifdef CONFIG_SIMNET_VERBOSE
#define DEBUGP(fmt,args...) \
	rtos_print("SIMNET:"fmt"\n",##args)
#else
#define DEBUGP(fmt,args...)
#endif
  
 #define NUM_OF_HOSTS 2
 
 static struct hpsb_host *simfwhost[NUM_OF_HOSTS];

 
 static int sim1394_transmit_packet(struct hpsb_host *host, struct hpsb_packet *packet)
{
        int i, size, ret;

	size= packet->header_size/4;
	size = (size > 4 ? 4 : size);

#ifdef CONFIG_SIMNET_VERBOSE
	rtos_print("Sim1394_xmit:");
	for (i = 0; i < size; i++)
		rtos_print(" %08x", packet->header[i]);
	rtos_print("\n");
#endif
	
	{
		rtos_time_t probe;
		rtos_get_time(&probe);
		packet->xmit_time = rtos_time_to_nanosecs(&probe);
		
						
		struct hpsb_packet *pkt = hpsb_alloc_packet(0, &host->pool);
		if(!pkt)
			return -ENOMEM;
		
		size_t len = packet->data_size + packet->header_size;
		pkt->data_size = len;

                memcpy(pkt->data, packet->header, packet->header_size);

		if(packet->data_size)
			memcpy(((u8*)pkt->data)+packet->header_size, packet->data, packet->data_size);
		
		//~ host->pkt->ack = ((data[size/4-1]>>16)&0x1f
				//~ == 0x11) ? 1 : 0;
		pkt->ack = 0;
		pkt->pri = packet->pri;
				
		//hack!!!
		switch(packet->node_id){
			case 0xffc0:
					//send the packet to simulated adapter 0
				        pkt->host=simfwhost[0];
					break;
			case 0xffc1:
					//send the packet to simulated adapter 1
					pkt->host=simfwhost[1];
					break;
			default:
					DEBUGP("illegal node id!!!\n");
					break;
		}
		
		//report back to caller
		hpsb_packet_sent(host, packet, packet->expect_response ? ACK_PENDING : ACK_COMPLETE);
		
		hpsb_packet_received(pkt);

	}
	
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
	 int ret, i;
	
	for(i=0;i<NUM_OF_HOSTS;i++){
		
		//initialize the host
		simfwhost[i]=host_alloc(sizeof(sim1394_driver));
		if(simfwhost[i]==NULL)
			return -ENOMEM;
	 
		simfwhost[i]->driver = &sim1394_driver;
		host_alloc_name(simfwhost[i],"sim_host%d");
		simfwhost[i]->vers=RTDEV_VERS_2_1;
		simfwhost[i]->type = HOST_TYPE_SIM1394;
		simfwhost[i]->node_id = 0xffc0+i; //bus address is all "1". 
	 
		ret=host_register(simfwhost[i]);
		if(ret)
			return -EBUSY;
	}
	
	return ret;
 }
 
 static void sim1394_exit(void)
 {
	int i;
	 for(i=0;i<NUM_OF_HOSTS;i++){
		host_unregister(simfwhost[i]);
		host_free(simfwhost[i]);
	}
 }
 
 module_init(sim1394_init);
 module_exit(sim1394_exit);
 
 MODULE_LICENSE("GPL");
 
 
 
 
 
