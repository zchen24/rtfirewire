/* rtfirewire/drivers/fake/rt_sim1394.c
 * simulated FireWire adapter for RT-FireWire stack. 
 *
 * Copyright (C) 2005 Zhang Yuchen <yuchen623@gmail.com>
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
 
 
 #define NUM_OF_HOSTS 1
 
 static struct hpsb_host *simfwhost[NUM_OF_HOSTS];

 
 static int sim1394_transmit_packet(struct hpsb_host *host, struct hpsb_packet *packet)
{
        int size;
	struct hpsb_host *recvhost;
	struct hpsb_packet *pkt;

	size= packet->header_size/4;
	size = (size > 4 ? 4 : size);

#ifdef CONFIG_IEEE1394_VERBOSEDEBUG
	int i;
	rtos_print("Sim1394_xmit:");
	for (i = 0; i < size; i++)
		rtos_print(" %08x", packet->header[i]);
	rtos_print("\n");
#endif
	
	{

		packet->xmit_time = rtos_get_time();
		
		///hack
		switch(packet->node_id){
			case 0xffc0:
					//send the packet to simulated adapter 0
				        recvhost=simfwhost[0];
					break;
			case 0xffc1:
					//send the packet to simulated adapter 1
					recvhost=simfwhost[1];
					break;
			default:
					HPSB_ERR("illegal node id!!!\n");
					return -EINVAL;
		}
		
		pkt = hpsb_alloc_packet(0, &recvhost->pool, packet->pri);
		if(!pkt)
			return -ENOMEM;
		
		pkt->data_size = packet->data_size;
		pkt->header_size = packet->header_size;

                memcpy(pkt->header, packet->header, packet->header_size);

		if(packet->data_size)
			memcpy(pkt->data, packet->data, packet->data_size);
		
		pkt->write_acked = (((packet->data[packet->data_size/4-1]>>16) & 0x1f)
				== 0x11) ? 1 : 0;
		pkt->pri = packet->pri;
		pkt->tcode = packet->tcode;
		pkt->host = recvhost;
		
		
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
 