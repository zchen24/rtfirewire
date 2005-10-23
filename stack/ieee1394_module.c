/* rtfirewire/stack/ieee1394_module.c
 *
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <ieee1394_chrdev.h>
#include <ieee1394_core.h>
#include <ieee1394_transactions.h>
#include <highlevel.h>
#include <hosts.h>
#include <csr.h>
#include <csr1212.h>
#include <config_roms.h>
#include <dma.h>
#include <iso.h>
//~ #include <oui.c>

int __init ieee1394_stack_init(void)
{
	int ret;
	
	ret = ieee1394_chrdev_init();
	if(ret<0)
		goto errout;
	
	ret = ieee1394_core_init();
	if(ret)
		goto errout_release_chrdev;
	
	printk("RT-Firewire:Real-Time FireWire Stack Initialized!\n");

	return ret;
	
errout_release_chrdev:
	ieee1394_chrdev_release();
errout:
	return ret;
}

void __exit ieee1394_stack_exit(void)
{
	ieee1394_core_cleanup();
	ieee1394_chrdev_release();
	printk("RT-Firewire:Real-Time Firewire Stack unloaded\n");
}

module_init(ieee1394_stack_init);
module_exit(ieee1394_stack_exit);

MODULE_LICENSE("GPL");


/* Exported symbols */
/** ieee1394_chrdev.c **/
EXPORT_SYMBOL(ieee1394_register_ioctls);
EXPORT_SYMBOL(ieee1394_unregister_ioctls);

/** hosts.c **/
EXPORT_SYMBOL(host_alloc);
EXPORT_SYMBOL(host_free);
EXPORT_SYMBOL(host_register);
EXPORT_SYMBOL(host_unregister);
EXPORT_SYMBOL(host_alloc_name);

/** ieee1394_core.c **/
EXPORT_SYMBOL(hpsb_set_packet_complete_task);
EXPORT_SYMBOL(hpsb_alloc_packet);
EXPORT_SYMBOL(hpsb_free_packet);
EXPORT_SYMBOL(hpsb_send_phy_config);
EXPORT_SYMBOL(hpsb_send_packet);
EXPORT_SYMBOL(hpsb_packet_sent);
EXPORT_SYMBOL(hpsb_send_packet_and_wait);
EXPORT_SYMBOL(hpsb_reset_bus);
EXPORT_SYMBOL(hpsb_bus_reset);
EXPORT_SYMBOL(hpsb_selfid_complete);
EXPORT_SYMBOL(hpsb_packet_received);
EXPORT_SYMBOL(hpsb_selfid_received);
EXPORT_SYMBOL(rtfw_procfs_entry);


/** ieee1394_transactions.c **/
EXPORT_SYMBOL(hpsb_get_tlabel);
EXPORT_SYMBOL(hpsb_free_tlabel);
EXPORT_SYMBOL(hpsb_make_readpacket);
EXPORT_SYMBOL(hpsb_make_writepacket);
EXPORT_SYMBOL(hpsb_make_streampacket);
EXPORT_SYMBOL(hpsb_make_lockpacket);
EXPORT_SYMBOL(hpsb_make_lock64packet);
EXPORT_SYMBOL(hpsb_make_phypacket);
EXPORT_SYMBOL(hpsb_make_isopacket);
EXPORT_SYMBOL(hpsb_read);
EXPORT_SYMBOL(hpsb_write);
EXPORT_SYMBOL(hpsb_lock);
EXPORT_SYMBOL(hpsb_packet_success);

/** highlevel.c **/
EXPORT_SYMBOL(hpsb_register_highlevel);
EXPORT_SYMBOL(hpsb_unregister_highlevel);
EXPORT_SYMBOL(hpsb_register_addrspace);
EXPORT_SYMBOL(hpsb_unregister_addrspace);
EXPORT_SYMBOL(hpsb_allocate_and_register_addrspace);
EXPORT_SYMBOL(hpsb_listen_channel);
EXPORT_SYMBOL(hpsb_unlisten_channel);
EXPORT_SYMBOL(hpsb_get_hostinfo);
EXPORT_SYMBOL(hpsb_create_hostinfo);
EXPORT_SYMBOL(hpsb_destroy_hostinfo);
EXPORT_SYMBOL(hpsb_set_hostinfo_key);
EXPORT_SYMBOL(hpsb_get_hostinfo_bykey);
EXPORT_SYMBOL(hpsb_set_hostinfo);
EXPORT_SYMBOL(highlevel_add_host);
EXPORT_SYMBOL(highlevel_remove_host);
EXPORT_SYMBOL(highlevel_host_reset);

/** dma.c **/
EXPORT_SYMBOL(dma_prog_region_init);
EXPORT_SYMBOL(dma_prog_region_alloc);
EXPORT_SYMBOL(dma_prog_region_free);
EXPORT_SYMBOL(dma_region_init);
EXPORT_SYMBOL(dma_region_alloc);
EXPORT_SYMBOL(dma_region_free);
EXPORT_SYMBOL(dma_region_mmap);
EXPORT_SYMBOL(dma_region_offset_to_bus);
EXPORT_SYMBOL(dma_region_sync_for_cpu);
EXPORT_SYMBOL(dma_region_sync_for_device);

/** iso.c **/
EXPORT_SYMBOL(hpsb_iso_xmit_init);
EXPORT_SYMBOL(hpsb_iso_recv_init);
EXPORT_SYMBOL(hpsb_iso_xmit_start);
EXPORT_SYMBOL(hpsb_iso_recv_start);
EXPORT_SYMBOL(hpsb_iso_recv_listen_channel);
EXPORT_SYMBOL(hpsb_iso_recv_unlisten_channel);
EXPORT_SYMBOL(hpsb_iso_recv_set_channel_mask);
EXPORT_SYMBOL(hpsb_iso_stop);
EXPORT_SYMBOL(hpsb_iso_shutdown);
EXPORT_SYMBOL(hpsb_iso_xmit_queue_packet);
EXPORT_SYMBOL(hpsb_iso_xmit_sync);
EXPORT_SYMBOL(hpsb_iso_recv_release_packets);
EXPORT_SYMBOL(hpsb_iso_n_ready);
EXPORT_SYMBOL(hpsb_iso_packet_sent);
EXPORT_SYMBOL(hpsb_iso_packet_received);
EXPORT_SYMBOL(hpsb_iso_callback);
EXPORT_SYMBOL(hpsb_iso_recv_flush);

/** csr1212.c **/
EXPORT_SYMBOL(csr1212_create_csr);
EXPORT_SYMBOL(csr1212_init_local_csr);
EXPORT_SYMBOL(csr1212_new_immediate);
EXPORT_SYMBOL(csr1212_new_directory);
EXPORT_SYMBOL(csr1212_associate_keyval);
EXPORT_SYMBOL(csr1212_attach_keyval_to_directory);
EXPORT_SYMBOL(csr1212_new_string_descriptor_leaf);
EXPORT_SYMBOL(csr1212_detach_keyval_from_directory);
EXPORT_SYMBOL(csr1212_release_keyval);
EXPORT_SYMBOL(csr1212_destroy_csr);
EXPORT_SYMBOL(csr1212_read);
EXPORT_SYMBOL(csr1212_generate_csr_image);
EXPORT_SYMBOL(csr1212_parse_keyval);
EXPORT_SYMBOL(csr1212_parse_csr);
EXPORT_SYMBOL(_csr1212_read_keyval);
EXPORT_SYMBOL(_csr1212_destroy_keyval);

	

