/*
 * ohci1394.c - driver for OHCI 1394 boards
 *  Linkdriver for OHCI of RT-FireWire
 *  adapted from Linux 1394subsystem 
 * Copyright (C) 2005	Zhang Yuchen <y.zhang-4@student.utwente.nl>
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*********************** Legacy acknowledgments from Linux1394 *****************/
/*
 * Things known to be working:
 * . Async Request Transmit
 * . Async Response Receive
 * . Async Request Receive
 * . Async Response Transmit
 * . Iso Receive
 * . DMA mmap for iso receive
 * . Config ROM generation
 *
 * Things implemented, but still in test phase:
 * . Iso Transmit
 * . Async Stream Packets Transmit (Receive done via Iso interface)
 *
 * Things not implemented:
 * . DMA error recovery
 *
 * Known bugs:
 * . devctl BUS_RESET arg confusion (reset type or root holdoff?)
 *   added LONG_RESET_ROOT and SHORT_RESET_ROOT for root holdoff --kk
 */

/*
 * Acknowledgments:
 *
 * Adam J Richter <adam@yggdrasil.com>
 *  . Use of pci_class to find device
 *
 * Emilie Chung	<emilie.chung@axis.com>
 *  . Tip on Async Request Filter
 *
 * Pascal Drolet <pascal.drolet@informission.ca>
 *  . Various tips for optimization and functionnalities
 *
 * Robert Ficklin <rficklin@westengineering.com>
 *  . Loop in irq_handler
 *
 * James Goodwin <jamesg@Filanet.com>
 *  . Various tips on initialization, self-id reception, etc.
 *
 * Albrecht Dress <ad@mpifr-bonn.mpg.de>
 *  . Apple PowerBook detection
 *
 * Daniel Kobras <daniel.kobras@student.uni-tuebingen.de>
 *  . Reset the board properly before leaving + misc cleanups
 *
 * Leon van Stuivenberg <leonvs@iae.nl>
 *  . Bug fixes
 *
 * Ben Collins <bcollins@debian.org>
 *  . Working big-endian support
 *  . Updated to 2.4.x module scheme (PCI aswell)
 *  . Config ROM generation
 *
 * Manfred Weihs <weihs@ict.tuwien.ac.at>
 *  . Reworked code for initiating bus resets
 *    (long, short, with or without hold-off)
 *
 * Nandu Santhi <contactnandu@users.sourceforge.net>
 *  . Added support for nVidia nForce2 onboard Firewire chipset
 *
 */
 /**********************************************************************************/

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <asm/byteorder.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <linux/delay.h>

#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/irq.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/init.h>

#ifdef CONFIG_PPC_PMAC
#include <asm/machdep.h>
#include <asm/pmac_feature.h>
#include <asm/prom.h>
#include <asm/pci-bridge.h>
#endif

#include <rt1394_sys.h>
#include <csr1212.h>
#include <ieee1394.h>
#include <ieee1394_types.h>
#include <hosts.h>
#include <dma.h>
#include <iso.h>
#include <ieee1394_core.h>
#include <highlevel.h>
#include "rt_ohci1394.h"

#include <rt_serv.h>
#include <rtpkbuff.h>

#include <rtos_primitives.h>

#ifdef CONFIG_OHCI1394_DEBUG
	#define OHCI_NOTICE(fmt, args...) \
		rtos_print("%s: fw-host%d: " fmt, OHCI1394_DRIVER_NAME, ohci->host->ifindex, ## args)
	#define OHCI_NOTICE_G(fmt, args...) \
		rtos_print("%s: " fmt, OHCI1394_DRIVER_NAME, ## args)
#else
	#define OHCI_NOTICE(fmt, args...)
	#define OHCI_NOTICE_G(fmt, args...)
#endif

#define OHCI_ERR(fmt, args...) \
		rtos_print("%s: fw-host%d: " fmt, OHCI1394_DRIVER_NAME, ohci->host->ifindex, ## args)
#define OHCI_ERR_G(fmt, args...) \
		rtos_print("%s: " fmt, OHCI1394_DRIVER_NAME, ## args)
		
static char version[] __devinitdata =
	"OHCI driver for RT-FireWire project";

/* Module Parameters */
static int cards = 2;
MODULE_PARM(cards, "i");
MODULE_PARM_DESC(cards, "Number of cards to be steered by this driver (default  = 2).");
static int disable_irm = 0;
MODULE_PARM(disable_irm, "i");
MODULE_PARM_DESC(disable_irm, "Disable Isochronous Resource Manager Contending on local adapter (default = NO).");
static int phys_dma = 1;
MODULE_PARM(phys_dma, "i");
MODULE_PARM_DESC(phys_dma, "Enable dma for physical packets (default = 1).");

/**=========== Time Probing ============*/
static int timing_probe = 0;
MODULE_PARM(timing_probe, "i");
MODULE_PARM_DESC(timing_probe, "Enable time probing between tophalf and bottomhalf ISR (default = NO(0)).");
static int pacnt = 0;
static int pbcnt = 0;
struct timing_struct{
	__u64 paval;
	__u64 pbval;
} time_pair[10000];

static unsigned int cards_found;

static void dma_trm_routine(unsigned long data);
static void dma_trm_reset(struct dma_asyn_xmit *d);

static int alloc_dma_asyn_recv(struct ti_ohci *ohci, struct dma_asyn_recv *d,
			     enum context_type type, int ctx, int num_desc,
			     int buf_size,int split_buf_size, int context_base);
//static void stop_dma_asyn_recv(struct dma_asyn_recv *d);
static void free_dma_asyn_recv(struct dma_asyn_recv *d);

static int alloc_dma_asyn_xmit(struct ti_ohci *ohci, struct dma_asyn_xmit *d,
			     enum context_type type, int ctx, int num_desc,
			     int context_base);

static void ohci1394_pci_remove(struct pci_dev *pdev);

static unsigned hdr_sizes[] =
{
	3,	/* TCODE_WRITEQ */
	4,	/* TCODE_WRITEB */
	3,	/* TCODE_WRITE_RESPONSE */
	0,	/* ??? */
	3,	/* TCODE_READQ */
	4,	/* TCODE_READB */
	3,	/* TCODE_READQ_RESPONSE */
	4,	/* TCODE_READB_RESPONSE */
	1,	/* TCODE_CYCLE_START (???) */
	4,	/* TCODE_LOCK_REQUEST */
	2,	/* TCODE_ISO_DATA */
	4,	/* TCODE_LOCK_RESPONSE */
};

#ifndef __LITTLE_ENDIAN
/* Swap headers */
static inline void packet_swab(quadlet_t *data, int tcode)
{
	size_t size = hdr_sizes[tcode];

	if (tcode > TCODE_LOCK_RESPONSE || hdr_sizes[tcode] == 0)
		return;

	while (size--)
		data[size] = swab32(data[size]);
}
#else
/* Don't waste cycles on same sex byte swaps */
#define packet_swab(w,x)
#endif /* !LITTLE_ENDIAN */

/***********************************
 * IEEE-1394 functionality section *
 ***********************************/
static u8 get_phy_reg(struct ti_ohci *ohci, u8 addr)
{
	int i;
	unsigned long flags;
	quadlet_t r;

	rtos_spin_lock_irqsave (&ohci->phy_reg_lock, flags);

	reg_write(ohci, OHCI1394_PhyControl, (addr << 8) | 0x00008000);

	for (i = 0; i < OHCI_LOOP_COUNT; i++) {
		if (reg_read(ohci, OHCI1394_PhyControl) & 0x80000000)
			break;

		mdelay(1);
	}

	r = reg_read(ohci, OHCI1394_PhyControl);

	if (i >= OHCI_LOOP_COUNT)
		OHCI_ERR("Get PHY Reg timeout [0x%08x/0x%08x/%d]\n",
		       r, r & 0x80000000, i);

	rtos_spin_unlock_irqrestore (&ohci->phy_reg_lock, flags);

	return (r & 0x00ff0000) >> 16;
}

static void set_phy_reg(struct ti_ohci *ohci, u8 addr, u8 data)
{
	int i;
	unsigned long flags;
	u32 r = 0;

	rtos_spin_lock_irqsave (&ohci->phy_reg_lock, flags);

	reg_write(ohci, OHCI1394_PhyControl, (addr << 8) | data | 0x00004000);

	for (i = 0; i < OHCI_LOOP_COUNT; i++) {
		r = reg_read(ohci, OHCI1394_PhyControl);
		if (!(r & 0x00004000))
			break;

		mdelay(1);
	}

	if (i == OHCI_LOOP_COUNT)
		OHCI_ERR("Set PHY Reg timeout [0x%08x/0x%08x/%d\n",
		       r, r & 0x00004000, i);

	rtos_spin_unlock_irqrestore (&ohci->phy_reg_lock, flags);

	return;
}


static void set_phy_reg_mask(struct ti_ohci *ohci, u8 addr, u8 data)
{
	u8 old;

	old = get_phy_reg (ohci, addr);
	old |= data;
	set_phy_reg (ohci, addr, old);

	return;
}


static void handle_selfid(struct ti_ohci *ohci, struct hpsb_host *host,
				int phyid, int isroot)
{
	quadlet_t *q = ohci->selfid_buf_cpu;
	quadlet_t self_id_count=reg_read(ohci, OHCI1394_SelfIDCount);
	size_t size;
	quadlet_t q0, q1;

	/* Check status of self-id reception */

	if (ohci->selfid_swap)
		q0 = le32_to_cpu(q[0]);
	else
		q0 = q[0];

	if ((self_id_count & 0x80000000) ||
	    ((self_id_count & 0x00FF0000) != (q0 & 0x00FF0000))) {
		OHCI_ERR("Error in reception of SelfID packets [0x%08x/0x%08x] (count: %d)\n",
		      self_id_count, q0, ohci->self_id_errors);

		/* Tip by James Goodwin <jamesg@Filanet.com>:
		 * We had an error, generate another bus reset in response.  */
		if (ohci->self_id_errors<OHCI1394_MAX_SELF_ID_ERRORS) {
			set_phy_reg_mask (ohci, 1, 0x40);
			ohci->self_id_errors++;
		} else {
			OHCI_ERR("Too many errors on SelfID error reception, giving up!\n");
		}
		return;
	}

	/* SelfID Ok, reset error counter. */
	ohci->self_id_errors = 0;

	size = ((self_id_count & 0x00001FFC) >> 2) - 1;
	q++;
	
	/**
	 * ok, selfid is ok, we start to deliver the selfids on to stack*/
	while (size > 0) {
		if (ohci->selfid_swap) {
			q0 = le32_to_cpu(q[0]);
			q1 = le32_to_cpu(q[1]);
		} else {
			q0 = q[0];
			q1 = q[1];
		}

		if (q0 == ~q1) {
			OHCI_NOTICE ("SelfID packet 0x%x received\n", q0);
			hpsb_selfid_received(host, cpu_to_be32(q0));
			if (((q0 & 0x3f000000) >> 24) == phyid)
				OHCI_NOTICE ("SelfID for this node is 0x%08x", q0);
		} else {
			    OHCI_ERR("SelfID is inconsistent [0x%08x/0x%08x]\n", q0, q1);
		}
		q += 2;
		size -= 2;
	}

	OHCI_NOTICE("SelfID complete\n");

	return;
}


static void ohci_soft_reset(struct ti_ohci *ohci) {
	int i;

	reg_write(ohci, OHCI1394_HCControlSet, OHCI1394_HCControl_softReset);

	for (i = 0; i < OHCI_LOOP_COUNT; i++) {
		if (!(reg_read(ohci, OHCI1394_HCControlSet) & OHCI1394_HCControl_softReset))
			break;
		mdelay(1);
	}
	OHCI_NOTICE ("Soft reset finished\n");
}


static void initialize_dma_asyn_recv(struct dma_asyn_recv *d, int generate_irq)
{
	struct ti_ohci *ohci = (struct ti_ohci*)(d->ohci);
	int i;

	ohci1394_stop_context(ohci, d->ctrlClear, NULL);

	for (i=0; i<d->num_desc; i++) {
		u32 c;

		c = DMA_CTL_INPUT_MORE | DMA_CTL_UPDATE | DMA_CTL_BRANCH;
		if (generate_irq)
			c |= DMA_CTL_IRQ;

		d->prg_cpu[i]->control = cpu_to_le32(c | d->buf_size);

		/* End of descriptor list? */
		if (i + 1 < d->num_desc) {
			d->prg_cpu[i]->branchAddress =
				cpu_to_le32((d->prg_bus[i+1] & 0xfffffff0) | 0x1);
		} else {
			d->prg_cpu[i]->branchAddress =
				cpu_to_le32((d->prg_bus[0] & 0xfffffff0));
		}

		d->prg_cpu[i]->address = cpu_to_le32(d->buf_bus[i]);
		d->prg_cpu[i]->status = cpu_to_le32(d->buf_size);
	}

        d->buf_ind = 0;
        d->buf_offset = 0;

	/* Tell the controller where the first AR program is */
	reg_write(ohci, d->cmdPtr, d->prg_bus[0] | 0x1);

	/* Run context */
	reg_write(ohci, d->ctrlSet, 0x00008000);

	OHCI_NOTICE("Receive DMA ctx=%d initialized\n", d->context);
}


static void initialize_dma_asyn_xmit(struct dma_asyn_xmit *d)
{
	struct ti_ohci *ohci = (struct ti_ohci*)(d->ohci);

	/* Stop the context */
	ohci1394_stop_context(ohci, d->ctrlClear, NULL);

        d->prg_ind = 0;
	d->sent_ind = 0;
	d->free_prgs = d->num_desc;
        d->branchAddrPtr = NULL;
	INIT_LIST_HEAD(&d->fifo_list);
	INIT_LIST_HEAD(&d->pending_list);

	
	OHCI_NOTICE("Transmit DMA ctx=%d initialized\n", d->context);
}


static int get_nb_iso_ctx(struct ti_ohci *ohci, int reg)
{
	int i,ctx=0;
	u32 tmp;

	reg_write(ohci, reg, 0xffffffff);
	tmp = reg_read(ohci, reg);

	OHCI_NOTICE("Iso contexts reg: %08x implemented: %08x\n", reg, tmp);

	/* Count the number of contexts */
	for (i=0; i<32; i++) {
	    	if (tmp & 1) ctx++;
		tmp >>= 1;
	}
	return ctx;
}


static void ohci_initialize(struct ti_ohci *ohci)
{
	char irq_buf[16];
	quadlet_t buf;
	int num_ports, i;

	rtos_spin_lock_init(&ohci->phy_reg_lock);
	rtos_spin_lock_init(&ohci->event_lock);

	/*! Put some defaults to these undefined bus options */
	buf = reg_read(ohci, OHCI1394_BusOptions);
	buf |=  0x60000000; /* Enable CMC and ISC */
	if(!disable_irm)
		buf |=  0x80000000; /* Enable IRMC */
	buf &= ~0x00ff0000; /* XXX: Set cyc_clk_acc to zero for now */
	buf &= ~0x18000000; /* Disable PMC and BMC */
	reg_write(ohci, OHCI1394_BusOptions, buf);

	/*! Set the bus number */
	reg_write(ohci, OHCI1394_NodeID, 0x0000ffc0);

	/*! Enable posted writes */
	reg_write(ohci, OHCI1394_HCControlSet, OHCI1394_HCControl_postedWriteEnable);

	/*! Clear link control register */
	reg_write(ohci, OHCI1394_LinkControlClear, 0xffffffff);

	/*! Enable cycle timer and cycle master and set the IRM
	 * contender bit in our self ID packets if appropriate. */
	reg_write(ohci, OHCI1394_LinkControlSet,
		  OHCI1394_LinkControl_CycleTimerEnable |
		  OHCI1394_LinkControl_CycleMaster);
	set_phy_reg_mask(ohci, 4, PHY_04_LCTRL |
			 (disable_irm ? 0 : PHY_04_CONTENDER));

	/*! Set up self-id dma buffer */
	reg_write(ohci, OHCI1394_SelfIDBuffer, ohci->selfid_buf_bus);

	/*! enable self-id and phys */
	reg_write(ohci, OHCI1394_LinkControlSet, OHCI1394_LinkControl_RcvSelfID |
		  OHCI1394_LinkControl_RcvPhyPkt);

	/*! Set the Config ROM mapping register */
	reg_write(ohci, OHCI1394_ConfigROMmap, ohci->csr_config_rom_bus);

	/*! Now get our max packet size */
	ohci->max_packet_size =
		1<<(((reg_read(ohci, OHCI1394_BusOptions)>>12)&0xf)+1);
		
	/*! Don't accept phy packets into AR request context */
	reg_write(ohci, OHCI1394_LinkControlClear, 0x00000400);

	/*! Clear the interrupt mask */
	reg_write(ohci, OHCI1394_IsoRecvIntMaskClear, 0xffffffff);
	reg_write(ohci, OHCI1394_IsoRecvIntEventClear, 0xffffffff);

	/*! Clear the interrupt mask */
	reg_write(ohci, OHCI1394_IsoXmitIntMaskClear, 0xffffffff);
	reg_write(ohci, OHCI1394_IsoXmitIntEventClear, 0xffffffff);

	/*! Initialize AR dma */
	initialize_dma_asyn_recv(&ohci->ar_req_context, 0);
	initialize_dma_asyn_recv(&ohci->ar_resp_context, 0);

	/*! Initialize AT dma */
	initialize_dma_asyn_xmit(&ohci->at_req_context);
	initialize_dma_asyn_xmit(&ohci->at_resp_context);
	
	/*!
	 * Accept AT requests from all nodes. This probably
	 * will have to be controlled from the subsystem
	 * on a per node basis.
	 */
	reg_write(ohci,OHCI1394_AsReqFilterHiSet, 0x80000000);

	/*! Specify AT retries */
	reg_write(ohci, OHCI1394_ATRetries,
		  OHCI1394_MAX_AT_REQ_RETRIES |
		  (OHCI1394_MAX_AT_RESP_RETRIES<<4) |
		  (OHCI1394_MAX_PHYS_RESP_RETRIES<<8));

	/*! We don't want hardware swapping */
	reg_write(ohci, OHCI1394_HCControlClear, OHCI1394_HCControl_noByteSwap);

	/*! Enable interrupts 
	  this is just the initial mask, we can surly change it to 
	  our own needs, like to enable the cycle start interrupt*/
	reg_write(ohci, OHCI1394_IntMaskSet,
		  OHCI1394_unrecoverableError |
		  OHCI1394_masterIntEnable |
		  OHCI1394_busReset |
		  OHCI1394_selfIDComplete |
		  OHCI1394_RSPkt |
		  OHCI1394_RQPkt |
		  OHCI1394_respTxComplete |
		  OHCI1394_reqTxComplete |
		  OHCI1394_isochRx |
		  OHCI1394_isochTx |
		  OHCI1394_cycleInconsistent);

	/*! Enable link */
	reg_write(ohci, OHCI1394_HCControlSet, OHCI1394_HCControl_linkEnable);

	buf = reg_read(ohci, OHCI1394_Version);
#ifndef __sparc__
	sprintf (irq_buf, "%d", ohci->dev->irq);
#else
	sprintf (irq_buf, "%s", __irq_itoa(ohci->dev->irq));
#endif
	OHCI_NOTICE("OHCI-1394 %d.%d (PCI): IRQ=[%s]  "
	      "MMIO=[%lx-%lx]  Max Packet=[%d]\n",
	      ((((buf) >> 16) & 0xf) + (((buf) >> 20) & 0xf) * 10),
	      ((((buf) >> 4) & 0xf) + ((buf) & 0xf) * 10), irq_buf,
	      pci_resource_start(ohci->dev, 0),
	      pci_resource_start(ohci->dev, 0) + OHCI1394_REGISTER_SIZE - 1,
	      ohci->max_packet_size);

	/*! Check all of our ports to make sure that if anything is
	 * connected, we enable that port. */
	num_ports = get_phy_reg(ohci, 2) & 0xf;
	for (i = 0; i < num_ports; i++) {
		unsigned int status;

		set_phy_reg(ohci, 7, i);
		status = get_phy_reg(ohci, 8);

		if (status & 0x20)
			set_phy_reg(ohci, 8, status & ~1);
	}
        /*! Serial EEPROM Sanity check. */
        if ((ohci->max_packet_size < 512) ||
	    (ohci->max_packet_size > 4096)) {
		/* Serial EEPROM contents are suspect, set a sane max packet
		 * size and print the raw contents for bug reports if verbose
		 * debug is enabled. */
#if 0
		int i;
#endif

		OHCI_NOTICE("Serial EEPROM has suspicious values, "
                      "attempting to setting max_packet_size to 512 bytes\n");
		reg_write(ohci, OHCI1394_BusOptions,
			  (reg_read(ohci, OHCI1394_BusOptions) & 0xf007) | 0x8002);
		ohci->max_packet_size = 512;
#if 0
		OHCI_NOTICE(KERN_DEBUG, "    EEPROM Present: %d\n",
		      (reg_read(ohci, OHCI1394_Version) >> 24) & 0x1);
		reg_write(ohci, OHCI1394_GUID_ROM, 0x80000000);

		for (i = 0;
		     ((i < 1000) &&
		      (reg_read(ohci, OHCI1394_GUID_ROM) & 0x80000000)); i++)
			udelay(10);

		for (i = 0; i < 0x20; i++) {
			reg_write(ohci, OHCI1394_GUID_ROM, 0x02000000);
			OHCI_NOTICE(KERN_DEBUG, "    EEPROM %02x: %02x\n", i,
			      (reg_read(ohci, OHCI1394_GUID_ROM) >> 16) & 0xff);
		}
#endif
	}
}


static void insert_packet(struct ti_ohci *ohci,
			  struct dma_asyn_xmit *d, struct hpsb_packet *packet)
{
	u32 cycleTimer;
	int idx = d->prg_ind;

	OHCI_NOTICE("Inserting packet to context %s for node " NODE_BUS_FMT
	       ", tlabel=%d, tcode=0x%x, speed=%d\n", d->name,
	       NODE_BUS_ARGS(ohci->host, packet->node_id), packet->tlabel,
	       packet->tcode, packet->speed_code);

	d->prg_cpu[idx]->begin.address = 0;
	d->prg_cpu[idx]->begin.branchAddress = 0;

	if (d->type == ASYNC_RESP_TRANSMIT) {
		/*
		 * For response packets, we need to put a timeout value in
		 * the 16 lower bits of the status... let's try 1 sec timeout
		 */
		cycleTimer = reg_read(ohci, OHCI1394_IsochronousCycleTimer);
		d->prg_cpu[idx]->begin.status = cpu_to_le32(
			(((((cycleTimer>>25)&0x7)+1)&0x7)<<13) |
			((cycleTimer&0x01fff000)>>12));

		OHCI_NOTICE("cycleTimer: %08x timeStamp: %08x\n",
		       cycleTimer, d->prg_cpu[idx]->begin.status);
	} else 
		d->prg_cpu[idx]->begin.status = 0;

        if ( (packet->type == hpsb_async) || (packet->type == hpsb_raw) ) {

                if (packet->type == hpsb_raw) {
			d->prg_cpu[idx]->data[0] = cpu_to_le32(OHCI1394_TCODE_PHY<<4);
                        d->prg_cpu[idx]->data[1] = cpu_to_le32(packet->header[0]);
                        d->prg_cpu[idx]->data[2] = cpu_to_le32(packet->header[1]);
                } else {
                        d->prg_cpu[idx]->data[0] = packet->speed_code<<16 |
                                (packet->header[0] & 0xFFFF);

			if (packet->tcode == TCODE_ISO_DATA) {
				/* Sending an async stream packet */
				d->prg_cpu[idx]->data[1] = packet->header[0] & 0xFFFF0000;
			} else {
				/* Sending a normal async request or response */
				d->prg_cpu[idx]->data[1] =
					(packet->header[1] & 0xFFFF) |
					(packet->header[0] & 0xFFFF0000);
				d->prg_cpu[idx]->data[2] = packet->header[2];
				d->prg_cpu[idx]->data[3] = packet->header[3];
			}

			packet_swab(d->prg_cpu[idx]->data, packet->tcode);
                }

                if (packet->data_size) { /* block transmit */
			if (packet->tcode == TCODE_STREAM_DATA){
				d->prg_cpu[idx]->begin.control =
					cpu_to_le32(DMA_CTL_OUTPUT_MORE |
						    DMA_CTL_IMMEDIATE | 0x8);
			} else {
				d->prg_cpu[idx]->begin.control =
					cpu_to_le32(DMA_CTL_OUTPUT_MORE |
						    DMA_CTL_IMMEDIATE | 0x10);
			}
                        d->prg_cpu[idx]->end.control =
                                cpu_to_le32(DMA_CTL_OUTPUT_LAST |
					    DMA_CTL_IRQ |
					    DMA_CTL_BRANCH |
					    packet->data_size);
                        /*
                         * Check that the packet data buffer
                         * does not cross a page boundary.
			 *
			 * XXX Fix this some day. eth1394 seems to trigger
			 * it, but ignoring it doesn't seem to cause a
			 * problem.
                         */
#if 0
                        if (cross_bound((unsigned long)packet->data,
                                        packet->data_size)>0) {
                                /* FIXME: do something about it */
				OHCI_ERR( "%s: packet data addr: %p size %Zd bytes "
                                      "cross page boundary\n", __FUNCTION__,
                                      packet->data, packet->data_size);
                        }
#endif
                        d->prg_cpu[idx]->end.address = cpu_to_le32(
                                pci_map_single(ohci->dev, packet->data,
                                               packet->data_size,
                                               PCI_DMA_TODEVICE));
			OHCI_NOTICE("single, block transmit packet");

                        d->prg_cpu[idx]->end.branchAddress = 0;
                        d->prg_cpu[idx]->end.status = 0;
                        if (d->branchAddrPtr)
                                *(d->branchAddrPtr) =
					cpu_to_le32(d->prg_bus[idx] | 0x3);

                        d->branchAddrPtr =
                                &(d->prg_cpu[idx]->end.branchAddress);
                } else { /* quadlet transmit */
                        if (packet->type == hpsb_raw)
                                d->prg_cpu[idx]->begin.control =
					cpu_to_le32(DMA_CTL_OUTPUT_LAST |
						    DMA_CTL_IMMEDIATE |
						    DMA_CTL_IRQ |
						    DMA_CTL_BRANCH |
						    (packet->header_size + 4));
                        else
                                d->prg_cpu[idx]->begin.control =
					cpu_to_le32(DMA_CTL_OUTPUT_LAST |
						    DMA_CTL_IMMEDIATE |
						    DMA_CTL_IRQ |
						    DMA_CTL_BRANCH |
						    packet->header_size);

                        if (d->branchAddrPtr)
                                *(d->branchAddrPtr) =
					cpu_to_le32(d->prg_bus[idx] | 0x2);
                        d->branchAddrPtr =
                                &(d->prg_cpu[idx]->begin.branchAddress);
                }

        } else { /* iso stream packet */
                d->prg_cpu[idx]->data[0] = packet->speed_code<<16 |
                        (packet->header[0] & 0xFFFF);
                d->prg_cpu[idx]->data[1] = packet->header[0] & 0xFFFF0000;
		packet_swab(d->prg_cpu[idx]->data, packet->tcode);

                d->prg_cpu[idx]->begin.control =
			cpu_to_le32(DMA_CTL_OUTPUT_MORE |
				    DMA_CTL_IMMEDIATE | 0x8);
                d->prg_cpu[idx]->end.control =
			cpu_to_le32(DMA_CTL_OUTPUT_LAST |
				    DMA_CTL_UPDATE |
				    DMA_CTL_IRQ |
				    DMA_CTL_BRANCH |
				    packet->data_size);
                d->prg_cpu[idx]->end.address = cpu_to_le32(
				pci_map_single(ohci->dev, packet->data,
				packet->data_size, PCI_DMA_TODEVICE));
		OHCI_NOTICE("single, iso transmit packet\n");

                d->prg_cpu[idx]->end.branchAddress = 0;
                d->prg_cpu[idx]->end.status = 0;
                OHCI_NOTICE("Iso xmit context info: header[%08x %08x]\n"
                       "                       begin=%08x %08x %08x %08x\n"
                       "                             %08x %08x %08x %08x\n"
                       "                       end  =%08x %08x %08x %08x\n",
                       d->prg_cpu[idx]->data[0], d->prg_cpu[idx]->data[1],
                       d->prg_cpu[idx]->begin.control,
                       d->prg_cpu[idx]->begin.address,
                       d->prg_cpu[idx]->begin.branchAddress,
                       d->prg_cpu[idx]->begin.status,
                       d->prg_cpu[idx]->data[0],
                       d->prg_cpu[idx]->data[1],
                       d->prg_cpu[idx]->data[2],
                       d->prg_cpu[idx]->data[3],
                       d->prg_cpu[idx]->end.control,
                       d->prg_cpu[idx]->end.address,
                       d->prg_cpu[idx]->end.branchAddress,
                       d->prg_cpu[idx]->end.status);
                if (d->branchAddrPtr)
  		        *(d->branchAddrPtr) = cpu_to_le32(d->prg_bus[idx] | 0x3);
                d->branchAddrPtr = &(d->prg_cpu[idx]->end.branchAddress);
        }
	d->free_prgs--;

	/* queue the packet in the appropriate context queue */
	list_add_tail(&packet->driver_list, &d->fifo_list);
	d->prg_ind = (d->prg_ind + 1) % d->num_desc;
	
	/*if the xmit_stamp is not NULL, that means some protocol wants the sending time stamp*/
	if(packet->xmit_stamp)
		*packet->xmit_stamp = cpu_to_be64(rtos_get_time() + *packet->xmit_stamp);
}


static void dma_trm_flush(struct ti_ohci *ohci, struct dma_asyn_xmit *d)
{
	struct hpsb_packet *packet, *ptmp;
	int idx = d->prg_ind;
	int z = 0;

	/* insert the packets into the dma fifo */
	list_for_each_entry_safe(packet, ptmp, &d->pending_list, driver_list) {
		if (!d->free_prgs)
			break;

		/* For the first packet only */
		if (!z)
			z = (packet->data_size) ? 3 : 2;

		/* Insert the packet */
		list_del_init(&packet->driver_list);
		insert_packet(ohci, d, packet);
	}

	/* Nothing must have been done, either no free_prgs or no packets */
	if (z == 0)
		return;

	/* Is the context running ? (should be unless it is
	   the first packet to be sent in this context) */
	if (!(reg_read(ohci, d->ctrlSet) & 0x8000)) {
		u32 nodeId = reg_read(ohci, OHCI1394_NodeID);

		OHCI_NOTICE("Starting transmit DMA ctx=%d\n",d->context);
		reg_write(ohci, d->cmdPtr, d->prg_bus[idx] | z);

		/* Check that the node id is valid, and not 63 */
		if (!(nodeId & 0x80000000) || (nodeId & 0x3f) == 63)
			OHCI_ERR("Running dma failed because Node ID is not valid\n");
		else
			reg_write(ohci, d->ctrlSet, 0x8000);
	} else {
		/* Wake up the dma context if necessary */
		if (!(reg_read(ohci, d->ctrlSet) & 0x400))
			OHCI_NOTICE("Waking transmit DMA ctx=%d\n",d->context);

		/* do this always, to avoid race condition */
		reg_write(ohci, d->ctrlSet, 0x1000);
	}

	return;
}


static int ohci_transmit(struct hpsb_host *host, struct hpsb_packet *packet)
{
	struct ti_ohci *ohci = host->hostdata;
	struct dma_asyn_xmit *d;
	unsigned long flags;
	struct list_head *lh, *next;
	struct hpsb_packet *tmp;

	if (packet->data_size > ohci->max_packet_size) {
		OHCI_ERR("Transmit packet size %Zd is too big\n",
		      packet->data_size);
		return -EOVERFLOW;
	}

	/* Decide whether we have an iso, a request, or a response packet */
	if (packet->type == hpsb_raw)
		d = &ohci->at_req_context;
	else if ((packet->tcode == TCODE_ISO_DATA) && (packet->type == hpsb_iso)) {
		//transmit the stream data thru asynchronous dma. 
		d = &ohci->at_req_context; 
	} else if ((packet->tcode & 0x02) && (packet->tcode != TCODE_ISO_DATA))
		d = &ohci->at_resp_context;
	else
		d = &ohci->at_req_context;

	rtos_spin_lock_irqsave(&d->lock,flags);

	if(packet->pri==0xf)
		list_add_tail(&packet->driver_list, &d->pending_list);
	else{
		list_for_each_safe(lh, next, &d->pending_list) {
			tmp = list_entry(lh, struct hpsb_packet, driver_list);
				if (tmp->pri > packet->pri) {
					list_add(&packet->driver_list, &tmp->driver_list);
					break;
				}
		}
		if(lh==&d->pending_list){
			list_add_tail(&packet->driver_list, &d->pending_list);
		}
	}
	

	packet->xmit_time = rtos_get_time();
	
		
	
	dma_trm_flush(ohci, d);

	rtos_spin_unlock_irqrestore(&d->lock,flags);

	return 0;
}


static int ohci_devctl(struct hpsb_host *host, enum devctl_cmd cmd, int arg)
{
	struct ti_ohci *ohci = host->hostdata;
	int retval = 0;
	int phy_reg;

	switch (cmd) {
	case RESET_BUS:
		switch (arg) {
		case SHORT_RESET:
			phy_reg = get_phy_reg(ohci, 5);
			phy_reg |= 0x40;
			set_phy_reg(ohci, 5, phy_reg); /* set ISBR */
			break;
		case LONG_RESET:
			phy_reg = get_phy_reg(ohci, 1);
			phy_reg |= 0x40;
			set_phy_reg(ohci, 1, phy_reg); /* set IBR */
			break;
		case SHORT_RESET_NO_FORCE_ROOT:
			phy_reg = get_phy_reg(ohci, 1);
			if (phy_reg & 0x80) {
				phy_reg &= ~0x80;
				set_phy_reg(ohci, 1, phy_reg); /* clear RHB */
			}

			phy_reg = get_phy_reg(ohci, 5);
			phy_reg |= 0x40;
			set_phy_reg(ohci, 5, phy_reg); /* set ISBR */
			break;
		case LONG_RESET_NO_FORCE_ROOT:
			phy_reg = get_phy_reg(ohci, 1);
			phy_reg &= ~0x80;
			phy_reg |= 0x40;
			set_phy_reg(ohci, 1, phy_reg); /* clear RHB, set IBR */
			break;
		case SHORT_RESET_FORCE_ROOT:
			phy_reg = get_phy_reg(ohci, 1);
			if (!(phy_reg & 0x80)) {
				phy_reg |= 0x80;
				set_phy_reg(ohci, 1, phy_reg); /* set RHB */
			}

			phy_reg = get_phy_reg(ohci, 5);
			phy_reg |= 0x40;
			set_phy_reg(ohci, 5, phy_reg); /* set ISBR */
			break;
		case LONG_RESET_FORCE_ROOT:
			phy_reg = get_phy_reg(ohci, 1);
			phy_reg |= 0xc0;
			set_phy_reg(ohci, 1, phy_reg); /* set RHB and IBR */
			break;
		default:
			retval = -1;
		}
		break;

	case GET_CYCLE_COUNTER:
		retval = reg_read(ohci, OHCI1394_IsochronousCycleTimer);
		break;

	case SET_CYCLE_COUNTER:
		reg_write(ohci, OHCI1394_IsochronousCycleTimer, arg);
		break;

	case SET_BUS_ID:
		OHCI_ERR("devctl command SET_BUS_ID err\n");
		break;

	case ACT_CYCLE_MASTER:
		if (arg) {
			/* check if we are root and other nodes are present */
			u32 nodeId = reg_read(ohci, OHCI1394_NodeID);
			if ((nodeId & (1<<30)) && (nodeId & 0x3f)) {
				/*
				 * enable cycleTimer, cycleMaster
				 */
				OHCI_NOTICE("Cycle master enabled\n");
				reg_write(ohci, OHCI1394_LinkControlSet,
					  OHCI1394_LinkControl_CycleTimerEnable |
					  OHCI1394_LinkControl_CycleMaster);
			}
		} else {
			/* disable cycleTimer, cycleMaster, cycleSource */
			reg_write(ohci, OHCI1394_LinkControlClear,
				  OHCI1394_LinkControl_CycleTimerEnable |
				  OHCI1394_LinkControl_CycleMaster |
				  OHCI1394_LinkControl_CycleSource);
		}
		break;

	case CANCEL_REQUESTS:
		OHCI_NOTICE("Cancel request received\n");
		dma_trm_reset(&ohci->at_req_context);
		dma_trm_reset(&ohci->at_resp_context);
		break;

	case ISO_LISTEN_CHANNEL:
        {
		OHCI_NOTICE_G( "ISO listen thru ohci_devctl is deprecated!!!\n");
		break;
        }
	case ISO_UNLISTEN_CHANNEL:
        {
		OHCI_NOTICE_G("ISO unlisten channel thru ohci_devctl is deprecated!!!\n");
		break;
        }
	default:
		OHCI_NOTICE_G("ohci_devctl cmd %d not implemented yet",cmd);
		break;
	}
	return retval;
}

/***********************************
 * rawiso ISO reception            *
 ***********************************/

static void ohci_iso_recv_task(unsigned long data);
static void ohci_iso_recv_stop(struct hpsb_iso *iso);
static void ohci_iso_recv_shutdown(struct hpsb_iso *iso);
static int  ohci_iso_recv_start(struct hpsb_iso *iso, int cycle, int tag_mask, int sync);
static void ohci_iso_recv_program(struct hpsb_iso *iso);


static int ohci_iso_recv_init(struct hpsb_iso *iso)
{
	struct dma_iso_recv *recv;
	struct ti_ohci *ohci = iso->host->hostdata;
	int ctx;
	struct dma_base_ctx *base;
	int ret = -ENOMEM;
	
	recv=kmalloc(sizeof(struct dma_iso_recv), GFP_KERNEL);
	if(recv==NULL)
		return -ENOMEM;
	
	base =(struct dma_base_ctx *)recv;

	iso->hostdata = recv;
	recv->ohci = ohci;
	recv->task_active = 0;
	dma_prog_region_init(&recv->prog);
	recv->block = NULL;
	snprintf(recv->name, 32, iso->name);

	/* use buffer-fill mode, unless irq_interval is 1
	   (note: multichannel requires buffer-fill) */

	if (((iso->irq_interval == 1) ||
	     iso->dma_mode == HPSB_ISO_DMA_PACKET_PER_BUFFER) && iso->channel != -1) {
		recv->dma_mode = PACKET_PER_BUFFER_MODE;
	} else {
		recv->dma_mode = BUFFER_FILL_MODE;
	}

	/* set nblocks, buf_stride, block_irq_interval */

	if (recv->dma_mode == BUFFER_FILL_MODE) {
		recv->buf_stride = PAGE_SIZE;

		/* one block per page of data in the DMA buffer, minus the final guard page */
		recv->nblocks = iso->buf_size/PAGE_SIZE - 1;
		if (recv->nblocks < 3) {
			OHCI_NOTICE("ohci_iso_recv_init: DMA buffer too small\n");
			goto err;
		}

		/* iso->irq_interval is in packets - translate that to blocks */
		if (iso->irq_interval == 1)
			recv->block_irq_interval = 1;
		else
			recv->block_irq_interval = iso->irq_interval *
							((recv->nblocks+1)/iso->buf_packets);
		if (recv->block_irq_interval*4 > recv->nblocks)
			recv->block_irq_interval = recv->nblocks/4;
		if (recv->block_irq_interval < 1)
			recv->block_irq_interval = 1;

	} else {
		int max_packet_size;

		recv->nblocks = iso->buf_packets;
		recv->block_irq_interval = iso->irq_interval;
		if (recv->block_irq_interval * 4 > iso->buf_packets)
			recv->block_irq_interval = iso->buf_packets / 4;
		if (recv->block_irq_interval < 1)
		recv->block_irq_interval = 1;

		/* choose a buffer stride */
		/* must be a power of 2, and <= PAGE_SIZE */

		max_packet_size = iso->buf_size / iso->buf_packets;

		for (recv->buf_stride = 8; recv->buf_stride < max_packet_size;
		    recv->buf_stride *= 2);

		if (recv->buf_stride*iso->buf_packets > iso->buf_size ||
		   recv->buf_stride > PAGE_SIZE) {
			/* this shouldn't happen, but anyway... */
			OHCI_NOTICE("ohci_iso_recv_init: problem choosing a buffer stride\n");
			goto err;
		}
	}

	recv->block_reader = 0;
	recv->released_bytes = 0;
	recv->block_dma = 0;
	recv->dma_offset = 0;

	/* size of DMA program = one descriptor per block */
	if (dma_prog_region_alloc(&recv->prog,
				 sizeof(struct dma_cmd) * recv->nblocks,
				 recv->ohci->dev))
		goto err;

	recv->block = (struct dma_cmd*) recv->prog.kvirt;

	ohci1394_init_iso_ctx(base, OHCI_ISO_RECEIVE, iso);

	if (ohci1394_register_iso_ctx(recv->ohci, base) < 0) {
		ret = -EBUSY;
		goto err;
	}

	recv->task_active = 1;

	/* recv context registers are spaced 32 bytes apart */
	ctx = recv->context;
	recv->ctrlSet = OHCI1394_IsoRcvContextControlSet + 32 * ctx;
	recv->ctrlClear = OHCI1394_IsoRcvContextControlClear + 32 * ctx;
	recv->cmdPtr = OHCI1394_IsoRcvCommandPtr + 32 * ctx;
	recv->ctxtMatch = OHCI1394_IsoRcvContextMatch + 32 * ctx;

	if (iso->channel == -1) {
		/* clear multi-channel selection mask */
		reg_write(recv->ohci, OHCI1394_IRMultiChanMaskHiClear, 0xFFFFFFFF);
		reg_write(recv->ohci, OHCI1394_IRMultiChanMaskLoClear, 0xFFFFFFFF);
	}

	/* write the DMA program */
	ohci_iso_recv_program(iso);

	OHCI_NOTICE("ohci_iso_recv_init: %s mode, DMA buffer is %lu pages"
	       " (%u bytes), using %u blocks, buf_stride %u, block_irq_interval %d\n",
	       recv->dma_mode == BUFFER_FILL_MODE ?
	       "buffer-fill" : "packet-per-buffer",
	       iso->buf_size/PAGE_SIZE, iso->buf_size,
	       recv->nblocks, recv->buf_stride, recv->block_irq_interval);

	return 0;

err:
	ohci_iso_recv_shutdown(iso);
	return ret;
}


static void ohci_iso_recv_stop(struct hpsb_iso *iso)
{
	struct dma_iso_recv *recv = iso->hostdata;

	/* disable interrupts */
	reg_write(recv->ohci, OHCI1394_IsoRecvIntMaskClear, 1 << recv->context);

	/* halt DMA */
	ohci1394_stop_context(recv->ohci, recv->ctrlClear, NULL);
}


static void ohci_iso_recv_shutdown(struct hpsb_iso *iso)
{
	struct dma_iso_recv *recv = iso->hostdata;

	if (recv->task_active) {
		ohci_iso_recv_stop(iso);
		ohci1394_unregister_iso_ctx(recv->ohci, (struct dma_base_ctx *)recv);
		recv->task_active = 0;
	}

	dma_prog_region_free(&recv->prog);
	iso->hostdata = NULL;
	kfree(recv);
}


static void ohci_iso_recv_program(struct hpsb_iso *iso)
{
	struct dma_iso_recv *recv = iso->hostdata;
	int blk;

	/* address of 'branch' field in previous DMA descriptor */
	u32 *prev_branch = NULL;

	for (blk = 0; blk < recv->nblocks; blk++) {
		u32 control;

		/* the DMA descriptor */
		struct dma_cmd *cmd = &recv->block[blk];

		/* offset of the DMA descriptor relative to the DMA prog buffer */
		unsigned long prog_offset = blk * sizeof(struct dma_cmd);

		/* offset of this packet's data within the DMA buffer */
		unsigned long buf_offset = blk * recv->buf_stride;

		if (recv->dma_mode == BUFFER_FILL_MODE) {
			control = 2 << 28; /* INPUT_MORE */
		} else {
			control = 3 << 28; /* INPUT_LAST */
		}

		control |= 8 << 24; /* s = 1, update xferStatus and resCount */

		/* interrupt on last block, and at intervals */
		if (blk == recv->nblocks-1 || (blk % recv->block_irq_interval) == 0) {
			control |= 3 << 20; /* want interrupt */
		}

		control |= 3 << 18; /* enable branch to address */
		control |= recv->buf_stride;

		cmd->control = cpu_to_le32(control);
		cmd->address = cpu_to_le32(dma_region_offset_to_bus(&iso->data_buf, buf_offset));
		cmd->branchAddress = 0; /* filled in on next loop */
		cmd->status = cpu_to_le32(recv->buf_stride);

		/* link the previous descriptor to this one */
		if (prev_branch) {
			*prev_branch = cpu_to_le32(dma_prog_region_offset_to_bus(&recv->prog, prog_offset) | 1);
		}

		prev_branch = &cmd->branchAddress;
	}

	/* the final descriptor's branch address and Z should be left at 0 */
}


static void ohci_iso_recv_change_channel(struct hpsb_iso *iso, unsigned char channel, int listen)
{
	struct dma_iso_recv *recv = iso->hostdata;
	int reg, i;

	if (channel < 32) {
		reg = listen ? OHCI1394_IRMultiChanMaskLoSet : OHCI1394_IRMultiChanMaskLoClear;
		i = channel;
	} else {
		reg = listen ? OHCI1394_IRMultiChanMaskHiSet : OHCI1394_IRMultiChanMaskHiClear;
		i = channel - 32;
	}

	reg_write(recv->ohci, reg, (1 << i));

	/* issue a dummy read to force all PCI writes to be posted immediately */
	mb();
	reg_read(recv->ohci, OHCI1394_IsochronousCycleTimer);
}


static void ohci_iso_recv_set_channel_mask(struct hpsb_iso *iso, u64 mask)
{
	struct dma_iso_recv *recv = iso->hostdata;
	int i;

	for (i = 0; i < 64; i++) {
		if (mask & (1ULL << i)) {
			if (i < 32)
				reg_write(recv->ohci, OHCI1394_IRMultiChanMaskLoSet, (1 << i));
			else
				reg_write(recv->ohci, OHCI1394_IRMultiChanMaskHiSet, (1 << (i-32)));
		} else {
			if (i < 32)
				reg_write(recv->ohci, OHCI1394_IRMultiChanMaskLoClear, (1 << i));
			else
				reg_write(recv->ohci, OHCI1394_IRMultiChanMaskHiClear, (1 << (i-32)));
		}
	}

	/* issue a dummy read to force all PCI writes to be posted immediately */
	mb();
	reg_read(recv->ohci, OHCI1394_IsochronousCycleTimer);
}


static int ohci_iso_recv_start(struct hpsb_iso *iso, int cycle, int tag_mask, int sync)
{
	struct dma_iso_recv *recv = iso->hostdata;
	struct ti_ohci *ohci = recv->ohci;
	u32 command, contextMatch;

	reg_write(recv->ohci, recv->ctrlClear, 0xFFFFFFFF);
	wmb();

	/* always keep ISO headers */
	command = (1 << 30);

	if (recv->dma_mode == BUFFER_FILL_MODE)
		command |= (1 << 31);

	reg_write(recv->ohci, recv->ctrlSet, command);
	

	/* match on specified tags */
	contextMatch = tag_mask << 28;
	
	if (iso->channel == -1) {
		/* enable multichannel reception */
		reg_write(recv->ohci, recv->ctrlSet, (1 << 28));
	} else {
		/* listen on channel */
		contextMatch |= iso->channel;
	}

	if (cycle != -1) {
		u32 seconds;

		/* enable cycleMatch */
		reg_write(recv->ohci, recv->ctrlSet, (1 << 29));

		/* set starting cycle */
		cycle &= 0x1FFF;

		/* 'cycle' is only mod 8000, but we also need two 'seconds' bits -
		   just snarf them from the current time */
		seconds = reg_read(recv->ohci, OHCI1394_IsochronousCycleTimer) >> 25;

		/* advance one second to give some extra time for DMA to start */
		seconds += 1;

		cycle |= (seconds & 3) << 13;

		contextMatch |= cycle << 12;
	}

	if (sync != -1) {
		/* set sync flag on first DMA descriptor */
		struct dma_cmd *cmd = &recv->block[recv->block_dma];
		cmd->control |= cpu_to_le32(DMA_CTL_WAIT);

		/* match sync field */
		contextMatch |= (sync&0xf)<<8;
	}

	reg_write(recv->ohci, recv->ctxtMatch, contextMatch);
	
	wmb();
	

	/* address of first descriptor block */
	command = dma_prog_region_offset_to_bus(&recv->prog,
						recv->block_dma * sizeof(struct dma_cmd));
	command |= 1; /* Z=1 */

	reg_write(recv->ohci, recv->cmdPtr, command);


	/* enable interrupts */
	reg_write(recv->ohci, OHCI1394_IsoRecvIntMaskSet, 1 << recv->context);

	wmb();
			

	/* run */
	reg_write(recv->ohci, recv->ctrlSet, 0x8000);

	/* issue a dummy read of the cycle timer register to force
	   all PCI writes to be posted immediately */
	mb();
	reg_read(recv->ohci, OHCI1394_IsochronousCycleTimer);

	/* check RUN */
	if (!(reg_read(recv->ohci, recv->ctrlSet) & 0x8000)) {
		OHCI_ERR("Error starting IR DMA (ContextControl 0x%08x)\n",
		      reg_read(recv->ohci, recv->ctrlSet));
		return -1;
	}

	return 0;
}


static void ohci_iso_recv_release_block(struct dma_iso_recv *recv, int block)
{
	/* re-use the DMA descriptor for the block */
	/* by linking the previous descriptor to it */

	int next_i = block;
	int prev_i = (next_i == 0) ? (recv->nblocks - 1) : (next_i - 1);

	struct dma_cmd *next = &recv->block[next_i];
	struct dma_cmd *prev = &recv->block[prev_i];

	/* 'next' becomes the new end of the DMA chain,
	   so disable branch and enable interrupt */
	next->branchAddress = 0;
	next->control |= cpu_to_le32(3 << 20);
	next->status = cpu_to_le32(recv->buf_stride);

	/* link prev to next */
	prev->branchAddress = cpu_to_le32(dma_prog_region_offset_to_bus(&recv->prog,
									sizeof(struct dma_cmd) * next_i)
					  | 1); /* Z=1 */

	/* disable interrupt on previous DMA descriptor, except at intervals */
	if ((prev_i % recv->block_irq_interval) == 0) {
		prev->control |= cpu_to_le32(3 << 20); /* enable interrupt */
	} else {
		prev->control &= cpu_to_le32(~(3<<20)); /* disable interrupt */
	}
	wmb();

	/* wake up DMA in case it fell asleep */
	reg_write(recv->ohci, recv->ctrlSet, (1 << 12));
}


static void ohci_iso_recv_bufferfill_release(struct dma_iso_recv *recv,
					     struct hpsb_iso_packet_info *info)
{
	int len;

	/* release the memory where the packet was */
	len = info->len;

	/* add the wasted space for padding to 4 bytes */
	if (len % 4)
		len += 4 - (len % 4);

	/* add 8 bytes for the OHCI DMA data format overhead */
	len += 8;

	recv->released_bytes += len;

	/* have we released enough memory for one block? */
	while (recv->released_bytes > recv->buf_stride) {
		ohci_iso_recv_release_block(recv, recv->block_reader);
		recv->block_reader = (recv->block_reader + 1) % recv->nblocks;
		recv->released_bytes -= recv->buf_stride;
	}
}


static inline void ohci_iso_recv_release(struct hpsb_iso *iso, struct hpsb_iso_packet_info *info)
{
	struct dma_iso_recv *recv = iso->hostdata;
	if (recv->dma_mode == BUFFER_FILL_MODE) {
		ohci_iso_recv_bufferfill_release(recv, info);
	} else {
		ohci_iso_recv_release_block(recv, info - iso->infos);
	}
}


static void ohci_iso_recv_bufferfill_parse(struct hpsb_iso *iso, struct dma_iso_recv *recv)
{
	int wake = 0;
	int runaway = 0;
	struct ti_ohci *ohci = recv->ohci;

	while (1) {
		/*! we expect the next parsable packet to begin at recv->dma_offset */
		/* note: packet layout is as shown in section 10.6.1.1 of the OHCI spec */

		unsigned int offset;
		unsigned short len, cycle;
		unsigned char channel, tag, sy;

		unsigned char *p = iso->data_buf.kvirt;

		unsigned int this_block = recv->dma_offset/recv->buf_stride;

		/* don't loop infinitely */
		if (runaway++ > 100000) {
			atomic_inc(&iso->overflows);
			OHCI_ERR("IR DMA error - Runaway during buffer parsing!\n");
			break;
		}

		/* stop parsing once we arrive at block_dma (i.e. don't get ahead of DMA) */
		if (this_block == recv->block_dma)
			break;

		wake = 1;

		/* parse data length, tag, channel, and sy */

		/* note: we keep our own local copies of 'len' and 'offset'
		   so the user can't mess with them by poking in the mmap area */

		len = p[recv->dma_offset+2] | (p[recv->dma_offset+3] << 8);

		if (len > 4096) {
			OHCI_ERR(
			      "IR DMA error - bogus 'len' value %u\n", len);
		}

		channel = p[recv->dma_offset+1] & 0x3F;
		tag = p[recv->dma_offset+1] >> 6;
		sy = p[recv->dma_offset+0] & 0xF;

		/* advance to data payload */
		recv->dma_offset += 4;

		/* check for wrap-around */
		if (recv->dma_offset >= recv->buf_stride*recv->nblocks) {
			recv->dma_offset -= recv->buf_stride*recv->nblocks;
		}

		/* dma_offset now points to the first byte of the data payload */
		offset = recv->dma_offset;

		/* advance to xferStatus/timeStamp */
		recv->dma_offset += len;

		/* payload is padded to 4 bytes */
		if (len % 4) {
			recv->dma_offset += 4 - (len%4);
		}

		/* check for wrap-around */
		if (recv->dma_offset >= recv->buf_stride*recv->nblocks) {
			/* uh oh, the packet data wraps from the last
                           to the first DMA block - make the packet
                           contiguous by copying its "tail" into the
                           guard page */

			int guard_off = recv->buf_stride*recv->nblocks;
			int tail_len = len - (guard_off - offset);

			if (tail_len > 0  && tail_len < recv->buf_stride) {
				memcpy(iso->data_buf.kvirt + guard_off,
				       iso->data_buf.kvirt,
				       tail_len);
			}

			recv->dma_offset -= recv->buf_stride*recv->nblocks;
		}

		/* parse timestamp */
		cycle = p[recv->dma_offset+0] | (p[recv->dma_offset+1]<<8);
		cycle &= 0x1FFF;

		/* advance to next packet */
		recv->dma_offset += 4;

		/* check for wrap-around */
		if (recv->dma_offset >= recv->buf_stride*recv->nblocks) {
			recv->dma_offset -= recv->buf_stride*recv->nblocks;
		}

		hpsb_iso_packet_received(iso, offset, len, cycle, channel, tag, sy);
	}

	if (wake)
		hpsb_iso_callback(iso);
}


static void ohci_iso_recv_bufferfill_task(struct hpsb_iso *iso, struct dma_iso_recv *recv)
{
	int loop;
	struct ti_ohci *ohci = recv->ohci;

	/* loop over all blocks */
	for (loop = 0; loop < recv->nblocks; loop++) {

		/* check block_dma to see if it's done */
		struct dma_cmd *im = &recv->block[recv->block_dma];

		/* check the DMA descriptor for new writes to xferStatus */
		u16 xferstatus = le32_to_cpu(im->status) >> 16;

		/* rescount is the number of bytes *remaining to be written* in the block */
		u16 rescount = le32_to_cpu(im->status) & 0xFFFF;

		unsigned char event = xferstatus & 0x1F;

		if (!event) {
			/* nothing has happened to this block yet */
			break;
		}

		if (event != 0x11) {
			atomic_inc(&iso->overflows);
			OHCI_ERR(
			      "IR DMA error - OHCI error code 0x%02x\n", event);
		}

		if (rescount != 0) {
			/* the card is still writing to this block;
			   we can't touch it until it's done */
			break;
		}

		/* OK, the block is finished... */

		/* sync our view of the block */
		dma_region_sync_for_cpu(&iso->data_buf, recv->block_dma*recv->buf_stride, recv->buf_stride);

		/* reset the DMA descriptor */
		im->status = recv->buf_stride;

		/* advance block_dma */
		recv->block_dma = (recv->block_dma + 1) % recv->nblocks;

		if ((recv->block_dma+1) % recv->nblocks == recv->block_reader) {
			atomic_inc(&iso->overflows);
			OHCI_NOTICE("ISO reception overflow - "
			       "ran out of DMA blocks");
		}
	}

	/* parse any packets that have arrived */
	ohci_iso_recv_bufferfill_parse(iso, recv);
}


static void ohci_iso_recv_packetperbuf_task(struct hpsb_iso *iso, struct dma_iso_recv *recv)
{
	int count;
	int wake = 0;
	struct ti_ohci *ohci = recv->ohci;

	/* loop over the entire buffer */
	for (count = 0; count < recv->nblocks; count++) {
		u32 packet_len = 0;

		/* pointer to the DMA descriptor */
		struct dma_cmd *il = ((struct dma_cmd*) recv->prog.kvirt) + iso->pkt_dma;

		/* check the DMA descriptor for new writes to xferStatus */
		u16 xferstatus = le32_to_cpu(il->status) >> 16;
		u16 rescount = le32_to_cpu(il->status) & 0xFFFF;

		unsigned char event = xferstatus & 0x1F;

		if (!event) {
			/* this packet hasn't come in yet; we are done for now */
			goto out;
		}

		if (event == 0x11) {
			/* packet received successfully! */

			/* rescount is the number of bytes *remaining* in the packet buffer,
			   after the packet was written */
			packet_len = recv->buf_stride - rescount;

		} else if (event == 0x02) {
			OHCI_ERR( "IR DMA error - packet too long for buffer\n");
		} else if (event) {
			OHCI_ERR( "IR DMA error - OHCI error code 0x%02x\n", event);
		}

		/* sync our view of the buffer */
		dma_region_sync_for_cpu(&iso->data_buf, iso->pkt_dma * recv->buf_stride, recv->buf_stride);

		/* record the per-packet info */
		{
			/* iso header is 8 bytes ahead of the data payload */
			unsigned char *hdr;

			unsigned int offset;
			unsigned short cycle;
			unsigned char channel, tag, sy;

			offset = iso->pkt_dma * recv->buf_stride;
			hdr = iso->data_buf.kvirt + offset;

			/* skip iso header */
			offset += 8;
			packet_len -= 8;

			cycle = (hdr[0] | (hdr[1] << 8)) & 0x1FFF;
			channel = hdr[5] & 0x3F;
			tag = hdr[5] >> 6;
			sy = hdr[4] & 0xF;

			hpsb_iso_packet_received(iso, offset, packet_len, cycle, channel, tag, sy);
		}

		/* reset the DMA descriptor */
		il->status = recv->buf_stride;

		wake = 1;
		recv->block_dma = iso->pkt_dma;
	}

out:
	if (wake)
		hpsb_iso_callback(iso);
}


static void ohci_iso_recv_task(unsigned long data)
{
	struct hpsb_iso *iso = (struct hpsb_iso*) data;
	struct dma_iso_recv *recv = iso->hostdata;

	if (recv->dma_mode == BUFFER_FILL_MODE){
		DEBUG_PRINT("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
		ohci_iso_recv_bufferfill_task(iso, recv);
	}
	else{
		DEBUG_PRINT("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
		ohci_iso_recv_packetperbuf_task(iso, recv);
	}
}

/***********************************
 * rawiso ISO transmission         *
 ***********************************/
static int ohci_iso_xmit_init(struct hpsb_iso *iso);
static int ohci_iso_xmit_start(struct hpsb_iso *iso, int cycle);
static void ohci_iso_xmit_shutdown(struct hpsb_iso *iso);
static void ohci_iso_xmit_task(unsigned long data);


static int ohci_iso_xmit_init(struct hpsb_iso *iso)
{
	struct dma_iso_xmit *xmit;
	unsigned int prog_size;
	int ctx;
	struct dma_base_ctx *base;
	int ret = -ENOMEM;

	xmit=kmalloc(sizeof(struct dma_iso_xmit), GFP_KERNEL);
	if(xmit==NULL)
		return -ENOMEM;
	base = (struct dma_base_ctx *)xmit;
	
	iso->hostdata = xmit;
	xmit->ohci = iso->host->hostdata;
	xmit->task_active = 0;

	dma_prog_region_init(&xmit->prog);

	prog_size = sizeof(struct iso_xmit_cmd) * iso->buf_packets;

	if (dma_prog_region_alloc(&xmit->prog, prog_size, xmit->ohci->dev))
		goto err;

	ohci1394_init_iso_ctx(base,OHCI_ISO_TRANSMIT,iso);

	if (ohci1394_register_iso_ctx(xmit->ohci, base) < 0) {
		ret = -EBUSY;
		goto err;
	}

	base->task_active = 1;

	/* xmit context registers are spaced 16 bytes apart */
	ctx = base->context;
	xmit->ctrlSet = OHCI1394_IsoXmitContextControlSet + 16 * ctx;
	xmit->ctrlClear = OHCI1394_IsoXmitContextControlClear + 16 * ctx;
	xmit->cmdPtr = OHCI1394_IsoXmitCommandPtr + 16 * ctx;

	return 0;

err:
	ohci_iso_xmit_shutdown(iso);
	return ret;
}


static void ohci_iso_xmit_stop(struct hpsb_iso *iso)
{
	struct dma_iso_xmit *xmit = iso->hostdata;
	struct ti_ohci *ohci = xmit->ohci;

	/* disable interrupts */
	reg_write(xmit->ohci, OHCI1394_IsoXmitIntMaskClear, 1 << xmit->context);

	/* halt DMA */
	if (ohci1394_stop_context(xmit->ohci, xmit->ctrlClear, NULL)) {
		/* XXX the DMA context will lock up if you try to send too much data! */
		OHCI_ERR(
		      "you probably exceeded the OHCI card's bandwidth limit - "
		      "reload the module and reduce xmit bandwidth");
	}
}


static void ohci_iso_xmit_shutdown(struct hpsb_iso *iso)
{
	struct dma_iso_xmit *xmit = iso->hostdata;

	if (xmit->task_active) {
		ohci_iso_xmit_stop(iso);
		ohci1394_unregister_iso_ctx(xmit->ohci, (struct dma_base_ctx *)&xmit);
		xmit->task_active = 0;
	}

	dma_prog_region_free(&xmit->prog);
	iso->hostdata = NULL;
	kfree(xmit);
}


static void ohci_iso_xmit_task(unsigned long data)
{
	struct hpsb_iso *iso = (struct hpsb_iso*) data;
	struct dma_iso_xmit *xmit = iso->hostdata;
	struct ti_ohci *ohci = xmit->ohci;
	int wake = 0;
	int count;

	/* check the whole buffer if necessary, starting at pkt_dma */
	for (count = 0; count < iso->buf_packets; count++) {
		int cycle;

		/* DMA descriptor */
		struct iso_xmit_cmd *cmd = dma_region_i(&xmit->prog, struct iso_xmit_cmd, iso->pkt_dma);

		/* check for new writes to xferStatus */
		u16 xferstatus = le32_to_cpu(cmd->output_last.status) >> 16;
		u8  event = xferstatus & 0x1F;

		/* do we reach the end? */
		if (!event) {
			/* packet hasn't been sent yet; we are done for now */
			break;
		}

		if (event != 0x11)
			OHCI_ERR(
			      "IT DMA error - OHCI error code 0x%02x\n", event);

		/* at least one packet went out, so wake up the writer */
		wake = 1;

		/* parse cycle */
		cycle = le32_to_cpu(cmd->output_last.status) & 0x1FFF;

		/* tell the subsystem the packet has gone out */
		hpsb_iso_packet_sent(iso, cycle, event != 0x11);

		/* reset the DMA descriptor for next time */
		cmd->output_last.status = 0;
	}

	if (wake)
		hpsb_iso_callback(iso);
}


static int ohci_iso_xmit_queue(struct hpsb_iso *iso, struct hpsb_iso_packet_info *info)
{
	struct dma_iso_xmit *xmit = iso->hostdata;
	struct ti_ohci *ohci = xmit->ohci;

	int next_i, prev_i;
	struct iso_xmit_cmd *next, *prev;

	unsigned int offset;
	unsigned short len;
	unsigned char tag, sy;

	/* check that the packet doesn't cross a page boundary
	   (we could allow this if we added OUTPUT_MORE descriptor support) */
	if (cross_bound(info->offset, info->len)) {
		OHCI_ERR(
		      "rawiso xmit: packet %u crosses a page boundary",
		      iso->first_packet);
		return -EINVAL;
	}

	offset = info->offset;
	len = info->len;
	tag = info->tag;
	sy = info->sy;

	/* sync up the card's view of the buffer */
	/*in 2.6 it is dma_region_sync_for_device(&iso->data_buf, offset, len) */
	dma_region_sync_for_device(&iso->data_buf, offset, len);

	/* append first_packet to the DMA chain */
	/* by linking the previous descriptor to it */
	/* (next will become the new end of the DMA chain) */

	next_i = iso->first_packet;
	prev_i = (next_i == 0) ? (iso->buf_packets - 1) : (next_i - 1);

	next = dma_region_i(&xmit->prog, struct iso_xmit_cmd, next_i);
	prev = dma_region_i(&xmit->prog, struct iso_xmit_cmd, prev_i);

	/* set up the OUTPUT_MORE_IMMEDIATE descriptor */
	memset(next, 0, sizeof(struct iso_xmit_cmd));
	next->output_more_immediate.control = cpu_to_le32(0x02000008);

	/* ISO packet header is embedded in the OUTPUT_MORE_IMMEDIATE */

	/* tcode = 0xA, and sy */
	next->iso_hdr[0] = 0xA0 | (sy & 0xF);

	/* tag and channel number */
	next->iso_hdr[1] = (tag << 6) | (iso->channel & 0x3F);

	/* transmission speed */
	next->iso_hdr[2] = iso->speed & 0x7;

	/* payload size */
	next->iso_hdr[6] = len & 0xFF;
	next->iso_hdr[7] = len >> 8;

	/* set up the OUTPUT_LAST */
	next->output_last.control = cpu_to_le32(1 << 28);
	next->output_last.control |= cpu_to_le32(1 << 27); /* update timeStamp */
	next->output_last.control |= cpu_to_le32(3 << 20); /* want interrupt */
	next->output_last.control |= cpu_to_le32(3 << 18); /* enable branch */
	next->output_last.control |= cpu_to_le32(len);

	/* payload bus address */
	next->output_last.address = cpu_to_le32(dma_region_offset_to_bus(&iso->data_buf, offset));

	/* leave branchAddress at zero for now */

	/* re-write the previous DMA descriptor to chain to this one */

	/* set prev branch address to point to next (Z=3) */
	prev->output_last.branchAddress = cpu_to_le32(
		dma_prog_region_offset_to_bus(&xmit->prog, sizeof(struct iso_xmit_cmd) * next_i) | 3);

	/* disable interrupt, unless required by the IRQ interval */
	if (prev_i % iso->irq_interval) {
		prev->output_last.control &= cpu_to_le32(~(3 << 20)); /* no interrupt */
	} else {
		prev->output_last.control |= cpu_to_le32(3 << 20); /* enable interrupt */
	}

	wmb();

	/* wake DMA in case it is sleeping */
	reg_write(xmit->ohci, xmit->ctrlSet, 1 << 12);

	/* issue a dummy read of the cycle timer to force all PCI
	   writes to be posted immediately */
	mb();
	reg_read(xmit->ohci, OHCI1394_IsochronousCycleTimer);

	return 0;
}
/**
 * @ingroup ohci
 * @anchor ohci_iso_xmit_start
 * this is to really steer the hardware
 */
static int ohci_iso_xmit_start(struct hpsb_iso *iso, int cycle)
{
	struct dma_iso_xmit *xmit = iso->hostdata;
	struct ti_ohci *ohci = xmit->ohci;

	/* clear out the control register */
	reg_write(xmit->ohci, xmit->ctrlClear, 0xFFFFFFFF);
	wmb();

	/* address and length of first descriptor block (Z=3) */
	reg_write(xmit->ohci, xmit->cmdPtr,
		  dma_prog_region_offset_to_bus(&xmit->prog, iso->pkt_dma * sizeof(struct iso_xmit_cmd)) | 3);

	/* cycle match */
	if (cycle != -1) {
		u32 start = cycle & 0x1FFF;

		/* 'cycle' is only mod 8000, but we also need two 'seconds' bits -
		   just snarf them from the current time */
		u32 seconds = reg_read(xmit->ohci, OHCI1394_IsochronousCycleTimer) >> 25;

		/* advance one second to give some extra time for DMA to start */
		seconds += 1;

		start |= (seconds & 3) << 13;

		reg_write(xmit->ohci, xmit->ctrlSet, 0x80000000 | (start << 16));
	}

	/* enable interrupts */
	reg_write(xmit->ohci, OHCI1394_IsoXmitIntMaskSet, 1 << xmit->context);

	/* run */
	reg_write(xmit->ohci, xmit->ctrlSet, 0x8000);
	mb();

	/* wait 100 usec to give the card time to go active */
	udelay(100);

	/* check the RUN bit */
	if (!(reg_read(xmit->ohci, xmit->ctrlSet) & 0x8000)) {
		OHCI_ERR( "Error starting IT DMA (ContextControl 0x%08x)\n",
		      reg_read(xmit->ohci, xmit->ctrlSet));
		return -1;
	}

	return 0;
}


/************************************/
/*     ISO Control from RT-FireWire  kernel	       */
/************************************/
/**
 * @ingroup ohci
 * @anchor ohci_isoctl
 * to parse the isoctl command from above
 */
static int ohci_isoctl(struct hpsb_iso *iso, enum isoctl_cmd cmd, unsigned long arg)
{

	switch(cmd) {
	case XMIT_INIT:
		return ohci_iso_xmit_init(iso);
	case XMIT_START:
		return ohci_iso_xmit_start(iso, arg);
	case XMIT_STOP:
		ohci_iso_xmit_stop(iso);
		return 0;
	case XMIT_QUEUE:
		return ohci_iso_xmit_queue(iso, (struct hpsb_iso_packet_info*) arg);
	case XMIT_SHUTDOWN:
		ohci_iso_xmit_shutdown(iso);
		return 0;

	case RECV_INIT:
		return ohci_iso_recv_init(iso);
	case RECV_START: 
	{
		int *args = (int*) arg;
		return ohci_iso_recv_start(iso, args[0], args[1], args[2]);
	}
	case RECV_STOP:
		ohci_iso_recv_stop(iso);
		return 0;
	case RECV_RELEASE:
		ohci_iso_recv_release(iso, (struct hpsb_iso_packet_info*) arg);
		return 0;
	case RECV_FLUSH:
		ohci_iso_recv_task((unsigned long) iso);
		return 0;
	case RECV_SHUTDOWN:
		ohci_iso_recv_shutdown(iso);
		return 0;
	case RECV_LISTEN_CHANNEL:
		ohci_iso_recv_change_channel(iso, arg, 1);
		return 0;
	case RECV_UNLISTEN_CHANNEL:
		ohci_iso_recv_change_channel(iso, arg, 0);
		return 0;
	case RECV_SET_CHANNEL_MASK:
		ohci_iso_recv_set_channel_mask(iso, *((u64*) arg));
		return 0;

	default:
		OHCI_ERR_G("ohci_isoctl cmd %d not implemented yet",
			cmd);
		break;
	}
	return -EINVAL;
}

/***************************************
 * IEEE-1394 functionality section END *
 ***************************************/


/********************************************************
 * Global stuff (interrupt handler, init/shutdown code) *
 ********************************************************/

/**
 * @ingroup ohci
 * @anchor dma_trm_reset
 * to rest the xmit context
 */
static void dma_trm_reset(struct dma_asyn_xmit *d)
{
	unsigned long flags;
	LIST_HEAD(packet_list);
	struct ti_ohci *ohci = d->ohci;
	struct hpsb_packet *packet, *ptmp;

	ohci1394_stop_context(ohci, d->ctrlClear, NULL);

	/*! Lock the context, reset it and release it. Move the packets
	 * that were pending in the context to packet_list and free
	 * them after releasing the lock. */

	rtos_spin_lock_irqsave(&d->lock, flags);

	list_splice(&d->fifo_list, &packet_list);
	list_splice(&d->pending_list, &packet_list);
	INIT_LIST_HEAD(&d->fifo_list);
	INIT_LIST_HEAD(&d->pending_list);

	d->branchAddrPtr = NULL;
	d->sent_ind = d->prg_ind;
	d->free_prgs = d->num_desc;

	rtos_spin_unlock_irqrestore(&d->lock, flags);

	if (list_empty(&packet_list))
		return;

	OHCI_NOTICE( "AT dma reset ctx=%d, aborting transmission", d->context);

	/*! Now process subsystem callbacks for the packets from this
	 * context. */
	list_for_each_entry_safe(packet, ptmp, &packet_list, driver_list) {
		list_del_init(&packet->driver_list);
		hpsb_packet_sent(ohci->host, packet, ACKX_ABORTED);
	}
}


static RTOS_IRQ_HANDLER_PROTO(ohci_irq_handler)
{
	quadlet_t event, node_id;
	struct ti_ohci *ohci = RTOS_IRQ_GET_ARG(struct ti_ohci);
	struct hpsb_host *host = ohci->host;
	int phyid = -1, isroot = 0;
	unsigned long flags;
	int tosync = 0;

	/* Read and clear the interrupt event register.  Don't clear
	 * the busReset event, though. This is done when we get the
	 * selfIDComplete interrupt. */
	rtos_spin_lock_irqsave(&ohci->event_lock, flags);
	event = reg_read(ohci, OHCI1394_IntEventClear);
	reg_write(ohci, OHCI1394_IntEventClear, event & ~OHCI1394_busReset);
	rtos_spin_unlock_irqrestore(&ohci->event_lock, flags);

	if (!event)
	{	
		rtos_irq_end(&ohci->irq_handle);
		RTOS_IRQ_RETURN_HANDLED();
	}

	/* If event is ~(u32)0 cardbus card was ejected.  In this case
	 * we just return, and clean up in the ohci1394_pci_remove
	 * function. */
	if (event == ~(u32) 0) {
		OHCI_NOTICE("Device removed.");
		rtos_irq_end(&ohci->irq_handle);
		RTOS_IRQ_RETURN_HANDLED();
	}

	OHCI_NOTICE("IntEvent: %08x", event);

	if (event & OHCI1394_unrecoverableError) {
		int ctx;
		OHCI_ERR( "Unrecoverable error!");

		if (reg_read(ohci, OHCI1394_AsReqTrContextControlSet) & 0x800)
			OHCI_ERR( "Async Req Tx Context died: "
				"ctrl[%08x] cmdptr[%08x]",
				reg_read(ohci, OHCI1394_AsReqTrContextControlSet),
				reg_read(ohci, OHCI1394_AsReqTrCommandPtr));

		if (reg_read(ohci, OHCI1394_AsRspTrContextControlSet) & 0x800)
			OHCI_ERR( "Async Rsp Tx Context died: "
				"ctrl[%08x] cmdptr[%08x]",
				reg_read(ohci, OHCI1394_AsRspTrContextControlSet),
				reg_read(ohci, OHCI1394_AsRspTrCommandPtr));

		if (reg_read(ohci, OHCI1394_AsReqRcvContextControlSet) & 0x800)
			OHCI_ERR( "Async Req Rcv Context died: "
				"ctrl[%08x] cmdptr[%08x]",
				reg_read(ohci, OHCI1394_AsReqRcvContextControlSet),
				reg_read(ohci, OHCI1394_AsReqRcvCommandPtr));

		if (reg_read(ohci, OHCI1394_AsRspRcvContextControlSet) & 0x800)
			OHCI_ERR( "Async Rsp Rcv Context died: "
				"ctrl[%08x] cmdptr[%08x]",
				reg_read(ohci, OHCI1394_AsRspRcvContextControlSet),
				reg_read(ohci, OHCI1394_AsRspRcvCommandPtr));

		for (ctx = 0; ctx < ohci->nb_iso_xmit_ctx; ctx++) {
			if (reg_read(ohci, OHCI1394_IsoXmitContextControlSet + (16 * ctx)) & 0x800)
				OHCI_ERR( "Iso Xmit %d Context died: "
					"ctrl[%08x] cmdptr[%08x]", ctx,
					reg_read(ohci, OHCI1394_IsoXmitContextControlSet + (16 * ctx)),
					reg_read(ohci, OHCI1394_IsoXmitCommandPtr + (16 * ctx)));
		}

		for (ctx = 0; ctx < ohci->nb_iso_rcv_ctx; ctx++) {
			if (reg_read(ohci, OHCI1394_IsoRcvContextControlSet + (32 * ctx)) & 0x800)
				OHCI_ERR( "Iso Recv %d Context died: "
					"ctrl[%08x] cmdptr[%08x] match[%08x]", ctx,
					reg_read(ohci, OHCI1394_IsoRcvContextControlSet + (32 * ctx)),
					reg_read(ohci, OHCI1394_IsoRcvCommandPtr + (32 * ctx)),
					reg_read(ohci, OHCI1394_IsoRcvContextMatch + (32 * ctx)));
		}

		event &= ~OHCI1394_unrecoverableError;
	}

	if (event & OHCI1394_cycleInconsistent) {
		/* We subscribe to the cycleInconsistent event only to
		 * clear the corresponding event bit... otherwise,
		 * isochronous cycleMatch DMA won't work. */
		OHCI_NOTICE("OHCI1394_cycleInconsistent");
		event &= ~OHCI1394_cycleInconsistent;
	}

	if (event & OHCI1394_busReset) {
		/* The busReset event bit can't be cleared during the
		 * selfID phase, so we disable busReset interrupts, to
		 * avoid burying the cpu in interrupt requests. */
		rtos_spin_lock_irqsave(&ohci->event_lock, flags);
		reg_write(ohci, OHCI1394_IntMaskClear, OHCI1394_busReset);

		if (ohci->check_busreset) {
			int loop_count = 0;

			udelay(10);

			while (reg_read(ohci, OHCI1394_IntEventSet) & OHCI1394_busReset) {
				reg_write(ohci, OHCI1394_IntEventClear, OHCI1394_busReset);

				rtos_spin_unlock_irqrestore(&ohci->event_lock, flags);
				udelay(10);
				rtos_spin_lock_irqsave(&ohci->event_lock, flags);

				/*! The loop counter check is to prevent the driver
				 * from remaining in this state forever. For the
				 * initial bus reset, the loop continues for ever
				 * and the system hangs, until some device is plugged-in
				 * or out manually into a port! The forced reset seems
				 * to solve this problem. This mainly effects nForce2. */
				if (loop_count > 10000) {
					ohci_devctl(host, RESET_BUS, LONG_RESET);
					OHCI_NOTICE("Detected bus-reset loop. Forced a bus reset!");
					loop_count = 0;
				}

				loop_count++;
			}
		}
		rtos_spin_unlock_irqrestore(&ohci->event_lock, flags);
		if (!host->in_bus_reset) {
			OHCI_NOTICE("irq_handler: Bus reset requested");
			/* Subsystem call */
			hpsb_bus_reset(ohci->host);
		}
		event &= ~OHCI1394_busReset;
	}

	if (event & OHCI1394_reqTxComplete) {
		struct dma_asyn_xmit *d = &ohci->at_req_context;
		OHCI_NOTICE("Got reqTxComplete interrupt "
		       "status=0x%08X", reg_read(ohci, d->ctrlSet));
		if (reg_read(ohci, d->ctrlSet) & 0x800)
			ohci1394_stop_context(ohci, d->ctrlClear,
					      "reqTxComplete");
		else
			rt_event_pend(&d->event);
			tosync = 1;
		event &= ~OHCI1394_reqTxComplete;
	}
	if (event & OHCI1394_respTxComplete) {
		struct dma_asyn_xmit *d = &ohci->at_resp_context;
		OHCI_NOTICE("Got respTxComplete interrupt "
		       "status=0x%08X", reg_read(ohci, d->ctrlSet));
		if (reg_read(ohci, d->ctrlSet) & 0x800){
			ohci1394_stop_context(ohci, d->ctrlClear,
					      "respTxComplete");
		}
		else
			rt_event_pend(&d->event);
			tosync = 1;
		event &= ~OHCI1394_respTxComplete;
	}
	if (event & OHCI1394_RQPkt) {
		struct dma_asyn_recv *d = &ohci->ar_req_context;
		OHCI_NOTICE("Got RQPkt interrupt status=0x%08X",
		       reg_read(ohci, d->ctrlSet));
		if (reg_read(ohci, d->ctrlSet) & 0x800)
			ohci1394_stop_context(ohci, d->ctrlClear, "RQPkt");
		else
			rt_event_pend(&d->event);
			tosync = 1;
		event &= ~OHCI1394_RQPkt;
		if(timing_probe && pacnt < 10000){
			time_pair[pacnt].paval=rtos_get_time();
			pacnt++;
		}
	}
	if (event & OHCI1394_RSPkt) {
		struct dma_asyn_recv *d = &ohci->ar_resp_context;
		OHCI_NOTICE("Got RSPkt interrupt status=0x%08X",
		       reg_read(ohci, d->ctrlSet));
		if (reg_read(ohci, d->ctrlSet) & 0x800)
			ohci1394_stop_context(ohci, d->ctrlClear, "RSPkt");
		else
			rt_event_pend(&d->event);
			tosync = 1;
		event &= ~OHCI1394_RSPkt;
	}
	if (event & OHCI1394_isochRx) {
		quadlet_t rx_event;

		rx_event = reg_read(ohci, OHCI1394_IsoRecvIntEventSet);
		reg_write(ohci, OHCI1394_IsoRecvIntEventClear, rx_event);
		{
			struct dma_base_ctx *d;
			unsigned long mask,flags;
			int find=0;

			rtos_spin_lock_irqsave(&ohci->iso_ctx_list_lock, flags);

			list_for_each_entry(d, &ohci->iso_ctx_list, link) {
				mask = 1 << d->context;
				if (d->type == OHCI_ISO_RECEIVE && rx_event & mask){
					find=1;
					break;
				}
			}
			rtos_spin_unlock_irqrestore(&ohci->iso_ctx_list_lock, flags);
			if(find==1){
				tosync = 1;
				rt_event_pend(&d->event);
			}
		}
		
		event &= ~OHCI1394_isochRx;
	}
	if (event & OHCI1394_isochTx) {
		quadlet_t tx_event;
		int find=0;

		tx_event = reg_read(ohci, OHCI1394_IsoXmitIntEventSet);
		reg_write(ohci, OHCI1394_IsoXmitIntEventClear, tx_event);
		{
			struct dma_base_ctx *d;
			unsigned long mask,flags;

			rtos_spin_lock_irqsave(&ohci->iso_ctx_list_lock, flags);

			list_for_each_entry(d, &ohci->iso_ctx_list, link) {
				mask = 1 << d->context;
				if (d->type == OHCI_ISO_TRANSMIT && tx_event & mask){
					find = 1;
					break;
				}
			}
			rtos_spin_unlock_irqrestore(&ohci->iso_ctx_list_lock, flags);
			if(find==1){
				tosync = 1;
				rt_event_pend(&d->event);
			}
		}
		event &= ~OHCI1394_isochTx;
	}
	/**
	 * Now we still keep the selfid processing in Tophalf of interrupt handling. 
	 * But it may need to be moved to BH,*/
	if (event & OHCI1394_selfIDComplete) {
		if (host->in_bus_reset) {
			node_id = reg_read(ohci, OHCI1394_NodeID);

			if (!(node_id & 0x80000000)) {
				OHCI_ERR(
				      "SelfID received, but NodeID invalid "
				      "(probably new bus reset occurred): %08X",
				      node_id);
				goto selfid_not_valid;
			}

			phyid =  node_id & 0x0000003f;
			isroot = (node_id & 0x40000000) != 0;

			OHCI_NOTICE("SelfID interrupt received "
			      "(phyid %d, %s)", phyid,
			      (isroot ? "root" : "not root"));

			handle_selfid(ohci, host, phyid, isroot);

			/* Clear the bus reset event and re-enable the
			 * busReset interrupt.  */
			rtos_spin_lock_irqsave(&ohci->event_lock, flags);
			reg_write(ohci, OHCI1394_IntEventClear, OHCI1394_busReset);
			reg_write(ohci, OHCI1394_IntMaskSet, OHCI1394_busReset);
			rtos_spin_unlock_irqrestore(&ohci->event_lock, flags);

			/* Accept Physical requests from all nodes. */
			reg_write(ohci,OHCI1394_AsReqFilterHiSet, 0xffffffff);
			reg_write(ohci,OHCI1394_AsReqFilterLoSet, 0xffffffff);

			/* Turn on phys dma reception.
			 *
			 * TODO: Enable some sort of filtering management.
			 */
			if (phys_dma) {
				reg_write(ohci,OHCI1394_PhyReqFilterHiSet, 0xffffffff);
				reg_write(ohci,OHCI1394_PhyReqFilterLoSet, 0xffffffff);
				reg_write(ohci,OHCI1394_PhyUpperBound, 0xffff0000);
			} else {
				reg_write(ohci,OHCI1394_PhyReqFilterHiSet, 0x00000000);
				reg_write(ohci,OHCI1394_PhyReqFilterLoSet, 0x00000000);
			}

			OHCI_NOTICE("PhyReqFilter=%08x%08x",
			       reg_read(ohci,OHCI1394_PhyReqFilterHiSet),
			       reg_read(ohci,OHCI1394_PhyReqFilterLoSet));

			hpsb_selfid_complete(host, phyid, isroot);
		} else
			OHCI_ERR(
			      "SelfID received outside of bus reset sequence");

selfid_not_valid:
		event &= ~OHCI1394_selfIDComplete;
	}

	/* Make sure we handle everything, just in case we accidentally
	 * enabled an interrupt that we didn't write a handler for.  */
	if (event)
		OHCI_ERR( "Unhandled interrupt(s) 0x%08x",
		      event);

	/**
	 * in 2.6, its IRQ_HANDLED insteadof nothing
	 */
	if(tosync==1)
		rt_irq_broker_sync();
	
	rtos_irq_end(&ohci->irq_handle);
	RTOS_IRQ_RETURN_HANDLED();
}

/* Put the buffer back into the dma context */
static void insert_dma_buffer(struct dma_asyn_recv *d, int idx)
{
	struct ti_ohci *ohci = (struct ti_ohci*)(d->ohci);
	OHCI_NOTICE("Inserting dma buf ctx=%d idx=%d", d->context, idx);

	d->prg_cpu[idx]->status = cpu_to_le32(d->buf_size);
	d->prg_cpu[idx]->branchAddress &= le32_to_cpu(0xfffffff0);
	idx = (idx + d->num_desc - 1 ) % d->num_desc;
	d->prg_cpu[idx]->branchAddress |= le32_to_cpu(0x00000001);

	/* To avoid a race, ensure 1394 interface hardware sees the inserted
	 * context program descriptors before it sees the wakeup bit set. */
	wmb();
	
	/* wake up the dma context if necessary */
	if (!(reg_read(ohci, d->ctrlSet) & 0x400)) {
		OHCI_NOTICE(
		      "Waking dma ctx=%d ... processing is probably too slow",
		      d->context);
	}

	/* do this always, to avoid race condition */
	reg_write(ohci, d->ctrlSet, 0x1000);
}

#define cond_le32_to_cpu(data, noswap) \
	(noswap ? data : le32_to_cpu(data))

static const int TCODE_SIZE[16] = {20, 0, 16, -1, 16, 20, 20, 0,
			    -1, 0, -1, 0, -1, -1, 16, -1};

/*
 * Determine the length of a packet in the buffer (in bytes)
 * Optimization suggested by Pascal Drolet <pascal.drolet@informission.ca>
 */
static __inline__ int packet_length(struct dma_asyn_recv *d, int idx, quadlet_t *buf_ptr,
			 int offset, unsigned char tcode, int noswap)
{
	int length = -1;
	struct dma_base_ctx *dbase = (struct dma_base_ctx *)d;
	
	if (dbase->type == ASYNC_REQ_RECEIVE || dbase->type == ASYNC_RESP_RECEIVE) {
		length = TCODE_SIZE[tcode];
		if (length == 0) {
			if (offset + 12 >= d->buf_size) {
				length = (cond_le32_to_cpu(d->buf_cpu[(idx + 1) % d->num_desc]
						[3 - ((d->buf_size - offset) >> 2)], noswap) >> 16);
			} else {
				length = (cond_le32_to_cpu(buf_ptr[3], noswap) >> 16);
			}
			length += 20;
		}
	} else if (dbase->type == OHCI_ISO_RECEIVE 
		|| dbase->type == OHCI_ISO_MULTICHANNEL_RECEIVE) {
		/* Assumption: buffer fill mode with header/trailer */
		length = (cond_le32_to_cpu(buf_ptr[0], noswap) >> 16) + 8;
	}

	if (length > 0 && length % 4)
		length += 4 - (length % 4);

	return length;
}


/* Tasklet that processes dma receive buffers */
static void dma_rcv_routine (unsigned long data)
{
	struct dma_asyn_recv *d;
	nanosecs_t time_stamp;
	struct hpsb_packet *pkt;
	struct ti_ohci *ohci;
	unsigned int split_left, idx, offset, rescount;
	unsigned char tcode;
	int length, bytes_left;
	unsigned long flags;
	quadlet_t *buf_ptr;
	char *split_ptr;
	char msg[256];
	
	if(timing_probe && pbcnt < 10000){
		time_pair[pbcnt].pbval = rtos_get_time();
		pbcnt++;
	}
	time_stamp = rtos_get_time();
	
	d = (struct dma_asyn_recv*)data;
	ohci = d->ohci;
	
	rtos_spin_lock_irqsave(&d->lock, flags);

	pkt = hpsb_alloc_packet(0,&d->pool,0);
	if(!pkt) {
		rtos_print("%s:out of memory\n", __FUNCTION__);
		return;
	}
	
	d->spb = pkt->data;
	idx = d->buf_ind;
	offset = d->buf_offset;
	buf_ptr = d->buf_cpu[idx] + offset/4;

	rescount = le32_to_cpu(d->prg_cpu[idx]->status) & 0xffff;
	bytes_left = d->buf_size - rescount - offset;

	while (bytes_left > 0) {
		tcode = (cond_le32_to_cpu(buf_ptr[0], ohci->no_swap_incoming) >> 4) & 0xf;

		/* packet_length() will return < 4 for an error */
		length = packet_length(d, idx, buf_ptr, offset, tcode, ohci->no_swap_incoming);

		if (length < 4) { /* something is wrong */
			sprintf(msg,"Unexpected tcode 0x%x(0x%08x) in AR ctx=%d, length=%d",
				tcode, cond_le32_to_cpu(buf_ptr[0], ohci->no_swap_incoming),
				d->context, length);
			ohci1394_stop_context(ohci, d->ctrlClear, msg);
			rtos_spin_unlock_irqrestore(&d->lock, flags);
			return;
		}
		
		/* The first case is where we have a packet that crosses
		 * over more than one descriptor. The next case is where
		 * it's all in the first descriptor.  */
		if ((offset + length) > d->buf_size) {
			OHCI_NOTICE("Split packet rcv'd");
			if (length > d->split_buf_size) {
				ohci1394_stop_context(ohci, d->ctrlClear,
					     "Split packet size exceeded");
				d->buf_ind = idx;
				d->buf_offset = offset;
				rtos_spin_unlock_irqrestore(&d->lock, flags);
				hpsb_free_packet(pkt);
				return;
			}

			if (le32_to_cpu(d->prg_cpu[(idx+1)%d->num_desc]->status)
			    == d->buf_size) {
				/* Other part of packet not written yet.
				 * this should never happen I think
				 * anyway we'll get it on the next call.  */
				OHCI_NOTICE(
				      "Got only half a packet!");
				d->buf_ind = idx;
				d->buf_offset = offset;
				rtos_spin_unlock_irqrestore(&d->lock, flags);
				return;
			}

			split_left = length;
			split_ptr = (char *)pkt->data;
			memcpy(split_ptr,buf_ptr,d->buf_size-offset);
			split_left -= d->buf_size-offset;
			split_ptr += d->buf_size-offset;
			insert_dma_buffer(d, idx);
			idx = (idx+1) % d->num_desc;
			buf_ptr = d->buf_cpu[idx];
			offset=0;

			while (split_left >= d->buf_size) {
				memcpy(split_ptr,buf_ptr,d->buf_size);
				split_ptr += d->buf_size;
				split_left -= d->buf_size;
				insert_dma_buffer(d, idx);
				idx = (idx+1) % d->num_desc;
				buf_ptr = d->buf_cpu[idx];
			}

			if (split_left > 0) {
				memcpy(split_ptr, buf_ptr, split_left);
				offset = split_left;
				buf_ptr += offset/4;
			}
		} else {
			OHCI_NOTICE("Single packet rcv'd");
			memcpy(pkt->data, buf_ptr, length);
			offset += length;
			buf_ptr += length/4;
			if (offset==d->buf_size) {
				insert_dma_buffer(d, idx);
				idx = (idx+1) % d->num_desc;
				buf_ptr = d->buf_cpu[idx];
				offset=0;
			}
		}

		/* We get one phy packet to the async descriptor for each
		 * bus reset. We always ignore it.  */
		if (tcode != OHCI1394_TCODE_PHY) {
			if (!ohci->no_swap_incoming)
				packet_swab(d->spb, tcode);
			OHCI_NOTICE("Packet received from node"
				" %d ack=0x%02X spd=%d tcode=0x%X"
				" length=%d ctx=%d tlabel=%d",
				(d->spb[1]>>16)&0x3f,
				(cond_le32_to_cpu(d->spb[length/4-1], ohci->no_swap_incoming)>>16)&0x1f,
				(cond_le32_to_cpu(d->spb[length/4-1], ohci->no_swap_incoming)>>21)&0x3,
				tcode, length, d->context,
				(cond_le32_to_cpu(d->spb[0], ohci->no_swap_incoming)>>10)&0x3f);

			pkt->write_acked = (((cond_le32_to_cpu(pkt->data[length/4-1], ohci->no_swap_incoming)>>16)&0x1f)
				== 0x11) ? 1 : 0;
			pkt->pri = cond_le32_to_cpu(d->spb[0], ohci->no_swap_incoming)&0xf;
			pkt->host = ohci->host;
			pkt->tcode = tcode;
			/* according to tcode, seperate the header from data */
			pkt->header_size = hdr_sizes[tcode] * sizeof(quadlet_t);
			pkt->header = pkt->data;
			pkt->data = (quadlet_t *)((u8 *)pkt->data+pkt->header_size);
			pkt->data_size = length - 4 - pkt->header_size;
			
		#ifdef CONFIG_OHCI1394_DEBUG
			int i;
			quadlet_t *data_p = pkt->header;
			
			rtos_print("\n=========data dump (header size:%d  data size:%d)==========\n", pkt->header_size, pkt->data_size);
			for(i=0; i < (pkt->header_size/4); i++){
				rtos_print("%08X ", data_p[i]);
			}
			rtos_print("\n");
			
			data_p = pkt->data;
			for(i=0; i < (pkt->data_size/4); i++){
				rtos_print("%08X ", data_p[i]);
			}
			rtos_print("\n\n");
		#endif
			pkt->time_stamp = time_stamp; /*arrival time*/
			
			hpsb_packet_received(pkt);
		}
		else{ 
			OHCI_NOTICE( "Got phy packet ctx=%d ... discarded",
			       d->context);
			hpsb_free_packet(pkt);//we dont hand on phy packet, so free it here. 
		}
		

	       	rescount = le32_to_cpu(d->prg_cpu[idx]->status) & 0xffff;

		bytes_left = d->buf_size - rescount - offset;

	}

	d->buf_ind = idx;
	d->buf_offset = offset;

	rtos_spin_unlock_irqrestore(&d->lock, flags);
}
/**
 * @ingroup ohci
 * ISR Bottom half that processes sent packets 
*/
static void dma_trm_routine (unsigned long data)
{
	struct dma_asyn_xmit *d = (struct dma_asyn_xmit*)data;
	struct ti_ohci *ohci = (struct ti_ohci*)(d->ohci);
	struct hpsb_packet *packet, *ptmp;
	unsigned long flags;
	u32 status, ack;
        size_t datasize;

	rtos_spin_lock_irqsave(&d->lock, flags);
	
	list_for_each_entry_safe(packet, ptmp, &d->fifo_list, driver_list) {
                datasize = packet->data_size;
		if (datasize && packet->type != hpsb_raw)
			status = le32_to_cpu(
				d->prg_cpu[d->sent_ind]->end.status) >> 16;
		else
			status = le32_to_cpu(
				d->prg_cpu[d->sent_ind]->begin.status) >> 16;

		if (status == 0)
			/* this packet hasn't been sent yet*/
			break;

		if (datasize) {
			if (((le32_to_cpu(d->prg_cpu[d->sent_ind]->data[0])>>4)&0xf) == 0xa)
				OHCI_NOTICE("Stream packet sent to channel %d tcode=0x%X "
				       "ack=0x%X spd=%d dataLength=%d ctx=%d",
				       (le32_to_cpu(d->prg_cpu[d->sent_ind]->data[0])>>8)&0x3f,
				       (le32_to_cpu(d->prg_cpu[d->sent_ind]->data[0])>>4)&0xf,
				       status&0x1f, (status>>5)&0x3,
				       le32_to_cpu(d->prg_cpu[d->sent_ind]->data[1])>>16,
				       d->context);
			else
				OHCI_NOTICE("Packet sent to node %d tcode=0x%X tLabel="
				       "%d ack=0x%X spd=%d dataLength=%d ctx=%d",
				       (le32_to_cpu(d->prg_cpu[d->sent_ind]->data[1])>>16)&0x3f,
				       (le32_to_cpu(d->prg_cpu[d->sent_ind]->data[0])>>4)&0xf,
				       (le32_to_cpu(d->prg_cpu[d->sent_ind]->data[0])>>10)&0x3f,
				       status&0x1f, (status>>5)&0x3,
				       le32_to_cpu(d->prg_cpu[d->sent_ind]->data[3])>>16,
				       d->context);
		}
		else {
			OHCI_NOTICE("Packet sent to node %d tcode=0x%X tLabel="
			       "%d ack=0x%X spd=%d data=0x%08X ctx=%d",
                                (le32_to_cpu(d->prg_cpu[d->sent_ind]->data[1])
                                        >>16)&0x3f,
                                (le32_to_cpu(d->prg_cpu[d->sent_ind]->data[0])
                                        >>4)&0xf,
                                (le32_to_cpu(d->prg_cpu[d->sent_ind]->data[0])
                                        >>10)&0x3f,
                                status&0x1f, (status>>5)&0x3,
                                le32_to_cpu(d->prg_cpu[d->sent_ind]->data[3]),
                                d->context);
		}

		if (status & 0x10) {
			ack = status & 0xf;
		} else {
			switch (status & 0x1f) {
			case EVT_NO_STATUS: /* that should never happen */
			case EVT_RESERVED_A: /* that should never happen */
			case EVT_LONG_PACKET: /* that should never happen */
				OHCI_NOTICE( "Received OHCI evt_* error 0x%x", status & 0x1f);
				ack = ACKX_SEND_ERROR;
				break;
			case EVT_MISSING_ACK:
				ack = ACKX_TIMEOUT;
				break;
			case EVT_UNDERRUN:
				ack = ACKX_SEND_ERROR;
				break;
			case EVT_OVERRUN: /* that should never happen */
				OHCI_NOTICE( "Received OHCI evt_* error 0x%x", status & 0x1f);
				ack = ACKX_SEND_ERROR;
				break;
			case EVT_DESCRIPTOR_READ:
			case EVT_DATA_READ:
			case EVT_DATA_WRITE:
				ack = ACKX_SEND_ERROR;
				break;
			case EVT_BUS_RESET: /* that should never happen */
				OHCI_NOTICE( "Received OHCI evt_* error 0x%x", status & 0x1f);
				ack = ACKX_SEND_ERROR;
				break;
			case EVT_TIMEOUT:
				ack = ACKX_TIMEOUT;
				break;
			case EVT_TCODE_ERR:
				ack = ACKX_SEND_ERROR;
				break;
			case EVT_RESERVED_B: /* that should never happen */
			case EVT_RESERVED_C: /* that should never happen */
				OHCI_NOTICE( "Received OHCI evt_* error 0x%x", status & 0x1f);
				ack = ACKX_SEND_ERROR;
				break;
			case EVT_UNKNOWN:
			case EVT_FLUSHED:
				ack = ACKX_SEND_ERROR;
				break;
			default:
				OHCI_ERR( "Unhandled OHCI evt_* error 0x%x", status & 0x1f);
				ack = ACKX_SEND_ERROR;
			}
		}

		if (datasize) {
			#ifdef	CONFIG_OHCI1394_DEBUG
				int i;
				quadlet_t *data = packet->data;
				for(i=0;i < datasize; i++){
					rtos_print("%08X ", data[i]);
				}
				rtos_print("\n");					
			#endif
				
			pci_unmap_single(ohci->dev,
					 cpu_to_le32(d->prg_cpu[d->sent_ind]->end.address),
					 datasize, PCI_DMA_TODEVICE);
			OHCI_NOTICE("single Xmit data packet");
		}

		d->sent_ind = (d->sent_ind+1)%d->num_desc;
		d->free_prgs++;
		
		list_del_init(&packet->driver_list);
		hpsb_packet_sent(ohci->host, packet, ack);
	}

	dma_trm_flush(ohci, d);

	rtos_spin_unlock_irqrestore(&d->lock, flags);
}


static void free_dma_asyn_recv(struct dma_asyn_recv *d)
{
	int i;
	struct ti_ohci *ohci = d->ohci;

	if (ohci == NULL)
		return;

	OHCI_NOTICE("Freeing dma_asyn_recv %d", d->context);

	if (d->buf_cpu) {
		for (i=0; i<d->num_desc; i++)
			if (d->buf_cpu[i] && d->buf_bus[i]) {
				pci_free_consistent(
					ohci->dev, d->buf_size,
					d->buf_cpu[i], d->buf_bus[i]);
				OHCI_NOTICE("consistent dma_rcv buf[%d]", i);
			}
		kfree(d->buf_cpu);
		kfree(d->buf_bus);
	}
	if (d->prg_cpu) {
		for (i=0; i<d->num_desc; i++)
			if (d->prg_cpu[i] && d->prg_bus[i]) {
				pci_pool_free(d->prg_pool, d->prg_cpu[i], d->prg_bus[i]);
				OHCI_NOTICE("consistent dma_rcv prg[%d]", i);
			}
		pci_pool_destroy(d->prg_pool);
		OHCI_NOTICE("dma_rcv prg pool");
		kfree(d->prg_cpu);
		kfree(d->prg_bus);
	}
	rtpkb_pool_release(&d->pool);

	/* Mark this context as freed. */
	d->ohci = NULL;
}


static int
alloc_dma_asyn_recv(struct ti_ohci *ohci, struct dma_asyn_recv *d,
		  enum context_type type, int ctx, int num_desc,
		  int buf_size,int split_buf_size, int context_base)
{
	int i;
	static char pool_name[32];

	d->ohci = ohci;
	d->type = type;
	d->context = ctx;;

	d->num_desc = num_desc;
	d->buf_size =d->split_buf_size = buf_size;

	d->ctrlSet = 0;
	d->ctrlClear = 0;
	d->cmdPtr = 0;

	d->buf_cpu = kmalloc(d->num_desc * sizeof(quadlet_t*), GFP_ATOMIC);
	d->buf_bus = kmalloc(d->num_desc * sizeof(dma_addr_t), GFP_ATOMIC);

	if (d->buf_cpu == NULL || d->buf_bus == NULL) {
		OHCI_ERR( "Failed to allocate dma buffer");
		free_dma_asyn_recv(d);
		return -ENOMEM;
	}
	memset(d->buf_cpu, 0, d->num_desc * sizeof(quadlet_t*));
	memset(d->buf_bus, 0, d->num_desc * sizeof(dma_addr_t));

	d->prg_cpu = kmalloc(d->num_desc * sizeof(struct dma_cmd*),
				GFP_ATOMIC);
	d->prg_bus = kmalloc(d->num_desc * sizeof(dma_addr_t), GFP_ATOMIC);

	if (d->prg_cpu == NULL || d->prg_bus == NULL) {
		OHCI_ERR( "Failed to allocate dma prg");
		free_dma_asyn_recv(d);
		return -ENOMEM;
	}
	memset(d->prg_cpu, 0, d->num_desc * sizeof(struct dma_cmd*));
	memset(d->prg_bus, 0, d->num_desc * sizeof(dma_addr_t));

	if(type==ASYNC_REQ_RECEIVE)
		sprintf(pool_name, "areq_rcv%d", cards_found);
	else
		if(type==ASYNC_RESP_RECEIVE)
			sprintf(pool_name, "aresp_rcv%d", cards_found);


	d->prg_pool = pci_pool_create(pool_name, ohci->dev,
				sizeof(struct dma_cmd), 4, 0);


	if(d->prg_pool == NULL)
	{
		OHCI_ERR( "pci_pool_create failed for %s", pool_name);
		free_dma_asyn_recv(d);
		return -ENOMEM;
	}

	OHCI_NOTICE("asyn_recv prg pool");

	for (i=0; i<d->num_desc; i++) {
		d->buf_cpu[i] = pci_alloc_consistent(ohci->dev,
						     d->buf_size,
						     d->buf_bus+i);
		OHCI_NOTICE("consistent asyn_recv buf[%d]", i);

		if (d->buf_cpu[i] != NULL) {
			memset(d->buf_cpu[i], 0, d->buf_size);
		} else {
			OHCI_ERR(
			      "Failed to allocate dma buffer");
			free_dma_asyn_recv(d);
			return -ENOMEM;
		}

		d->prg_cpu[i] = pci_pool_alloc(d->prg_pool, SLAB_KERNEL, d->prg_bus+i);
		OHCI_NOTICE("pool asyn_recv prg[%d]", i);

                if (d->prg_cpu[i] != NULL) {
                        memset(d->prg_cpu[i], 0, sizeof(struct dma_cmd));
		} else {
			OHCI_ERR(
			      "Failed to allocate dma prg");
			free_dma_asyn_recv(d);
			return -ENOMEM;
		}
	}

        rtos_spin_lock_init(&d->lock);
	
	/**only one buffer object is needed, 
	just to temporarily contain the incoming packet
	**/
	rtpkb_pool_init(&d->pool,10);
	sprintf(d->pool.name, pool_name);
	
	d->ctrlSet = context_base + OHCI1394_ContextControlSet;
	d->ctrlClear = context_base + OHCI1394_ContextControlClear;
	d->cmdPtr = context_base + OHCI1394_ContextCommandPtr;
	
	/** we use the same name as of pci pool*/
	rt_event_init(&d->event, pool_name, dma_rcv_routine, (unsigned long)d);
	
	return 0;
}

static void free_dma_asyn_xmit(struct dma_asyn_xmit *d)
{
	int i;
	struct ti_ohci *ohci = d->ohci;

	if (ohci == NULL)
		return;

	OHCI_NOTICE("Freeing dma_asyn_xmit %d", d->context);

	if (d->prg_cpu) {
		for (i=0; i<d->num_desc; i++)
			if (d->prg_cpu[i] && d->prg_bus[i]) {
				pci_pool_free(d->prg_pool, d->prg_cpu[i], d->prg_bus[i]);
				OHCI_NOTICE("pool dma_trm prg[%d]", i);
			}
		pci_pool_destroy(d->prg_pool);
		OHCI_NOTICE("dma_trm prg pool");
		kfree(d->prg_cpu);
		kfree(d->prg_bus);
	}
	
	/* Mark this context as freed. */
	d->ohci = NULL;
}


static int
alloc_dma_asyn_xmit(struct ti_ohci *ohci, struct dma_asyn_xmit *d,
		  enum context_type type, int ctx, int num_desc,
		  int context_base)
{
	int i;
	static char pool_name[32];
	
	d->ohci = ohci;
	d->type = type;
	d->context = ctx;
	d->num_desc = num_desc;
	d->ctrlSet = 0;
	d->ctrlClear = 0;
	d->cmdPtr = 0;

	d->prg_cpu = kmalloc(d->num_desc * sizeof(struct at_dma_prg*),
			     GFP_KERNEL);
	d->prg_bus = kmalloc(d->num_desc * sizeof(dma_addr_t), GFP_KERNEL);

	if (d->prg_cpu == NULL || d->prg_bus == NULL) {
		OHCI_ERR( "Failed to allocate at dma prg");
		free_dma_asyn_xmit(d);
		return -ENOMEM;
	}
	memset(d->prg_cpu, 0, d->num_desc * sizeof(struct at_dma_prg*));
	memset(d->prg_bus, 0, d->num_desc * sizeof(dma_addr_t));

	if(type==ASYNC_REQ_TRANSMIT)
		sprintf(pool_name, "areq_trm%d", cards_found);
	else
		if(type==ASYNC_RESP_TRANSMIT)
			sprintf(pool_name, "aresp_trm%d", cards_found);

	d->prg_pool = pci_pool_create(pool_name, ohci->dev,
				sizeof(struct at_dma_prg), 4, 0);
				
	if (d->prg_pool == NULL) {
		OHCI_ERR( "pci_pool_create failed for %s", pool_name);
		free_dma_asyn_xmit(d);
		return -ENOMEM;
	}

	OHCI_NOTICE("asyn_xmit prg pool");

	for (i = 0; i < d->num_desc; i++) {
		/*!allocate the prg block memory and setup its corresponding dma bus address */
		d->prg_cpu[i] = pci_pool_alloc(d->prg_pool, SLAB_KERNEL, d->prg_bus+i);
		OHCI_NOTICE("asyn_xmit prg pool[%d]", i);

                if (d->prg_cpu[i] != NULL) {
                        memset(d->prg_cpu[i], 0, sizeof(struct at_dma_prg));
		} else {
			OHCI_ERR(
			      "Failed to allocate at dma prg");
			free_dma_asyn_xmit(d);
			return -ENOMEM;
		}
	}

        rtos_spin_lock_init(&d->lock);
	
	d->ctrlSet = context_base + OHCI1394_ContextControlSet;
	d->ctrlClear = context_base + OHCI1394_ContextControlClear;
	d->cmdPtr = context_base + OHCI1394_ContextCommandPtr;

	rt_event_init(&d->event, pool_name, dma_trm_routine, (unsigned long)d);
	
	sprintf(d->name, pool_name);

	return 0;
}

static void ohci_set_hw_config_rom(struct hpsb_host *host, quadlet_t *config_rom)
{
	struct ti_ohci *ohci = host->hostdata;

	reg_write(ohci, OHCI1394_ConfigROMhdr, be32_to_cpu(config_rom[0]));
	reg_write(ohci, OHCI1394_BusOptions, be32_to_cpu(config_rom[2]));

	memcpy(ohci->csr_config_rom_cpu, config_rom, OHCI_CONFIG_ROM_LEN);
}


static quadlet_t ohci_hw_csr_reg(struct hpsb_host *host, int reg,
                                 quadlet_t data, quadlet_t compare)
{
	struct ti_ohci *ohci = host->hostdata;
	int i;

	reg_write(ohci, OHCI1394_CSRData, data);
	reg_write(ohci, OHCI1394_CSRCompareData, compare);
	reg_write(ohci, OHCI1394_CSRControl, reg & 0x3);

	for (i = 0; i < OHCI_LOOP_COUNT; i++) {
		if (reg_read(ohci, OHCI1394_CSRControl) & 0x80000000)
			break;

		mdelay(1);
	}

	return reg_read(ohci, OHCI1394_CSRData);
}


static struct hpsb_host_driver ohci1394_driver = {
	.owner =		THIS_MODULE,
	.name =			OHCI1394_DRIVER_NAME,
	.set_hw_config_rom =	ohci_set_hw_config_rom,
	.transmit_packet =	ohci_transmit,
	.devctl =		ohci_devctl,
	.isoctl =               ohci_isoctl,
	.hw_csr_reg =		ohci_hw_csr_reg,
};



/***********************************
 * OHCI1394 SPEC Interface functions  *
 ***********************************/
void ohci_remove1(struct ti_ohci *ohci)
{
	switch (ohci->init_state) {
	case OHCI_INIT_DONE:
		host_unregister(ohci->host);
		/* Clear out BUS Options */
		reg_write(ohci, OHCI1394_ConfigROMhdr, 0);
		reg_write(ohci, OHCI1394_BusOptions,
			  (reg_read(ohci, OHCI1394_BusOptions) & 0x0000f007) |
			  0x00ff0000);
		memset(ohci->csr_config_rom_cpu, 0, OHCI_CONFIG_ROM_LEN);

	case OHCI_INIT_HAVE_IRQ:
		/* Clear interrupt registers */
		reg_write(ohci, OHCI1394_IntMaskClear, 0xffffffff);
		reg_write(ohci, OHCI1394_IntEventClear, 0xffffffff);
		reg_write(ohci, OHCI1394_IsoXmitIntMaskClear, 0xffffffff);
		reg_write(ohci, OHCI1394_IsoXmitIntEventClear, 0xffffffff);
		reg_write(ohci, OHCI1394_IsoRecvIntMaskClear, 0xffffffff);
		reg_write(ohci, OHCI1394_IsoRecvIntEventClear, 0xffffffff);

		/* Disable IRM Contender */
		set_phy_reg(ohci, 4, ~0xc0 & get_phy_reg(ohci, 4));
		
		/* Clear link control register */
		reg_write(ohci, OHCI1394_LinkControlClear, 0xffffffff);

		/* Let all other nodes know to ignore us */
		ohci_devctl(ohci->host, RESET_BUS, LONG_RESET_NO_FORCE_ROOT);

		/* Soft reset before we start - this disables
		 * interrupts and clears linkEnable and LPS. */
		ohci_soft_reset(ohci);
		if(rtos_irq_free(&ohci->irq_handle)<0)
			OHCI_ERR("failed to free irq\n");
		
	case OHCI_INIT_HAVE_TXRX_BUFFERS__MAYBE:
		/* Free AR dma */
		free_dma_asyn_recv(&ohci->ar_req_context);
		free_dma_asyn_recv(&ohci->ar_resp_context);

		/* Free AT dma */
		free_dma_asyn_xmit(&ohci->at_req_context);
		free_dma_asyn_xmit(&ohci->at_resp_context);

	case OHCI_INIT_HAVE_SELFID_BUFFER:
		pci_free_consistent(ohci->dev, OHCI1394_SI_DMA_BUF_SIZE, 
				    ohci->selfid_buf_cpu,
				    ohci->selfid_buf_bus);
		OHCI_NOTICE("consistent selfid_buf");
		
	case OHCI_INIT_HAVE_CONFIG_ROM_BUFFER:
		pci_free_consistent(ohci->dev, OHCI_CONFIG_ROM_LEN,
				    ohci->csr_config_rom_cpu,
				    ohci->csr_config_rom_bus);
		OHCI_NOTICE("consistent csr_config_rom");

	case OHCI_INIT_HAVE_IOMAPPING:
		iounmap(ohci->registers);

#ifdef CONFIG_ALL_PPC
	/* On UniNorth, power down the cable and turn off the chip
	 * clock when the module is removed to save power on
	 * laptops. Turning it back ON is done by the arch code when
	 * pci_enable_device() is called */
	{
		struct device_node* of_node;

		of_node = pci_device_to_OF_node(ohci->dev);
		if (of_node) {
			pmac_call_feature(PMAC_FTR_1394_ENABLE, of_node, 0, 0);
			pmac_call_feature(PMAC_FTR_1394_CABLE_POWER, of_node, 0, 0);
		}
	}
#endif /* CONFIG_ALL_PPC */

	case OHCI_INIT_ALLOC_HOST:
		break;
	}
	
	if(ohci->host)
		host_free(ohci->host);
}


#define FAIL(err, fmt, args...)			\
do {						\
	OHCI_ERR_G(fmt , ## args);	\
        ohci1394_pci_remove(pdev);               \
	return err;				\
} while (0)

int ohci_found1(struct pci_dev *pdev)
{
	struct hpsb_host *host=NULL;
	/*! shortcut to currently handled device*/
	struct ti_ohci *ohci;
	unsigned long ohci_base;
	int ret;
	
	host=host_alloc(sizeof(struct ti_ohci));
	if(!host)
		FAIL(-ENOMEM,"cant allocated new host structure\n");
	
	host->driver = &ohci1394_driver;
	host_alloc_name(host,"fwhost%d");
	RTOS_SET_MODULE_OWNER(host);
	host->pdev = pdev;
	host->type = HOST_TYPE_OHCI1394;
	
	ohci = host->hostdata;
	ohci->dev = pdev;
	ohci->host = host;
	ohci->init_state = OHCI_INIT_ALLOC_HOST;
	pci_set_drvdata(pdev, ohci);
	/* We don't want hardware swapping */
	pci_write_config_dword(pdev, OHCI1394_PCI_HCI_Control, 0);

	/* Some oddball Apple controllers do not order the selfid
	 * properly, so we make up for it here.  */
#ifndef __LITTLE_ENDIAN
	/* XXX: Need a better way to check this. I'm wondering if we can
	 * read the values of the OHCI1394_PCI_HCI_Control and the
	 * noByteSwapData registers to see if they were not cleared to
	 * zero. Should this work? Obviously it's not defined what these
	 * registers will read when they aren't supported. Bleh! */
	if (pdev->vendor == PCI_VENDOR_ID_APPLE && 
	    pdev->device == PCI_DEVICE_ID_APPLE_UNI_N_FW) {
		ohci->no_swap_incoming = 1;
		ohci->selfid_swap = 0;
	} else
		ohci->selfid_swap = 1;
#endif

#ifndef PCI_DEVICE_ID_NVIDIA_NFORCE2_FW
#define PCI_DEVICE_ID_NVIDIA_NFORCE2_FW 0x006e
#endif

	/* These chipsets require a bit of extra care when checking after
	 * a busreset.  */
	if ((pdev->vendor == PCI_VENDOR_ID_APPLE &&
	     pdev->device == PCI_DEVICE_ID_APPLE_UNI_N_FW) ||
	    (pdev->vendor ==  PCI_VENDOR_ID_NVIDIA &&
	     pdev->device == PCI_DEVICE_ID_NVIDIA_NFORCE2_FW))
		ohci->check_busreset = 1;

	ohci_base = pci_resource_start(pdev, 0);	
	ohci->init_state = OHCI_INIT_HAVE_MEM_REGION;

	ohci->registers = ioremap(ohci_base, OHCI1394_REGISTER_SIZE);
	if (ohci->registers == NULL)
		FAIL(-ENXIO, "Failed to remap registers - card not accessible\n");
	host->base_addr = (unsigned long)ohci->registers;
	
	ohci->init_state = OHCI_INIT_HAVE_IOMAPPING;
	OHCI_NOTICE("Remapped memory spaces reg 0x%p\n", ohci->registers);
	
	/* csr_config rom allocation */
	ohci->csr_config_rom_cpu =
		pci_alloc_consistent(ohci->dev, OHCI_CONFIG_ROM_LEN,
				     &ohci->csr_config_rom_bus);
	OHCI_NOTICE("consistent csr_config_rom\n");
	if (ohci->csr_config_rom_cpu == NULL)
		FAIL(-ENOMEM, "Failed to allocate buffer config rom\n");
	ohci->init_state = OHCI_INIT_HAVE_CONFIG_ROM_BUFFER;

	/* self-id dma buffer allocation */
	ohci->selfid_buf_cpu = 
		pci_alloc_consistent(ohci->dev, OHCI1394_SI_DMA_BUF_SIZE,
                      &ohci->selfid_buf_bus);
	OHCI_NOTICE("consistent selfid_buf\n");
	if (ohci->selfid_buf_cpu == NULL)
		FAIL(-ENOMEM, "Failed to allocate DMA buffer for self-id packets\n");
	ohci->init_state = OHCI_INIT_HAVE_SELFID_BUFFER;

	if ((unsigned long)ohci->selfid_buf_cpu & 0x1fff)
		OHCI_NOTICE( "SelfID buffer %p is not aligned on "
		      "8Kb boundary... may cause problems on some CXD3222 chip\n", 
		      ohci->selfid_buf_cpu);  

	/* No self-id errors at startup */
	ohci->self_id_errors = 0;

	ohci->init_state = OHCI_INIT_HAVE_TXRX_BUFFERS__MAYBE;
	/* AR DMA request context allocation */
	if (alloc_dma_asyn_recv(ohci, &ohci->ar_req_context,
			      ASYNC_REQ_RECEIVE, 0, AR_REQ_NUM_DESC,
			      AR_REQ_BUF_SIZE,AR_REQ_SPLIT_BUF_SIZE,
			      OHCI1394_AsReqRcvContextBase) < 0)
		FAIL(-ENOMEM, "Failed to allocate AR Req context\n");

	/* AR DMA response context allocation */
	if (alloc_dma_asyn_recv(ohci, &ohci->ar_resp_context,
			      ASYNC_RESP_RECEIVE, 0, AR_RESP_NUM_DESC,
			      AR_RESP_BUF_SIZE,AR_RESP_SPLIT_BUF_SIZE,
			      OHCI1394_AsRspRcvContextBase) < 0)
		FAIL(-ENOMEM, "Failed to allocate AR Resp context\n");

	/* AT DMA request context */
	if (alloc_dma_asyn_xmit(ohci, &ohci->at_req_context,
			      ASYNC_REQ_TRANSMIT, 0, AT_REQ_NUM_DESC,
			      OHCI1394_AsReqTrContextBase) < 0)
		FAIL(-ENOMEM, "Failed to allocate AT Req context\n");

	/* AT DMA response context */
	if (alloc_dma_asyn_xmit(ohci, &ohci->at_resp_context,
			      ASYNC_RESP_TRANSMIT, 1, AT_RESP_NUM_DESC,
			      OHCI1394_AsRspTrContextBase) < 0)
		FAIL(-ENOMEM, "Failed to allocate AT Resp context\n");
	
	/* Start off with a soft reset, to clear everything to a sane
	 * state. */
	ohci_soft_reset(ohci);

	/* Now enable LPS, which we need in order to start accessing
	 * most of the registers.  In fact, on some cards (ALI M5251),
	 * accessing registers in the SClk domain without LPS enabled
	 * will lock up the machine.  Wait 50msec to make sure we have
	 * full link enabled.  */
	reg_write(ohci, OHCI1394_HCControlSet, OHCI1394_HCControl_LPS);
	mdelay(50);

	/* Determine the number of available IR and IT contexts. */
	ohci->nb_iso_rcv_ctx =
		get_nb_iso_ctx(ohci, OHCI1394_IsoRecvIntMaskSet);
	OHCI_NOTICE("%d iso receive contexts available\n",
	       ohci->nb_iso_rcv_ctx);
	host->nb_iso_rcv_ctx = ohci->nb_iso_rcv_ctx;

	ohci->nb_iso_xmit_ctx =
		get_nb_iso_ctx(ohci, OHCI1394_IsoXmitIntMaskSet);
	OHCI_NOTICE("%d iso transmit contexts available\n",
	       ohci->nb_iso_xmit_ctx);
	host->nb_iso_xmit_ctx = ohci->nb_iso_xmit_ctx;

	/* Set the usage bits for non-existent contexts so they can't
	 * be allocated */
	host->ir_ctx_usage = ~0 << ohci->nb_iso_rcv_ctx;
	host->it_ctx_usage = ~0 << ohci->nb_iso_xmit_ctx;
	ohci->ir_ctx_usage = ~0 << ohci->nb_iso_rcv_ctx;
	ohci->it_ctx_usage = ~0 << ohci->nb_iso_xmit_ctx;

	INIT_LIST_HEAD(&ohci->iso_ctx_list);
	rtos_spin_lock_init(&ohci->iso_ctx_list_lock);
	ohci->ISO_channel_usage = 0;
        rtos_spin_lock_init(&ohci->IR_channel_lock);

	/* the IR DMA context is allocated on-demand; mark it inactive */
	//~ ohci->ir_legacy_context.ohci = NULL;
	/* same for the IT DMA context */
	//~ ohci->it_legacy_context.ohci = NULL;

	ohci->id = cards_found;
	if (rtos_irq_request(&ohci->irq_handle,pdev->irq, ohci_irq_handler, ohci)){
		FAIL(-ENOMEM, "Failed to allocate interrupt %d", pdev->irq);
	}else{
		OHCI_NOTICE( "irq: %d requested",pdev->irq);
	}
	rtos_irq_enable(&ohci->irq_handle);
	host->irq = pdev->irq;
			
	ohci->init_state = OHCI_INIT_HAVE_IRQ;
	ohci_initialize(ohci);
	/*! set certain csr values */
	host->csr.guid_hi = reg_read(ohci, OHCI1394_GUIDHi);
	host->csr.guid_lo = reg_read(ohci, OHCI1394_GUIDLo);
	*(u64 *)host->dev_id = (((u64)host->csr.guid_hi)<<32)|host->csr.guid_lo;
	host->csr.cyc_clk_acc = 100; /*! how can we determine clk accuracy? */
	host->csr.max_rec = (reg_read(ohci, OHCI1394_BusOptions) >> 12) & 0xf;
	host->max_packet_size = 1<<(host->csr.max_rec+1);
	host->csr.lnk_spd = reg_read(ohci, OHCI1394_BusOptions) & 0x7;
	host->mmio_start = 	pci_resource_start(ohci->dev, 0);
	host->mmio_end	=	pci_resource_start(ohci->dev, 0) + OHCI1394_REGISTER_SIZE - 1;
	
	if ( (ret=host_register(host)) )
		FAIL(ret, "Failed to register new host");
	
	ohci->init_state = OHCI_INIT_DONE;
	return ret;
	
#undef FAIL
}	

/***********************************
 * PCI Driver Interface functions  *
 ***********************************/
static int __devinit ohci1394_pci_probe(struct pci_dev *pdev,
					const struct pci_device_id *ent)
{
	static int version_printed = 0;
	int ret=0;
	
	if(cards_found >= cards)
		goto err_out_none;

	/* Seems PCMCIA handles this internally. Not sure why. Seems
	 * pretty bogus to force a driver to special case this.  */
#ifndef PCMCIA
	if (!request_mem_region(pci_resource_start(pdev, 0),
			pci_resource_len(pdev, 0), "ohci1394")) {
		OHCI_ERR_G("cannot reserve MMIO region\n");
		goto err_out_free_pio_region;
	}
#endif
	
	/* We hardwire the MMIO length, since some CardBus adaptors
	 * fail to report the right length.  Anyway, the ohci spec
	 * clearly says it's 2kb, so this shouldn't be a problem. */ 
	
	if (pci_resource_len(pdev, 0) != OHCI1394_REGISTER_SIZE)
		OHCI_ERR_G("unexpected PCI resource length of %lx!\n",
		      pci_resource_len(pdev, 0));
	
	if (version_printed++ == 0)
		rtos_print("%s\n", version);

        if (pci_enable_device(pdev)){
		OHCI_ERR_G("Failed to enable OHCI hardware %d\n",
		        cards_found++);
		goto err_out_free_mmio_region;
	}
	
        pci_set_master(pdev);
	
	if (!(ret=ohci_found1(pdev)))
		cards_found++;
	else
		goto err_out_free_mmio_region;

	return ret;

err_out_free_mmio_region:
	release_mem_region(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
err_out_free_pio_region:
	release_region(pci_resource_start(pdev, 1), pci_resource_len(pdev, 1));
err_out_none:
	return ret;
}

static void ohci1394_pci_remove(struct pci_dev *pdev)
{
	struct ti_ohci *ohci;

	ohci = pci_get_drvdata(pdev);
	if (ohci)
		ohci_remove1(ohci);

#ifndef PCMCIA
	release_mem_region(pci_resource_start(pdev, 0), pci_resource_len(pdev,0));
#endif
	
	pci_set_drvdata(pdev,NULL);
	
	pci_disable_device(pdev);
}
	

#ifdef  CONFIG_PM
static int ohci1394_pci_resume (struct pci_dev *dev)
{
	pci_enable_device(dev);
	return 0;
}
#endif


#define PCI_CLASS_FIREWIRE_OHCI     ((PCI_CLASS_SERIAL_FIREWIRE << 8) | 0x10)

/**
 * @addtogroup ohci
 *@{*/
static struct pci_device_id ohci1394_pci_tbl[] = {
	{
		.class = 	PCI_CLASS_FIREWIRE_OHCI,
		.class_mask = 	PCI_ANY_ID,
		.vendor =	PCI_ANY_ID,
		.device =	PCI_ANY_ID,
		.subvendor =	PCI_ANY_ID,
		.subdevice =	PCI_ANY_ID,
	},
	{ 0, },
};

MODULE_DEVICE_TABLE(pci, ohci1394_pci_tbl);

static struct pci_driver ohci1394_pci_driver = {
	.name =		OHCI1394_DRIVER_NAME,
	.id_table =	ohci1394_pci_tbl,
	.probe =	ohci1394_pci_probe,
	.remove =	ohci1394_pci_remove,
#ifdef CONFIG_PM
	.resume =	ohci1394_pci_resume,
#endif
};

/*@}*/



/***********************************
 * OHCI1394 Video Interface        *
 ***********************************/

int ohci1394_stop_context(struct ti_ohci *ohci, int reg, char *msg)
{
	int i=0;

	/* stop the channel program if it's still running */
	reg_write(ohci, reg, 0x8000);

	/* Wait until it effectively stops */
	while (reg_read(ohci, reg) & 0x400) {
		i++;
		if (i>5000) {
			OHCI_ERR(
			      "Runaway loop while stopping context: %s...", msg ? msg : "");
			return 1;
		}

		mb();
		udelay(10);
	}
	if (msg) OHCI_ERR( "%s: dma prg stopped", msg);
	return 0;
}


void ohci1394_init_iso_ctx(struct dma_base_ctx *d, int type, struct hpsb_iso *iso)
{	
	d->type = type;
	
	switch(type){
		case OHCI_ISO_TRANSMIT:
			rt_event_init(&d->event ,d->name, ohci_iso_xmit_task, (unsigned long)iso);
			break;
		case OHCI_ISO_RECEIVE:
			OHCI_ISO_MULTICHANNEL_RECEIVE:
			rt_event_init(&d->event, d->name, ohci_iso_recv_task, (unsigned long)iso);
			break;
		default:
			break;
	}
}


int ohci1394_register_iso_ctx(struct ti_ohci *ohci,
				  struct dma_base_ctx *d)
{
	unsigned long flags, *usage;
	int n, i, r = -EBUSY;

	if (d->type == OHCI_ISO_TRANSMIT) {
		n = ohci->nb_iso_xmit_ctx;
		usage = &ohci->it_ctx_usage;
	}
	else {
		n = ohci->nb_iso_rcv_ctx;
		usage = &ohci->ir_ctx_usage;

		/* only one receive context can be multichannel (OHCI sec 10.4.1) */
		if (d->type == OHCI_ISO_MULTICHANNEL_RECEIVE) {
			if (test_and_set_bit(0, &ohci->ir_multichannel_used)) {
				return r;
			}
		}
	}

	rtos_spin_lock_irqsave(&ohci->iso_ctx_list_lock, flags);

	for (i = 0; i < n; i++)
		if (!test_and_set_bit(i, usage)) {
			d->context = i;
			list_add_tail(&d->link, &ohci->iso_ctx_list);
			r = 0;
			break;
		}

	rtos_spin_unlock_irqrestore(&ohci->iso_ctx_list_lock, flags);

	return r;
}


void ohci1394_unregister_iso_ctx(struct ti_ohci *ohci,
				     struct dma_base_ctx *d)
{
	unsigned long flags;

	rtos_spin_lock_irqsave(&ohci->iso_ctx_list_lock, flags);

	if (d->type == OHCI_ISO_TRANSMIT)
		clear_bit(d->context, &ohci->it_ctx_usage);
	else {
		clear_bit(d->context, &ohci->ir_ctx_usage);

		if (d->type == OHCI_ISO_MULTICHANNEL_RECEIVE) {
			clear_bit(0, &ohci->ir_multichannel_used);
		}
	}

	list_del(&d->link);

	rtos_spin_unlock_irqrestore(&ohci->iso_ctx_list_lock, flags);
}

EXPORT_SYMBOL(ohci1394_stop_context);
EXPORT_SYMBOL(ohci1394_init_iso_ctx);
EXPORT_SYMBOL(ohci1394_register_iso_ctx);
EXPORT_SYMBOL(ohci1394_unregister_iso_ctx);


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
/*==================== for data reduction =======================*/
#define MAX_BIN 200
struct bin {
	int val;
	int counter;
};

struct bin binG[MAX_BIN];
#define BIN_STEP 1000 //1 microsecond

static int timing_read_proc(char *page, char **start, off_t off, int count,
					int *eof, void *data)
{
	off_t begin=0, pos=0;
	int len=0;
	int i;
	
	if(timing_probe && pacnt ==10000 && pbcnt == 10000){
		 for(i=0;i<MAX_BIN;i++){
			binG[i].val=0;
			binG[i].counter=0;
		}
		while(pacnt >= 0 ){
			int latency_round = ((int)(time_pair[pbcnt].pbval - time_pair[pacnt].paval)/BIN_STEP) *BIN_STEP;
			for(i=0;i<MAX_BIN;i++){
				if(binG[i].val==0)
					binG[i].val=latency_round;
				if(binG[i].val==latency_round){
					binG[i].counter+=1;
					break;
				}
			}
			time_pair[pbcnt].pbval = time_pair[pacnt].paval =0;
			pacnt = pbcnt = pacnt - 1;
		}
		PUTF("\n\n==============================================\n\n");
		for(i=0;i<MAX_BIN;i++){
			if(binG[i].val!=0)
				PUTF("%d - bin val:%d, bin counter: %d\n", i, binG[i].val, binG[i].counter);
		}
		PUTF("\n\n==============================================\n\n");

done_proc:
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
	else{
		PUTF("Timing probe not enabled or the measurment not finished yet!\n");
		return len;
	}
		
}
#undef PUTF

/***********************************
 * General module initialization   *
 ***********************************/

MODULE_DESCRIPTION("Real-Time Driver for PCI OHCI IEEE-1394 controllers (RT-FireWire)");
MODULE_LICENSE("GPL");

static void __exit ohci1394_cleanup (void)
{
	pci_unregister_driver(&ohci1394_pci_driver);
	remove_proc_entry("ohci_isr_timing",0);
}

static int __init ohci1394_init(void)
{
	struct proc_dir_entry *proc_entry;
	proc_entry = create_proc_entry("ohci_isr_timing", S_IFREG | S_IRUGO | S_IWUSR, 0);
	if(!proc_entry) {
		rtos_print("failed to create proc entry!\n");
		return -ENOMEM;
	}
	proc_entry->read_proc = timing_read_proc;
	
	return pci_module_init(&ohci1394_pci_driver);
}

module_init(ohci1394_init);
module_exit(ohci1394_cleanup);
