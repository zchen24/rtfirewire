#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <ieee1394_chrdev.h>

#define PRINT_FLAG_ALL 1
#define PRINT_FLAG_INACTIVE 2

int f;
struct ieee1394_core_cmd cmd;

void help(void)
{
	fprintf(stderr, "Usage:\n"
	"\thostconfig [-a] [<dev>]\n"
	"\thostconfig [<dev>] up\n"
	"\thostconfig [<dev>] down\n"
	);
	
	exit(1);
}
	
void print_dev(void)
{
	unsigned int flags;
	
	cmd.head.if_name[9]=0;
	
	printf("\n%-9s Medium: ", cmd.head.if_name);
	
	if ((cmd.args.info.flags & IFF_DUMMY) != 0)
		printf("Local Loopback\n");
	else if (cmd.args.info.type == HOST_TYPE_OHCI1394)
		printf("OHCI1394   G-U-ID: "
			"%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
               cmd.args.info.dev_id[0], cmd.args.info.dev_id[1],
               cmd.args.info.dev_id[2], cmd.args.info.dev_id[3],
               cmd.args.info.dev_id[4], cmd.args.info.dev_id[5],
		cmd.args.info.dev_id[6], cmd.args.info.dev_id[7]);
	else
		printf("unknown (%X)\n", cmd.args.info.type);
	
	printf("          Bus Generation:%d  Node ID:%d  IRM:%d  Bus Manager:%d\n",
			cmd.args.info.generation, cmd.args.info.node_id,
			cmd.args.info.irm_id, cmd.args.info.busmgr_id);
	
	printf("          Pending Packets:%d\n", cmd.args.info.pending_packets);
	
	flags = cmd.args.info.flags &
        (IFF_UP | IFF_BROADCAST | IFF_DUMMY| IFF_RUNNING | IFF_PROMISC);
	printf("          %s%s%s%s%s%s Max Packet Size: %d\n",
           ((flags & IFF_UP) != 0) ? "UP " : "",
           ((flags & IFF_BROADCAST) != 0) ? "BROADCAST " : "",
           ((flags & IFF_DUMMY) != 0) ? "DUMMY " : "",
           ((flags & IFF_RUNNING) != 0) ? "RUNNING " : "",
           ((flags & IFF_PROMISC) != 0) ? "PROMISC " : "",
           (flags == 0) ? "[NO FLAGS] " : "", cmd.args.info.max_packet_size);
	
	printf("          Interrupt:%d  Base Address:%lx  Memory:%lx-%lx\n",
			cmd.args.info.irq, cmd.args.info.base_addr, 
			cmd.args.info.mmio_start, cmd.args.info.mmio_end);
	
	printf("          Iso xmit DMA ctx:%d   Usage:%x\n",
			cmd.args.info.nb_iso_xmit_ctx, cmd.args.info.it_ctx_usage);
	printf("          Iso rcv DMA ctx:%d   Usage:%x\n",
			cmd.args.info.nb_iso_rcv_ctx, cmd.args.info.ir_ctx_usage);		
	
	if(cmd.args.info.node_id == cmd.args.info.irm_id)
	printf("          Isochronous BW:%d	 Channels:%llx\n\n",
			cmd.args.info.bw_remaining, cmd.args.info.channels);
	else
	printf("\n");
	
}

void do_display(int print_flags)
{
	int i;
	int ret;
	
	if((print_flags & PRINT_FLAG_ALL) !=0 )
		for (i=1; i <= MAX_RT_HOSTS; i++) {
			cmd.args.info.ifindex = i;
			
			ret=ioctl(f, IOC_RTFW_IFINFO, &cmd);
			if(ret==0) {
				if(((print_flags & PRINT_FLAG_INACTIVE)!=0) ||
					((cmd.args.info.flags & IFF_RUNNING)!=0))
					print_dev();
			}else if (errno != ENODEV) {
				perror("ioctl");
				exit(1);
			}
	}
	else {
			cmd.args.info.ifindex = 0;
		
			ret=ioctl(f, IOC_RTFW_IFINFO, &cmd);
			if(ret<0) {
				perror("ioctl");
				exit(1);
			}
			print_dev();
	}
	exit(0);
}

void do_up(int argc, char *argv[])
{
	int ret;
	
	if(argc>3)
		help();
	
	ret = ioctl(f, IOC_RTFW_IFUP, &cmd);
	if(ret<0){
		perror("ioctl");
		exit(1);
	}
	exit(0);
}

void do_down(int argc, char *argv[])
{
	int ret;
	
	if(argc>3)
		help();
	
	ret = ioctl(f, IOC_RTFW_IFDOWN, &cmd);
	if(ret<0){
		perror("ioctl");
		exit(1);
	}
	exit(0);
}


int main(int argc, char *argv[])
{	
	if((argc>1) && (strcmp(argv[1], "--help")==0))
		help();
	
	f = open("/dev/rt-firewire",O_RDWR);
	if(f<0) {
		perror("/dev/rt-firewire");
		exit(1);
	}
	
	if(argc==1)
		do_display(PRINT_FLAG_ALL);
	
	if(strcmp(argv[1],"-a")==0) {
		if(argc==3) {
			strncpy(cmd.head.if_name, argv[1], IFNAMSIZ);
			do_display(PRINT_FLAG_INACTIVE);
		} else
			do_display(PRINT_FLAG_INACTIVE | PRINT_FLAG_ALL);
	}else
		strncpy(cmd.head.if_name, argv[1], IFNAMSIZ);
		
	if(argc<3)
		do_display(0);
	
	if(strcmp(argv[2],"up")==0)
		do_up(argc, argv);
	if(strcmp(argv[2],"down")==0)
		do_down(argc,argv);
	/**
	 * we can add more options here
	 */
	help();
	
	return 0;
}
