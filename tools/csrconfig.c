/***
 *
 *  tools/rtping.c
 *  sends real-time bus internal echo requests
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <ieee1394_chrdev.h>
#include <bis1394.h>


int             f;
struct bis_cmd cmd;

void help(void)
{
    fprintf(stderr, "Usage:\n"
        "\tcsrconfig [-h host] [-d destid] [-o offset] [-t type]\n"
        );

    exit(1);
}



int getintopt(int argc, int pos, char *argv[], int min)
{
    int result;


    if (pos >= argc)
        help();
    if ((sscanf(argv[pos], "%u", &result) != 1) || (result < min)) {
        fprintf(stderr, "invalid parameter: %s %s\n", argv[pos-1], argv[pos]);
        exit(1);
    }

    return result;
}



void do_csr_access(void)
{
	int ret;
	
	ret = ioctl(f, IOC_RTFW_CSR_RAW,&cmd);
	
	if(ret<0){
		perror("ioctl");
		exit(1);
	}
	exit(0);
}


int main(int argc, char *argv[])
{
    const char          dev[] = "/dev/rt-firewire";
    int                 i;

    //we need local host name and remote destination id	
    if (argc < 3)
        help();

    for (i = 1; i < argc-1; i++) {
	if(strcmp(argv[i], "-h") == 0){
	    strncpy(cmd.head.if_name, argv[++i], IFNAMSIZ);
	}
        else if (strcmp(argv[i], "-d") == 0)
            cmd.args.csr_raw.destid = getintopt(argc, ++i, argv, 0);
        else if (strcmp(argv[i], "-o") == 0) 
            cmd.args.csr_raw.offset = getintopt(argc, ++i, argv, 0);
	else if (strcmp(argv[i], "-t")  == 0) 
	    cmd.args.csr_raw.type = getintopt(argc, ++i, argv, 0);
	else
            help();
    }

    f = open(dev, O_RDWR);
    if (f < 0) {
        perror(dev);
        exit(1);
    }

    do_csr_access();
    return 0;
}


	