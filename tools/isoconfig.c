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
        "\tisoconfig -h [host] -c [channel] -s [data buffer size]\n"
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

void do_iso(void)
{
	int ret;
	
	printf("%d, %d\n", cmd.args.iso.channel, cmd.args.iso.data_buf_size);
	if(cmd.args.iso.channel==-1){
		printf("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
		ret = ioctl(f, IOC_RTFW_ISO_SHUTDOWN, &cmd);
	}
	else
		ret = ioctl(f, IOC_RTFW_ISO_START,&cmd);
	
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

	cmd.args.iso.channel = 1;
	cmd.args.iso.data_buf_size = 500;
	
    for (i = 1; i < argc-1; i++) {
	if(strcmp(argv[i], "-h") == 0){
		printf("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
	    strncpy(cmd.head.if_name, argv[++i], IFNAMSIZ);
	}
	else if (strcmp(argv[i],"-t")==0){
		printf("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
	    cmd.args.iso.channel = -1;
		break;
	}
        else if (strcmp(argv[i], "-c") == 0){
		printf("pointer to %s(%s)%d\n",__FILE__,__FUNCTION__,__LINE__);
            cmd.args.iso.channel = getintopt(argc, ++i, argv, 1);
	}
        else if (strcmp(argv[i], "-s") == 0) {
            cmd.args.iso.data_buf_size = getintopt(argc, ++i, argv, 0);
            if (cmd.args.iso.data_buf_size > 4096)
                cmd.args.iso.data_buf_size = 4096;
        } else
            help();
    }

    f = open(dev, O_RDWR);
    if (f < 0) {
        perror(dev);
        exit(1);
    }

    do_iso();
    
    return 0;
}


