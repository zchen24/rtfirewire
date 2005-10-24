/***
 *
 *  tools/rtping.c
 *  sends real-time bus internal echo requests
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <ieee1394_chrdev.h>
#include <bis1394.h>


int             f;
struct bis_cmd cmd;
int             delay    = 1000;
unsigned int    sent     = 0;
unsigned int    received = 0;
float           wc_rtt   = 0;
int max_count = 10000;

/*==================== for data reduction =======================*/
#define MAX_BIN 200
int i;

struct bin {
	int val;
	int counter;
};

struct bin binG[MAX_BIN];

/*=============================================================*/

void help(void)
{
    fprintf(stderr, "Usage:\n"
        "\trtping [-h host] [-d destid] [-i interval] [-s packetsize] [-p priority]\n"
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



void print_statistics()
{
    printf("\n--- %s and %d roundtripping statistics ---\n"
           "%d packets transmitted, %d received, %d%% packet loss\n"
           "worst case rtt = %.1f us\n",
           cmd.head.if_name, cmd.args.ping.destid, 
		sent, received, 100 - ((received * 100) / sent),
           wc_rtt);
	
	 for(i=0;i<MAX_BIN;i++){
	    if(binG[i].val!=0)
		    printf("%d - bin val:%d, bin counter: %d\n", i, binG[i].val, binG[i].counter);
    }
    exit(0);
}



void terminate(int signal)
{
    print_statistics();
}



void ping(int signal)
{
    int             ret;
    float           rtt;
    
    sent++;

    ret = ioctl(f, IOC_RTFW_PING, &cmd);
    if (ret < 0) {
        if (errno == ETIME){
            goto done;
	}
        perror("ioctl");
        exit(1);
    }

    received++;
    rtt = (float)cmd.args.ping.rtt / (float)1000;
    if (rtt > wc_rtt)
        wc_rtt = rtt;
    //~ printf("%d bytes roundtriping %s and %d: time=%.1f us\n",
           //~ cmd.args.ping.msg_size, cmd.head.if_name, cmd.args.ping.destid, rtt);
    int rtt_round = ((int)rtt/5) *5;
    for(i=0;i<MAX_BIN;i++){
	    if(binG[i].val==0)
		    binG[i].val=rtt_round;
	    if(binG[i].val==rtt_round){
		    binG[i].counter+=1;
		    break;
	    }
    }
    if(sent == max_count)
	    goto done;
    
    return;
done:
    print_statistics();
}



int main(int argc, char *argv[])
{
    const char          dev[] = "/dev/rt-firewire";
    struct timeval      time;
    struct itimerval    timer = {{0, 0}, {0, 1}};
    int                 i;

    //we need local host name and remote destination id	
    if (argc < 3)
        help();
    
    struct sched_param mysched;
    mysched.sched_priority = sched_get_priority_max(SCHED_FIFO) - 1;
	if( sched_setscheduler( 0, SCHED_FIFO, &mysched ) == -1 ) {
		puts("ERROR IN SETTING THE SCHEDULER");
		perror("errno");
		exit(1);
	}

    gettimeofday(&time, NULL);
    cmd.args.ping.msg_size = 56;
    cmd.args.ping.timeout  = 500;

    for (i = 1; i < argc-1; i++) {
	if(strcmp(argv[i], "-h") == 0){
	    strncpy(cmd.head.if_name, argv[++i], IFNAMSIZ);
	}
        else if (strcmp(argv[i], "-d") == 0)
            cmd.args.ping.destid = getintopt(argc, ++i, argv, 0);
        else if (strcmp(argv[i], "-i") == 0)
            delay = getintopt(argc, ++i, argv, 1);
	else if (strcmp(argv[i], "-p") == 0)
            cmd.args.ping.pri = getintopt(argc, ++i, argv, 0);
        else if (strcmp(argv[i], "-s") == 0) {
            cmd.args.ping.msg_size = getintopt(argc, ++i, argv, 0);
            if (cmd.args.ping.msg_size > 4096)
                cmd.args.ping.msg_size = 4096;
        } 
	else if(strcmp(argv[i],"-c") ==0){
		max_count = getintopt(argc, ++i, argv, 0);
	}else
            help();
    }

    f = open(dev, O_RDWR);
    if (f < 0) {
        perror(dev);
        exit(1);
    }
    
    for(i=0;i<MAX_BIN;i++){
	    binG[i].val=0;
	    binG[i].counter=0;
    }


    printf("Real-time PING over FireWire: %s to node_%d %d bytes of data with priority %d.\n",
           cmd.head.if_name, cmd.args.ping.destid, cmd.args.ping.msg_size,
						cmd.args.ping.pri);

    signal(SIGINT, terminate);
    //~ signal(SIGALRM, ping);
    //~ timer.it_interval.tv_sec  = delay / 1000;
    //~ timer.it_interval.tv_usec = (delay % 1000) * 1000;
    //~ setitimer(ITIMER_REAL, &timer, NULL);
    for(i=0;i<max_count;i++){
	    ping(0);
    }

    while (1) pause();
}
