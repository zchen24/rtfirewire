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
int             delay    = 1000;
unsigned int    sent     = 0;
unsigned int    received = 0;
float           wc_rtt   = 0;


void help(void)
{
    fprintf(stderr, "Usage:\n"
        "\trtping [-h host] [-d destid] [-i interval] [-s packetsize]\n"
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
    printf("%d bytes roundtriping %s and %d: time=%.1f us\n",
           cmd.args.ping.msg_size, cmd.head.if_name, cmd.args.ping.destid, rtt);
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
        else if (strcmp(argv[i], "-s") == 0) {
            cmd.args.ping.msg_size = getintopt(argc, ++i, argv, 0);
            if (cmd.args.ping.msg_size > 4096)
                cmd.args.ping.msg_size = 4096;
        } else
            help();
    }

    f = open(dev, O_RDWR);
    if (f < 0) {
        perror(dev);
        exit(1);
    }

    printf("Real-time PING over FireWire: %s to node_%d %d bytes of data.\n",
           cmd.head.if_name, cmd.args.ping.destid, cmd.args.ping.msg_size);

    signal(SIGINT, terminate);
    signal(SIGALRM, ping);
    timer.it_interval.tv_sec  = delay / 1000;
    timer.it_interval.tv_usec = (delay % 1000) * 1000;
    setitimer(ITIMER_REAL, &timer, NULL);

    while (1) pause();
}


	