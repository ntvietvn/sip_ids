/*
 * Viet Nguyen @ viatelecom.com
 */
#ifdef __cplusplus
#include <cstdio>
#include <iostream>
extern "C" {
#endif
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* inclued net/ethernet.h */
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "ids_engine.h"
#include "watchdog.h"
#include "tsqueue.h"
#include "dialog.h"
#include "config.h"
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include "tslog.h"
#include "remote.h"
#include <zmq.h>

#define MAXBYTES2CAPTURE 		2048
#define	CAPTURE_PORT_INIT		0
#define	CAPTURE_PORT_DEFAULT	5060
#define NB_THREADS_MAX			30
#define NB_THREADS_DEFAULT		5

struct sockaddr_in my_ip;
unsigned int capture_port;
unsigned char stateful_enabled = 0;
static unsigned int nb_threads = NB_THREADS_DEFAULT; 

extern struct capture_t capture_cfg;
extern struct system_t system_cfg;

/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in */
/* hexadecimal. */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){
   	struct ether_header 	*eptr = NULL; 
	struct iphdr 			*iphdr = NULL;
	struct timeval ts = pkthdr->ts;
	
	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;

	/* Do a couple of checks to see what packet type we have..*/
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
		iphdr = (struct iphdr*)((unsigned char*)eptr + sizeof(struct ether_header));
		/* IDS takes part in IP packets */
		ids_engine_run(iphdr, &ts);
	}
	return;
} 

static int get_my_ip(const char *dev) {
#if 0	
	struct ifaddrs *interfaceArray = NULL, *tempIfAddr = NULL;
	int rc = 0;
	void *tempAddrPtr = NULL;
	char str[INET_ADDRSTRLEN];
	struct sockaddr_in *sa;
		  
	rc = getifaddrs(&interfaceArray);  /* retrieve the current interfaces */
	if (rc == 0) {
		tempIfAddr = interfaceArray;
		while (tempIfAddr) {
			printf("interface = %s\n",tempIfAddr->ifa_name);
			sa = (struct sockaddr_in *)tempIfAddr->ifa_addr;
			inet_ntop(sa->sa_family, &(sa->sin_addr), str, INET_ADDRSTRLEN);
			printf("ip = %s\n",str);
			if (!strcmp(tempIfAddr->ifa_name, dev)) {
				memcpy(&my_ip,tempIfAddr->ifa_addr, sizeof(struct sockaddr));
				return 0;
			}
			tempIfAddr = tempIfAddr->ifa_next;
		}
	}
	return -1;
#endif
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in *sa;   
	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;
		 
	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	
	sa = (struct sockaddr_in*)&ifr.ifr_addr;
	memcpy(&my_ip, sa, sizeof(struct sockaddr_in));
	return 0;	
}

static void help() 
{
	printf("Usage: \n");
	printf("./sip_ids -i [interface] -p [port] -nt [nb_threads]\n");
	printf("	-i	:capturing interface\n");
	printf("	-p	:port (5060 default)\n");
	printf("	-nt	:nb processing thread (5 default)\n");
	printf("	-sf	:stateful mode\n");
}

int main(int argc, char **argv)
{
	char *dev = NULL; /* name of the device to use */ 
	char *net = NULL; /* dot notation of the network address */
	char *mask = NULL;/* dot notation of the network mask    */
	int ret;   /* return code */
	char *config_file_name = NULL;/* dot notation of the network mask    */
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp; /* ip          */
	bpf_u_int32 maskp;/* subnet mask */
	struct in_addr addr;
 	int i=0, j = 0, count=0;
  	pcap_t *descr = NULL;
    memset(errbuf,0,PCAP_ERRBUF_SIZE); 
	char	myip_str[INET_ADDRSTRLEN];
    pcap_if_t *alldevs, *d;
	int inum;

	/* ask pcap to find a valid device for use to sniff on */
	//dev = pcap_lookupdev(errbuf);

	/* default */
	capture_port = CAPTURE_PORT_INIT;

	if (argc > 0) {
		for (j = 1; j < argc; j++) {
			if (!strncmp(argv[j], "-i", 2) && (j + 1 < argc)) {
				dev = (char*)malloc(strlen(argv[j+1]));
				strcpy(dev,argv[j+1]);
			}
			if (!strncmp(argv[j], "-f", 2) && (j + 1 < argc)) {
				config_file_name = (char*)malloc(strlen(argv[j+1]));
				strcpy(config_file_name,argv[j+1]);
			}
			if (!strncmp(argv[j], "-p", 2) && (j + 1 < argc)) {
				capture_port = atoi(argv[j+1]);
			}
			
			if (!strncmp(argv[j], "-nt", 3) && (j + 1 < argc)) {
				nb_threads = atoi(argv[j+1]);
			}
			
			if (!strncmp(argv[j], "-sf", 3)) {
				stateful_enabled = 1;
			}
			
			if (!strncmp(argv[j], "-h",2)) {
				help();
				exit(0);
			}
		}
	}

	printf("\nfile : %s.\n",config_file_name);
	if (config_file_name[0]) {
		load_config(config_file_name);
	}

	//openlog ("sip_ids", LOG_PERROR | LOG_CONS | LOG_PID | LOG_NDELAY, system_cfg.facility);
	int logrs = tslog_init();
	if (logrs == -1) {
			fprintf(stderr,"error initializing log\n");
			exit(1);
	}
	logrs = tslog_open(system_cfg.logfile);
	if (logrs == -1) {
			fprintf(stderr,"error initializing logfile %s\n", system_cfg.logfile);
			exit(1);
	}
	
	tslog_info("sip_ids started");
	show_config();

	stateful_enabled = capture_cfg.sf; 

	if (!dev) {
		if (capture_cfg.inf[0]) {
			dev = (char*)malloc(strlen(capture_cfg.inf)+1);
			strcpy(dev, capture_cfg.inf);
		}
	}

	if (!dev) {
		/* The user didn't provide a packet source: Retrieve the device list */
		if (pcap_findalldevs(&alldevs, errbuf) == -1) {
			fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for(d=alldevs; d; d=d->next) {
			printf("%d. %s", ++i, d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if(i==0) {
			printf("\nNo interfaces found! \n");
			return -1;
		}

		printf("Enter the interface number (1-%d):",i);
		scanf("%d", &inum);

		if(inum < 1 || inum > i) {
			printf("\nInterface number out of range.\n");
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}
		
		/* Jump to the selected adapter */
		for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

		dev = d->name;
	}

	capture_port = capture_cfg.port;
	if (capture_port <= 0 || capture_port > 65535)
		capture_port = CAPTURE_PORT_DEFAULT;
	
	nb_threads = (system_cfg.nb_threads) ? system_cfg.nb_threads : NB_THREADS_DEFAULT;
	if (nb_threads < 0 || nb_threads > NB_THREADS_MAX)
		nb_threads = NB_THREADS_DEFAULT;
	
	/* error checking */
	if(dev == NULL) {
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}

	/* signal handlers */
	signal(SIGPIPE, SIG_IGN);

	/* print out device name */
	tslog_info("DEV: %s",dev);

	/* get my ip */
	if (get_my_ip(dev) < 0) {
		return -1;
	}
	inet_ntop(AF_INET, &(my_ip.sin_addr), myip_str, INET_ADDRSTRLEN);
	tslog_info( "capturing on <%s>: %s port %d",dev, myip_str, capture_port);

	/* ask pcap for the network address and mask of the device */
	ret = pcap_lookupnet(dev,&netp,&maskp,errbuf);

	if(ret == -1) {
		printf("%s\n",errbuf);
		exit(1);
	}

	/* get the network address in a human readable form */
	addr.s_addr = netp;
	net = inet_ntoa(addr);

	if(net == NULL) {
		perror("inet_ntoa");
		exit(1);
	}

	tslog_info( "NET: %s",net);

	/* do the same as above for the device's mask */
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);

	if(mask == NULL) {
		perror("inet_ntoa");
		exit(1);
	}

	/* init all iptables chain for sip_ids */
	init_sip_ids_chain("filter","SIP_IDS");
	
	/* init tab storing REGISTER stats */
	init_reg_peers();

	/* load all known peers */
	init_known_peers((capture_cfg.wl[0])?capture_cfg.wl:"known_peers.data");

	/* load blacklist ip */
	load_blacklist_ip((capture_cfg.bl[0])?capture_cfg.bl:"blip.data");

	/* init the thread-safe queue */
	int qsize = (system_cfg.qsize)?system_cfg.qsize:TSQ_MAX_ELEM;
	tsqueue_init(qsize);

	/* init the unique zmq context */
	void *context = zmq_ctx_new ();

	/* create threads for processing packets */
	unsigned int tid = 0;
	pthread_t *thread_array = (pthread_t *)malloc(nb_threads * sizeof(pthread_t));
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	/* set stack size to 512Ko only */
	int	ssize = (system_cfg.stack_size) ? system_cfg.stack_size : (1024*1024/2);
	pthread_attr_setstacksize(&attr, ssize);
	for (tid = 0; tid < nb_threads; tid++) { 
 		pthread_create((pthread_t*)&thread_array[tid], &attr, &process_ids_elem, context);
		pthread_detach(thread_array[tid]);
	}
	
#ifdef STATEFUL 	
	pthread_t watchdog;
	/* init the dialog list */
	if (stateful_enabled) {
		init_dialog_list();
		/* create the thread watching dialog/elem list */
		pthread_create(&watchdog, &attr, &wd_start, NULL);
		pthread_detach(watchdog);
	}
#endif

	/* create the thread 'remote' communicating with other sip_ids */
	pthread_t remote;
	pthread_create(&remote, &attr, &process_remote_msg, context);
	pthread_detach(remote);

	/* destroy thread attribute */
	pthread_attr_destroy(&attr);

	tslog_info( "MASK: %s",mask);
	tslog_info("Opening device %s", dev);

	tslog_info("size of timeval = %d", sizeof(struct timeval));

   /* Open device in promiscuous mode */
	int maxbytecapture = (system_cfg.maxbyte) ? system_cfg.maxbyte : MAXBYTES2CAPTURE;
    if ( (descr = pcap_open_live(dev, maxbytecapture, 1, 512, errbuf)) == NULL){
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	/* Loop forever & call processPacket() for every received packet*/
	if ( pcap_loop(descr, -1, processPacket, (u_char *)&count) == -1){
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}

	zmq_ctx_destroy(context);

	return 0;
}
#ifdef __cplusplus
}
#endif
