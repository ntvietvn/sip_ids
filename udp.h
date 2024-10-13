#ifndef __RAW_UDP__
#define __RAW_UDP__
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>

// The packet length

#define PCKT_LEN 8192

struct ipheader {
	unsigned char      	iph_ihl:5, iph_ver:4;
	unsigned char      	iph_tos;
	unsigned short 	   	iph_len;
	unsigned short     	iph_ident;
	unsigned char      	iph_flag;
	unsigned short	   	iph_offset;
	unsigned char      	iph_ttl;
	unsigned char      	iph_protocol;
	unsigned short		iph_chksum;
	unsigned int       	iph_sourceip;
	unsigned int       	iph_destip;
};

struct udpheader {
	unsigned short	udph_srcport;
	unsigned short 	udph_destport;
	unsigned short 	udph_len;
	unsigned short 	udph_chksum;
};

#endif
