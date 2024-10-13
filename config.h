#ifndef __CONFIG_H__
#define	__CONFIG_H__

#include <stdio.h>
#include <string.h>
#include <libconfig.h>

#define MAX_BUF	64
#define MAX_STR	512

struct capture_t {
	char inf[MAX_BUF];
	int port;
	int sf;
	char wl[MAX_BUF];
	char bl[MAX_BUF];
};

struct notif_t {
	char email_list[MAX_STR];
	char ipds_srv_ip[MAX_STR];
	int ipds_srv_port;
	int ipds_srv_sub_port;
};

struct system_t {
	int nb_threads;
	int qsize;
	int maxbyte;
	int	stack_size;
	int	facility;
	char logfile[MAX_STR];
};

struct criteria_t {
	int mean;
	int	nb_fail;
	int nb_hijack;
};

void load_config(const char *file);
void show_config();

#endif


