#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "config.h"
#include "remote.h"
#include "ipt_cmd.h"
#include "socket.h"
#include "tslog.h"
#include "pthread.h"
#include <zmq.h>
#include "elem_stat.h"

extern struct notif_t noti_cfg;
char hostname[MAX_STR];

static void subscribe(int fd, int mask)
{
	char msg[MAX_STR] = { 0 };
	strcpy(msg, "src=");
	gethostname(msg + strlen(msg), 32);
	sprintf(msg + strlen(msg), ";action=subscribe;mask=%d\n", mask);
	socket_send(fd, msg);
}

static void process_msg(const char *buffer)
{
	if (!buffer) return;
	char act[MAX_STR] = { 0 };
	char src[MAX_STR] = { 0 };
	char ip[MAX_STR] = { 0 };
	sscanf(buffer, "src=%[^;];action=%[^;]", src,act);
	if (!strcmp(src, hostname)) {
		tslog_info( "[%s] Message sent from me - ignored",__FUNCTION__);
		return;
	}
	
				
	if (strcmp(act,ACT_BLOCK) == 0) {
		sscanf(buffer, "src=%[^;];action=%[^;];ip=%[^;]", src,act,ip);
		if (get_peer(ip)) {
			tslog_info( "[%s] ip = %s in this server's whitelist\n",__FUNCTION__, ip);
			return;
		}
		block_ip(ip);
		tslog_warn("--------------> IP <%s> is blocked on host %s (broadcasted from %s))",ip, src, src);
	} 
}

static int connect_subscribe(int mask) 
{
	int fd = socket_new();
	int res = fd;
	tslog_info( "[%s] connecting to ipds server %s:%d",__FUNCTION__, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port);
	if (!socket_connect(fd, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port)) {
		tslog_info( "[%s] connected to ipds server %s:%d",__FUNCTION__, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port);
		tslog_info( "[%s] subscribe to BLOCK event on ipds server %s:%d",__FUNCTION__, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port);
		subscribe(fd,mask); 
	} else { 
		tslog_info( "[%s] fd = %d - Connect to ipds server %s:%d failed, errno = %d (%s)",__FUNCTION__, fd, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port,errno,strerror(errno));
		res = -1;
	}
	return res;
}


void *process_remote_msg(void *data)
{
	/* get hostname */
	memset(hostname, 0, MAX_STR);
	gethostname(hostname, MAX_STR);

	tslog_info( "[%s] starting new thread <%p> to process remote messages",__FUNCTION__, (void*)pthread_self()); 
	char pub_addr[MAX_STR];
	memset(pub_addr,0,MAX_STR);
	snprintf(pub_addr, MAX_STR - 1, "tcp://%s:%d", noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_sub_port);
	void *context = data;
	void *subscriber = zmq_socket (context, ZMQ_SUB);
	zmq_connect(subscriber,pub_addr);
	zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE,"",0);

	char buffer[MAX_MSG_BUF];
	memset(buffer, 0, MAX_MSG_BUF);
	int res = 1;

	while(1) {
			memset(buffer, 0, MAX_MSG_BUF);
			res = zmq_recv (subscriber, buffer, MAX_MSG_BUF, 0);
			if (res == -1) {
				if (errno == EINTR) {
					continue;
				}
			}
			buffer[res] = '\0';
			tslog_info( "[%s] received %d bytes from ipds server:\n %s",__FUNCTION__, res, buffer);
			process_msg(buffer);
	}
	zmq_close(subscriber);
}

#ifdef __cplusplus
}
#endif

