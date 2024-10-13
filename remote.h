#ifndef __REMOTE_H__
#define __REMOTE_H__

#define	IPDS_NONE		0
#define	IPDS_BLOCK	1000

#define ACT_BLOCK		"block"

#define MAX_MSG_BUF			512

void *process_remote_msg(void *data);

#endif
