#ifndef __IDS_ELEM__
#define	__IDS_ELEM__

#include <time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>

typedef struct _ids_elem {
	struct sockaddr_in *src_sa;
	struct sockaddr_in *dst_sa;
	unsigned short src_port;
	unsigned short dst_port;
	char *payload;
	struct timeval tv;
} IdsElem, *pIdsElem; 

void ids_elem_init(pIdsElem idsElem_p,
					struct sockaddr_in *src_sa,
					struct sockaddr_in *dst_sa, 
					unsigned short src_port, 
					unsigned short dst_port, 
					struct timeval *tv,
					char *payload);

void ids_elem_free(IdsElem *pElem);

#endif
