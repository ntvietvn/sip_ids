#ifdef __cplusplus
extern "C" {
#endif
#include "ids_elem.h"

static int sockaddr_in_copy(struct sockaddr_in **dst, struct sockaddr_in *src)
{
	if (!src) return -1;
	*dst = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memcpy(*dst, src, sizeof(struct sockaddr_in));
	return 0;
}

void ids_elem_init(pIdsElem idsElem_p,
					struct sockaddr_in *src_sa,
					struct sockaddr_in *dst_sa, 
					unsigned short src_port, 
					unsigned short dst_port, 
					struct timeval *tv,
					char *payload)
{
	if (!idsElem_p) return;
	if (sockaddr_in_copy(&idsElem_p->src_sa, src_sa))
		return;	
	if (sockaddr_in_copy(&idsElem_p->dst_sa, dst_sa))
		return;	

	idsElem_p->src_port = src_port;	
	idsElem_p->dst_port = dst_port;
	idsElem_p->tv = *tv;
	int size = strlen(payload);
	idsElem_p->payload = (char*)malloc(size+1);
	memcpy(idsElem_p->payload,payload, size);
	idsElem_p->payload[size]='\0'; 	
}

void ids_elem_free(IdsElem *pElem)
{
	if (!pElem) return;
	if (pElem->src_sa) 	free(pElem->src_sa);
	if (pElem->dst_sa) 	free(pElem->dst_sa);
	if (pElem->payload) free(pElem->payload);
}
#ifdef __cplusplus
}
#endif
