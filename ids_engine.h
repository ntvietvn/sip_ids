#ifndef __IDS_ENGINE__
#define __IDS_ENGINE__
#ifdef __cplusplus
extern "C" {
#endif
#include "ipt_cmd.h"
#include "elem_stat.h"
#include "sip_fct.h"
#include "ids_elem.h"

#define MAX_DATA	1472
#define MAX_STR		512

void ids_engine_run(struct iphdr *iphdr, struct timeval *pts);
void ids_engine_udp(struct udphdr *udphdr, struct timeval *pts, 
					struct sockaddr_in *src_sa, struct sockaddr_in *dst_sa);

void ids_engine_sip(void *sender, pIdsElem idsElem_p);

/* entry function for processing thread */
void *process_ids_elem(void*);
#ifdef __cplusplus
}
#endif
#endif
