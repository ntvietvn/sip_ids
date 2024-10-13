#ifndef __IPT_CMD__
#define	__IPT_CMD__

#include <stdio.h>
#include <errno.h>
#include <string.h>
// iptables c api
#ifdef __cplusplus
extern "C" {
#endif
#include <libiptc/libiptc.h> /* including ip.h & udp.h */

int insert_rule (const char *table,
				const char *chain,
				unsigned int src,
				int inverted_src,
				unsigned int dest,
				int inverted_dst,
				const char *target);

int rule_exists(const char *chain, struct xtc_handle *handle, struct ipt_entry *entry);
void init_sip_ids_chain(const char *table,const char *chain);
void block_ip_src(unsigned int src);
void block_ip(const char *ip);
#ifdef __cplusplus
}
#endif


#endif
