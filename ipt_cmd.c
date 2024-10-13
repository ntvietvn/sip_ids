#ifdef __cplusplus
extern "C" {
#endif
#include <stdlib.h> 
#include <syslog.h> 
#include <arpa/inet.h>
#include "ipt_cmd.h"
#ifdef __cplusplus
}
#endif

#define MAX_CMD	512

#ifdef __cplusplus
extern "C" {
#endif
static int entry_cmp(const struct ipt_entry *entry1, const struct ipt_entry *entry2) {
	if (!entry1 || !entry2) return -1;
	return memcmp(&entry1->ip.src, &entry2->ip.src, sizeof(struct in_addr));
		//&& memcmp(&entry1->ip.smsk, &entry2->ip.smsk, sizeof(struct in_addr));
}

int rule_exists(const char *chain, struct xtc_handle *handle, struct ipt_entry *entry) {
	if (!entry) return 0;
	const struct ipt_entry *rule = iptc_first_rule(chain, handle);
	while (rule) {
		if (!entry_cmp(rule, entry))
			return 1;
		rule = iptc_next_rule(rule, handle); 		
	}
	return 0;
}

void init_sip_ids_chain(const char *table, const char *chain) {
	if (!table || !chain) return;
	struct xtc_handle *h = (struct xtc_handle *)iptc_init (table);
	char cmd[MAX_CMD] = { '\0' };
	if (!h) {
		syslog (LOG_ERR, "Could not init IPTC library: %s\n", iptc_strerror (errno));
		return;
	}
	xt_chainlabel label;
	if (strlen(chain) < sizeof(xt_chainlabel))
		memcpy(label, chain, strlen(chain));
	
	if (iptc_is_chain(chain, h)) {
		syslog(LOG_WARNING, "Chain %s already exists\n", chain);
		if (h) iptc_free(h);
		return;
	}
	if (h)
		iptc_free(h);
/*		
	if (iptc_create_chain(label, h)) {
		syslog(LOG_ERR, "Could not create chain %s: %s\n", chain, iptc_strerror (errno));
		return -1;
	}
*/
	snprintf(cmd,MAX_CMD - 1, "iptables -N %s", chain);
	
	/* this can load the rsyslogd */
	/* sprintf(cmd + strlen(cmd),";iptables -A %s -j LOG --log-prefix=\"SIP_IDS -->\"",chain);*/
	sprintf(cmd + strlen(cmd),";iptables -A %s -j DROP",chain);
	system(cmd);
}

void block_ip(const char *ip) {
	struct in_addr ipn;
	inet_aton(ip, &ipn);
	block_ip_src(ipn.s_addr);
}

void block_ip_src(unsigned int src) {
	insert_rule ("filter", "INPUT", src, 0, 0, 0, "SIP_IDS");
}

int insert_rule (const char *table,
				const char *chain,
				unsigned int src,
				int inverted_src,
				unsigned int dest,
				int inverted_dst,
				const char *target)
{
	struct
	{
		struct ipt_entry entry;
		struct xt_standard_target target;
	} entry;
	
	struct xtc_handle *h;
	int ret = 1;
	 
	h = (struct xtc_handle *)iptc_init (table);
	if (!h) {
		 syslog(LOG_ERR, "Could not init IPTC library: %s\n", iptc_strerror (errno));
		 goto out;
	}
	  
	memset (&entry, 0, sizeof (entry));
	   
	/* target */
	entry.target.target.u.user.target_size = XT_ALIGN (sizeof (struct xt_standard_target));
	strncpy (entry.target.target.u.user.name, target, sizeof (entry.target.target.u.user.name));
	    
	/* entry */
	entry.entry.target_offset = sizeof (struct ipt_entry);
	entry.entry.next_offset = entry.entry.target_offset + entry.target.target.u.user.target_size;
	if (src) {
		entry.entry.ip.src.s_addr = src;
		entry.entry.ip.smsk.s_addr = 0xFFFFFFFF;
		if (inverted_src)
			entry.entry.ip.invflags |= IPT_INV_SRCIP;
	}
		 
	if (dest) {
		entry.entry.ip.dst.s_addr = dest;
		entry.entry.ip.dmsk.s_addr = 0xFFFFFFFF;
		if (inverted_dst)
			entry.entry.ip.invflags |= IPT_INV_DSTIP;
	}
	if (!rule_exists(chain, h, &(entry.entry))) {
		if (iptc_first_rule(chain, h)) {
			if (!iptc_insert_entry(chain, (struct ipt_entry *) &(entry.entry), 1, h)) {
				syslog(LOG_ERR, "Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
				goto out;
			}
		} else if (!iptc_append_entry(chain, (struct ipt_entry *) &(entry.entry), h)) {
			syslog(LOG_ERR, "Could not insert a rule in iptables (table %s): %s\n", table, iptc_strerror (errno));
			goto out;
		}
		   
		if (!iptc_commit (h)) {
			syslog(LOG_ERR, "Could not commit changes in iptables (table %s): %s\n", table, iptc_strerror (errno));
			goto out;
		}
	} 	
		    
	ret = 0;
	out:
		if (h)
			iptc_free (h);
	return ret;
}
#ifdef __cplusplus
}
#endif
