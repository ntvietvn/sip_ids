#ifndef __ELEM_STAT__
#define __ELEM_STAT__

#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include "c_hash_str.h"
#include <stdlib.h>
#include <string.h>
#include "constants.h"

#define	MAX_HASH		100
#define	MAX_HASH_PEER	20
#define	MAX_PEER_NAME	128

typedef struct _bl {
	int len;
	char *blipArr[MAX_IP_ADDR];
} blist;

typedef struct _elem {
	char peer[MAX_PEER_NAME];
	struct timeval first_ts;
	int	count;
	int old_count;
	int nb_unauth;
	int nb_hijack;
	int nb_ua_ko;
	int nb_done;
	int emailSent;
} regElem, *pRegElem;

void init_reg_peers();
void reset_reg_elem(pRegElem elem,struct timeval *pts);
void add_reg_elem(pRegElem elem);
pRegElem init_reg_elem(const char *name);
void del_reg_elem(char *elemName);
pRegElem get_reg_elem(char *pName);
void print_all_elem();
int fraudDetected(pRegElem pElem);
void reset_old_elem(pRegElem pElem, struct timeval *ts);
void elem_clean_all();

/*** Peer ***/

typedef struct _peer {
	char name[MAX_PEER_NAME];
} peer, *pPeer;

void init_known_peers(const char *name);
void add_peer(pPeer elem);
pPeer init_peer(const char *name);
void del_peer(char *peerName);
pPeer get_peer(char *pName);
void print_all_peers();
void load_peers(const char *fileName);
void load_blacklist_ip(const char *fileName);

#endif
#ifdef __cplusplus
}
#endif
