#ifdef __cplusplus
extern "C" {
#endif
#include "elem_stat.h"
#include <semaphore.h>
#include <errno.h>
#include "utils.h"
#include <time.h>
#include "tslog.h"
#include <sys/time.h>
#include <pthread.h>


t_hTable *regPeers = NULL;
sem_t	elem_stat_sem;
t_hTable *knownPeers = NULL;
blist	blacklist;

static char * getRegElemName(void *data) {
	pRegElem pElem = (pRegElem)data;
	return pElem->peer;
}

void init_reg_peers() {
	if (!regPeers)
		regPeers = hash_str_init(MAX_HASH, getRegElemName);
	sem_init(&elem_stat_sem, 0, 1);	
}

void add_reg_elem(pRegElem elem) {
	if (!elem) return;
	semaphore_wait(&elem_stat_sem);
	if (hash_str_get(regPeers,elem->peer)) {
		sem_post(&elem_stat_sem);
		return;
	}
	hash_str_add(regPeers, elem->peer, elem);
	print_all_elem();
	sem_post(&elem_stat_sem);
}

pRegElem init_reg_elem(const char *name) {
	pRegElem elem = (pRegElem)malloc(sizeof(regElem));
	elem->nb_unauth = 0;
	elem->nb_done = 0;
	elem->nb_ua_ko = 0;
	elem->nb_hijack = 0;
	elem->count = 0;
	elem->old_count = 0;
	elem->emailSent = 0;
	memset(&elem->first_ts,0,sizeof(struct timeval));
	strncpy(elem->peer, name, MAX_PEER_NAME-1);
	return elem;
}

void reset_reg_elem(pRegElem elem,struct timeval *pts) {
	if (!elem || !pts) return;
	elem->nb_ua_ko = 0;
	elem->nb_unauth = 0;
	elem->nb_hijack = 0;
	elem->count = 0;
	elem->old_count = 0;
	elem->nb_done = 0;
	elem->first_ts = *pts;
	elem->emailSent = 0;
}

static void del_reg_elem_mono(char *elemName) {
	if (!elemName) return;
	pRegElem elem = (pRegElem)hash_str_get(regPeers, elemName);
	if (elem) {
		hash_str_del(regPeers, elemName, elem);
		free(elem);
	}
}


void del_reg_elem(char *elemName) {
	if (!elemName) return;
	semaphore_wait(&elem_stat_sem);
	del_reg_elem_mono(elemName);
	sem_post(&elem_stat_sem);
}

pRegElem get_reg_elem(char *pName) {
	semaphore_wait(&elem_stat_sem);
	void *data = hash_str_get(regPeers, pName);
	sem_post(&elem_stat_sem);
	return (pRegElem)data;
}

static void print_elem(void *data) {
	if (!data) return;
	pRegElem elem = (pRegElem)data;
	if (!elem) return;
	tslog_info("RegElem @%p (%s):",elem,elem->peer);
	tslog_info("	-> nb_unauth	= %d",elem->nb_unauth);
	tslog_info("	-> nb_done	= %d",elem->nb_done);
	tslog_info("	-> nb_ua_ko	= %d",elem->nb_ua_ko);
	tslog_info("	-> nb_hijack= %d",elem->nb_hijack);
	tslog_info("	-> count	= %d",elem->count);
	tslog_info("	-> oldcount	= %d",elem->old_count);
	tslog_info("	-> ts		= %lu (micro s)",elem->first_ts.tv_sec*1000000 + elem->first_ts.tv_usec);
}

void print_all_elem() {
	tslog_info("**************");
	tslog_info("All elems: ");
	tslog_info("**************");
	print_hash_table(regPeers, print_elem);
}

int fraudDetected(pRegElem pElem) {
	if (!pElem) return 0;
	return (pElem->emailSent || (pElem->nb_ua_ko > 0) || (pElem->count > 50));
}
void reset_old_elem(pRegElem pElem, struct timeval *pts) {
	if (!pElem || !pts) return;
	struct timeval ts = *pts;
	/* get interval */
	int interval_s = (int)(((ts.tv_sec - pElem->first_ts.tv_sec) * 1000000 + (ts.tv_usec - pElem->first_ts.tv_usec))/1000000);
	/* reset the elem after a long time */
	if (interval_s >= 600) {
		reset_reg_elem(pElem,&ts);
	}   
}

static void elem_clean(void *data) {
	if (!data) return;
	pRegElem pElem = (pRegElem)data;
	if (!pElem) return;
	struct timeval now;
	gettimeofday(&now, NULL);
	int interval_s = (int)(((now.tv_sec - pElem->first_ts.tv_sec) * 1000000 + (now.tv_usec - pElem->first_ts.tv_usec))/1000000);
	if (interval_s >= SESS_TIMEOUT) {
		tslog_info("[Thread %p]Elem timeout - to be deleted: ", (void*)pthread_self());
		print_elem(pElem);
		del_reg_elem_mono(pElem->peer);
	}
}

void elem_clean_all(){
	semaphore_wait(&elem_stat_sem);
	if (regPeers)
		print_hash_table(regPeers, elem_clean);
	sem_post(&elem_stat_sem);
}
/****** Peer ******/

static char * getPeerName(void *data) {
	pPeer peer = (pPeer)data;
	return peer->name;
}

void init_known_peers(const char *name) {
	if (!knownPeers)
		knownPeers = hash_str_init(MAX_HASH_PEER, getPeerName);
	load_peers(name);	
}

void add_peer(pPeer p) {
	if (!p) return;
	if (get_peer(p->name)) return;
	hash_str_add(knownPeers, p->name, p);
}

pPeer init_peer(const char *name) {
	pPeer p = (pPeer)malloc(sizeof(peer));
	strncpy(p->name, name, MAX_PEER_NAME-1);
	return p;
}

void del_peer(char *name) {
	if (!name) return;
	pPeer peer = get_peer(name);
	if (peer) {
		hash_str_del(knownPeers, name, peer);
		free(peer);
	}
}

pPeer get_peer(char *pName) {
	void *data = hash_str_get(knownPeers, pName);
	return (pPeer)data;
}

static void print_peer(void *data) {
	if (!data) return;
	pPeer p = (pPeer)data;
	tslog_info("Peer @%p:",p);
	tslog_info("	-> ip	= %s",p->name);
}

void print_all_peers() {
	tslog_info("********************");
	tslog_info("All kwown peers: ");
	tslog_info("********************");
	print_hash_table(knownPeers, print_peer);
}

void load_peers(const char *fileName)
{
	char pName[MAX_PEER_NAME];
	char line[MAX_PEER_NAME];
	pPeer p = NULL;
	FILE *fr = fopen (fileName, "rt");  /* open the file for reading */

	while(fgets(line, MAX_PEER_NAME, fr) != NULL) {
		sscanf (line, "%s", pName);
		/* convert the string to a long int */
		p = init_peer(pName);
		add_peer(p);
	}
	fclose(fr);  /* close the file prior to exiting the routine */
	print_all_peers();
}

void init_blacklist() {
	blacklist.len = 0;
	int i = 0;
	for (i = 0; i < MAX_IP_ADDR; i++)
		blacklist.blipArr[i] = NULL;
}

void load_blacklist_ip(const char *fileName)
{
	char pName[MAX_PEER_NAME];
	char line[MAX_PEER_NAME];
	FILE *fr = fopen (fileName, "rt");  /* open the file for reading */
	int i = 0, j = 0;

	init_blacklist();

	while(fgets(line, MAX_PEER_NAME, fr) != NULL && (i < MAX_IP_ADDR)) {
		sscanf (line, "%s", pName);
		if (!blacklist.blipArr[i]) {
			blacklist.blipArr[i] = (char*)malloc(strlen(pName) + 1);
			strcpy(blacklist.blipArr[i], pName);
			i++;
			blacklist.len++;
		}
	}
	fclose(fr);  /* close the file prior to exiting the routine */
	tslog_info("blacklist ip size = %d", blacklist.len);
	for (j = 0; j < blacklist.len; j++)
		tslog_info("blacklist ip[%d] = %s", j, blacklist.blipArr[j]);
}
#ifdef __cplusplus
}
#endif
