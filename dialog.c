#ifdef __cplusplus
extern "C" {
#endif
#include "dialog.h"
#include "utils.h"
#include <semaphore.h>
#include <pthread.h>
#include <sys/time.h>
#include "tslog.h"

t_hTable *dialog_list = NULL;
sem_t	dialog_list_sem;
extern unsigned char stateful_enabled;
static char * getDialogId(void *data) {
	pDialog pdlg = (pDialog)data;
	return pdlg->id;
}

void init_dialog_list() {
	if (!dialog_list)
		dialog_list = hash_str_init(MAX_DIALOG_HASH, getDialogId);
	sem_init(&dialog_list_sem, 0, 1);	
}

static void print_dialog(void *data) {
	if (!data) return;
	pDialog pdlg = (pDialog)data;
	if (!pdlg) return;
	tslog_info("Dialog @%p:",pdlg);
	tslog_info("	-> id		= %s",pdlg->id);
	tslog_info("	-> id len	= %d",strlen(pdlg->id));
	tslog_info("	-> src_ip	= %s",pdlg->src_ip);
	tslog_info("	-> src_port	= %d",pdlg->src_port);
	tslog_info("	-> ts		= %lu (micro s)",pdlg->ts.tv_sec*1000000 + pdlg->ts.tv_usec);
}

static void del_dialog_mono(char *id) {
	if (!id) return;
	pDialog pdlg = (pDialog)hash_str_get(dialog_list, id);
	if (pdlg) {
		tslog_info("[Thread %p]Dialog found - to be deleted:", (void*)pthread_self());
		print_dialog(pdlg);
		hash_str_del(dialog_list, id, pdlg);
		free(pdlg);
	}
}
void add_dialog(pDialog pdlg) {
	if (!pdlg) return;
	semaphore_wait(&dialog_list_sem);
	if (hash_str_get(dialog_list, pdlg->id)) {
		semaphore_post(&dialog_list_sem);
		return;
	}

	hash_str_add(dialog_list, pdlg->id, pdlg);
	print_all_dialogs();
	semaphore_post(&dialog_list_sem);
}

pDialog create_dialog(const char *id_in, const char *src_ip_in, short src_port_in, struct timeval *ts) {
	pDialog pdlg = (pDialog)malloc(sizeof(Dialog));
	memcpy(&pdlg->ts,ts,sizeof(struct timeval));
	memset(pdlg->id, 0, MAX_ID);
	strncpy(pdlg->id, id_in, MAX_ID-1);
	strncpy(pdlg->src_ip, src_ip_in, MAX_IP_ADDR-1);
	pdlg->src_port = src_port_in;
	return pdlg;
}

void del_dialog(char *id) {
	semaphore_wait(&dialog_list_sem);
	del_dialog_mono(id);
	print_all_dialogs();
	semaphore_post(&dialog_list_sem);
}

pDialog get_dialog(char *id) {
	semaphore_wait(&dialog_list_sem);
	void *data = hash_str_get(dialog_list, id);
	semaphore_post(&dialog_list_sem);
	return (pDialog)data;
}


void print_all_dialogs() {
	tslog_info("**************");
	tslog_info("All dialogs: ");
	tslog_info("**************");
	print_hash_table(dialog_list, print_dialog);
}

static void dialog_clean(void *data) {
	if (!data) return;
	pDialog pdlg = (pDialog)data;
	if (!pdlg) return;
	struct timeval now;
	gettimeofday(&now, NULL);
	int interval_s = (int)(((now.tv_sec - pdlg->ts.tv_sec) * 1000000 + (now.tv_usec - pdlg->ts.tv_usec))/1000000);
	if (interval_s >= SESS_TIMEOUT) {
		tslog_info("[Thread %p]Dialog timeout - to be deleted: ", (void*)pthread_self());
		print_dialog(pdlg);
		del_dialog_mono(pdlg->id);
	}
}

void dialog_clean_all(){
	if (stateful_enabled == 0) return;
	semaphore_wait(&dialog_list_sem);
	if (dialog_list)
		print_hash_table(dialog_list, dialog_clean);
	semaphore_post(&dialog_list_sem);
}

int same_src(pDialog pdlg, char *src_ip, unsigned short src_port) {
	if (!pdlg || !pdlg->src_ip || !src_ip) return 0;
	if (!strcmp(src_ip, (char*)pdlg->src_ip) && (pdlg->src_port == src_port))
		return 1; 
	return 0;
}
#ifdef __cplusplus
}
#endif
