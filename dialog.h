#ifndef __DIALOG__
#define __DIALOG__
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include "c_hash_str.h"
#include <stdlib.h>
#include <string.h>
#include "constants.h"

#define	MAX_DIALOG_HASH	250
#define	MAX_ID			256
#define	MAX_PORT		65535


typedef struct _dialog {
	char id[MAX_ID];
	struct timeval ts;
	char src_ip[MAX_IP_ADDR];
	unsigned short	src_port;
} Dialog, *pDialog;

void init_dialog_list();
void add_dialog(pDialog pdlg);
pDialog create_dialog(const char *id_in, const char *src_ip_in, short src_port_in, struct timeval *ts);
void del_dialog(char *id);
pDialog get_dialog(char *id);
void print_all_dialogs();
int same_src(pDialog pdlg, char *src_ip, unsigned short src_port);
void dialog_clean_all();
#ifdef __cplusplus
}
#endif
#endif
