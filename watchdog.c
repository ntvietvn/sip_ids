#ifdef __cplusplus
#include <iostream>
extern "C" {
#endif
#include "watchdog.h"
#include "dialog.h"
#include "elem_stat.h"
#include <pthread.h>
#include <time.h>
#include "tslog.h"
#include <unistd.h>

#define WD_INTERVAL	60

void *wd_start(void *data) {
	tslog_info("[%s] Starting new thread <%p> watching dialog list",__FUNCTION__,(void*)pthread_self());
	while (1) {
		tslog_info("Looking for timeout dialog & peer info...");
		sleep(WD_INTERVAL);
		dialog_clean_all();
		elem_clean_all();
	}
}
#ifdef __cplusplus
}
#endif

