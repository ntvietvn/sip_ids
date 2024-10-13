#ifndef __TS_QUEUE__
#define __TS_QUEUE__
#ifdef __cplusplus
extern "C" {
#endif
#include <semaphore.h>

#define	TSQ_MAX_ELEM	100

typedef struct _queue {
	sem_t readable;
	sem_t writable;
	sem_t r_access;
	sem_t w_access;
	void **queue;
	int wpos;
	int rpos;
} TSQueue, *pTSQueue; //Thread_safe queue

void tsqueue_init(int nb_elems);
void tsqueue_add(void *data, int size);
void *tsqueue_poll();
//void tsqueue_remove();	

#ifdef __cplusplus
}
#endif
#endif
