/**
 * Avantage of circular buffer:
 * 	- writer & reader can access the buffer simultaneously if there is necessarily data to read
 * 	- a dispatcher in a separating thread is needed to pull out data from the buffer then dispatch to processing thread (one or many)
 **/

#ifdef __cplusplus
extern "C" {
#endif
#include "tsqueue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "utils.h"
#include <pthread.h>
#include "tslog.h"

static pTSQueue tsQueue = NULL;

/* initialize the unique thread-safe queue */
void tsqueue_init(nb_elems) {
	if (tsQueue) return;
	tsQueue = (pTSQueue)malloc(sizeof(TSQueue));
	sem_init(&tsQueue->readable, 0, 0);
	sem_init(&tsQueue->r_access, 0, 1);
	sem_init(&tsQueue->w_access, 0, 1);
	sem_init(&tsQueue->writable, 0, nb_elems);
	tsQueue->queue = (void**)malloc(sizeof(void*)*nb_elems);
	memset(tsQueue->queue, 0, sizeof(void*)*nb_elems);
	tsQueue->wpos = 0;
	tsQueue->rpos = 0;
}

void tsqueue_add(void *data, int size) {
	int value = 0;
	
	//sem_getvalue(&tsQueue->writable, &value); 
	//printf("[%s][thread %p]semaphore writable = %d\n", __FUNCTION__,pthread_self(),value);
	
	semaphore_wait(&tsQueue->writable);		
	/* add data(elem) to the array */
	semaphore_wait(&tsQueue->w_access);
	if (!tsQueue->queue[tsQueue->wpos]) {
		tsQueue->queue[tsQueue->wpos] = malloc(size);
		memcpy(tsQueue->queue[tsQueue->wpos], data, size);
	}
	tsQueue->wpos++;
	if (tsQueue->wpos == TSQ_MAX_ELEM) {
		tsQueue->wpos = 0;
	}
	sem_post(&tsQueue->w_access);

	/* readers can read */
	sem_getvalue(&tsQueue->readable, &value); 
	//printf("[%s][thread %p]semaphore readable before = %d\n", __FUNCTION__, pthread_self(),value);
	if (value < TSQ_MAX_ELEM)
		sem_post(&tsQueue->readable); 
}

void *tsqueue_poll() 
{
	int value = 0;
	void *res = NULL;
	//int sem_res = 0;
	//sem_getvalue(&tsQueue->readable, &value); 
	//printf("[%s][thread %p] semaphore readable = %d\n", __FUNCTION__, pthread_self(), value);
	
	semaphore_wait(&tsQueue->readable);		
	//sem_getvalue(&tsQueue->readable, &value); 
	//printf("[%s][thread %p] semaphore readable after entering = %d\n", __FUNCTION__, pthread_self(), value);

	/* atomic access to read position */
	semaphore_wait(&tsQueue->r_access);		
	res = tsQueue->queue[tsQueue->rpos];
	tsQueue->queue[tsQueue->rpos] = NULL;
	if (!res) {		
		tslog_error("[%s][thread %p]read POINTER NULL", __FUNCTION__,(void*)pthread_self());
	}
	tsQueue->rpos++;
	if (tsQueue->rpos == TSQ_MAX_ELEM) {
		tsQueue->rpos = 0;
	}
	sem_post(&tsQueue->r_access);	
	
	/* writers can write */
	sem_getvalue(&tsQueue->writable, &value); 
	//printf("[%s][thread %p]semaphore writable before = %d\n", __FUNCTION__,pthread_self(), value);
	if (value < TSQ_MAX_ELEM)
		sem_post(&tsQueue->writable);
	return res;
}
#ifdef __cplusplus
}
#endif
