#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t * q) {
	return (q->size == 0);
}

void enqueue(struct queue_t * q, struct pcb_t * proc) {
	/* TODO: put a new process to queue [q] */
    if (q->size < MAX_QUEUE_SIZE) {
        q->proc[q->size] = proc;
        q->size++
	}
}

struct pcb_t * dequeue(struct queue_t * q) {
    /* TODO: return a pcb whose prioprity is the highest
        * in the queue [q] and remember to remove it from q
        * */
    if (q->size == 0) return NULL;
    struct pcb_t *temp_proc = NULL;
    /* For finding the highest priority process in queue */
    int current_max_priority = q->proc[0]->priority;
    temp_proc = q->proc[0];
    /* For saving index while searching highest priority process */
    int found_index = 0;
    int i;
    for (i = 1; i < q->size; i++) {
        if (q->proc[i]->priority > current_max_priority) {
            temp_proc = q->proc[i];
            current_max_priority = q->proc[i]->priority;
            found_index = i;
        }
    }
    /* Re-Update queue */
    for (i = found_index; i < q->size - 1; i++)
        q->proc[i] = q->proc[i + 1];
    q->proc[q->size - 1] = NULL;
    --q->size;
    return temp_proc;
}

