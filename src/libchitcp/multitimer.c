/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  An API for managing multiple timers
 */

/*
 *  Copyright (c) 2013-2019, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include "chitcp/multitimer.h"
#include "chitcp/log.h"

void *mt_handler_func(void* args)
{
    multi_timer_t* mt = (multi_timer_t*) args;
    int rc;
    struct timespec ts, temp;

    pthread_mutex_lock(&mt->mt_lock);
    mt->active = true;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ((ts.tv_nsec + (SECOND/2)) / SECOND);
    ts.tv_nsec = ((ts.tv_nsec + (SECOND/2)) % SECOND);

    while (mt->active)
    {
        rc = pthread_cond_timedwait(&mt->mt_cond, &mt->mt_lock, &ts);

        clock_gettime(CLOCK_REALTIME, &ts);

        if (rc == ETIMEDOUT)
        {
            clock_gettime(CLOCK_REALTIME, &ts);
            while (mt->active_timers && timespec_subtract(&temp, 
                &mt->active_timers->expiration, &ts))
            {
                mt->active_timers->timer->num_timeouts += 1;
                mt->active_timers->timer->active = false;

                mt->active_timers->timer->callback_fn(mt, 
                    mt->active_timers->timer, 
                    mt->active_timers->timer->callback_args);

                remove_timer(mt, mt->active_timers->timer->id);
            }
        }
        if (mt->active_timers != NULL)
        {
            ts.tv_sec = mt->active_timers->expiration.tv_sec;
            ts.tv_nsec = mt->active_timers->expiration.tv_nsec;

            /* Normalize Timespec */
            if (ts.tv_nsec > SECOND)
            {
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += ((ts.tv_nsec + (SECOND/2)) / SECOND);
                ts.tv_nsec = ((ts.tv_nsec + (SECOND/2)) % SECOND);
            }
        }
        else 
        {
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += ((ts.tv_nsec + (SECOND/2)) / SECOND);
            ts.tv_nsec = ((ts.tv_nsec + (SECOND/2)) % SECOND);
        }
    }
    pthread_exit(NULL);
}

/* See multitimer.h */
int timespec_subtract(struct timespec *result, struct timespec *x, 
    struct timespec *y)
{
    struct timespec tmp;
    tmp.tv_sec = y->tv_sec;
    tmp.tv_nsec = y->tv_nsec;

    /* Perform the carry for the later subtraction by updating tmp. */
    if (x->tv_nsec < tmp.tv_nsec) {
        uint64_t sec = (tmp.tv_nsec - x->tv_nsec) / SECOND + 1;
        tmp.tv_nsec -= SECOND * sec;
        tmp.tv_sec += sec;
    }
    if (x->tv_nsec - tmp.tv_nsec > SECOND) {
        uint64_t sec = (x->tv_nsec - tmp.tv_nsec) / SECOND;
        tmp.tv_nsec += SECOND * sec;
        tmp.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - tmp.tv_sec;
    result->tv_nsec = x->tv_nsec - tmp.tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < tmp.tv_sec;
}


/* See multitimer.h */
int mt_init(multi_timer_t *mt, uint16_t num_timers)
{
    mt->timers = (single_timer_t**)calloc(1, 
                    sizeof(single_timer_t*) * num_timers);
    if (mt->timers == NULL)
    {
        perror("Could not initialize some part of the multitimer");
        return CHITCP_EINIT;
    }

    mt->num_timers = (int)num_timers;

    for (int id=0; id < num_timers; id++)
    {
        mt->timers[id] = (single_timer_t*)calloc(1, sizeof(single_timer_t));
        if (mt->timers[id] == NULL)
        {
            perror("Could not initialize a timer");
            return CHITCP_EINIT;
        }
        
        mt->timers[id]->active = false;
        mt->timers[id]->id = id;
        mt->timers[id]->num_timeouts = 0;
        mt->timers[id]->callback_fn = NULL;
        mt->timers[id]->callback_args = NULL;
    }

    pthread_mutex_init(&mt->mt_lock, NULL);
    pthread_cond_init(&mt->mt_cond, NULL);
    mt->active_timers = NULL;

    if (pthread_create(&mt->mt_thread, NULL, mt_handler_func, mt) != 0)
    {
        perror("Could not create thread");
        return CHITCP_ETHREAD;
    }

    return CHITCP_OK;
}


/* list_free - Free a linked list of active timers (helper function for free)
 * 
 * active_timers - active timer list to be freed
 * 
 * Returns: nothing
 */
void list_free(active_timer_t* active_timers)
{
    if(active_timers != NULL)
    {
        if (active_timers->next_timer != NULL)
        {
            list_free(active_timers->next_timer);
        }
        free(active_timers);
    }
}

/* See multitimer.h */
int mt_free(multi_timer_t *mt)
{
    while (!mt->active)
    {

    }
    /* Signal Thread to Close */
    pthread_mutex_lock(&mt->mt_lock);
    mt->active = false;
    pthread_cond_signal(&mt->mt_cond);
    pthread_mutex_unlock(&mt->mt_lock);

    pthread_join(mt->mt_thread, NULL);

    /* Free resources */
    pthread_mutex_destroy(&mt->mt_lock);
    pthread_cond_destroy(&mt->mt_cond);

    /* Free single timers, active timers, and lastly multitimer */
    for (int i=0; i<mt->num_timers; i++)
    {
        free(mt->timers[i]);
    }
    free(mt->timers);
    list_free(mt->active_timers);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_get_timer_by_id(multi_timer_t *mt, uint16_t id, single_timer_t **timer)
{
    if (id >= mt->num_timers)
    {
        return CHITCP_EINVAL;
    }

    *timer = mt->timers[id];
    
    return CHITCP_OK;
}

/* 
 * add_to_list - Helper function to add a timer to the linked list of timers.
 * 
 * list: given list to add node to
 * 
 * timer: timer to be added to the linked list
 * 
 * Return: 1 on being first timer, 0 on not
 */
int add_to_list(multi_timer_t *mt, active_timer_t* timer)
{
    // Case 1: list is empty
    if (mt->active_timers == NULL)
    {
        mt->active_timers = timer;
        return 1;
    }
    // Case 2: list is not empty
    active_timer_t* curr = mt->active_timers;
    active_timer_t* prev = NULL;
    struct timespec res;

    while (curr != NULL)
    {
        /* Not using timespec_subtract in order to make this operation 
         * slightly faster
         */
        if (timer->expiration.tv_sec < curr->expiration.tv_sec ||
            (timer->expiration.tv_sec == curr->expiration.tv_sec &&
            timer->expiration.tv_nsec < curr->expiration.tv_nsec))
        {
            // If timer expires earlier than the current timer being looked at,
            // place it before.
            if (prev == NULL)
            {
                mt->active_timers = timer;
                timer->next_timer = curr;
                return 1;
            }
            else
            {
                prev->next_timer = timer;
                timer->next_timer = curr;
                return 0;
            } 
        }
        // If timer expires later, update prev and curr
        prev = curr;
        curr = curr->next_timer;
    }
    // Case 3: end of the list
    prev->next_timer = timer;
    timer->next_timer = NULL;
    return 0;
}


/* See multitimer.h */
int mt_set_timer(multi_timer_t *mt, uint16_t id, uint64_t timeout, 
    mt_callback_func callback_fn, void* callback_args)
{
    while (!mt->active)
    {

    }
    
    mt->timers[id]->active = true;
    mt->timers[id]->callback_fn = callback_fn;
    mt->timers[id]->callback_args = callback_args;

    active_timer_t* new_active_timer = (active_timer_t*)calloc(1, 
            sizeof(active_timer_t));
    new_active_timer->timer = mt->timers[id];
    clock_gettime(CLOCK_REALTIME, &new_active_timer->expiration);
    new_active_timer->expiration.tv_sec += (
        (new_active_timer->expiration.tv_nsec + timeout) / SECOND);
    new_active_timer->expiration.tv_nsec = (
        (new_active_timer->expiration.tv_nsec + timeout) % SECOND);
    new_active_timer->next_timer = NULL;

    pthread_mutex_lock(&mt->mt_lock);
    if (add_to_list(mt, new_active_timer))
    {
        pthread_cond_signal(&mt->mt_cond);
    }
    pthread_mutex_unlock(&mt->mt_lock);

    return CHITCP_OK;
} 


/*
 * remove_timer - remove an active timer from the list
 * 
 * id: id of timer to be removed
 * 
 * head: head of list to remove timer from
 * 
 * Returns: nothing
 */
void remove_timer(multi_timer_t *mt, uint16_t id)
{
    /* Case 1: timer is head */
    if (mt->active_timers->timer->id == id)
    {
        active_timer_t* to_delete = mt->active_timers;
        if (to_delete->next_timer == NULL)
        {
            mt->active_timers = NULL;
        }
        else
        {
            mt->active_timers = mt->active_timers->next_timer;
        }
        free(to_delete);
        return;
    }

    /* Case 2: timer is not head */
    active_timer_t* prev = mt->active_timers;
    active_timer_t* curr = mt->active_timers->next_timer;

    while (curr != NULL)
    {
        if (curr->timer->id == id)
        {
            prev->next_timer = curr->next_timer;
            free(curr);
            return;
        }
        prev = curr;
        curr = curr->next_timer;
    }

    /* Case 3: timer is end of linked list */
    if (curr->timer->id == id)
    {
        prev->next_timer = NULL;
        free(curr);
    }
    return;
}

/* See multitimer.h */
int mt_cancel_timer(multi_timer_t *mt, uint16_t id)
{
    while (!mt->active)
    {

    }
    pthread_mutex_lock(&mt->mt_lock);
    if (!mt->timers[id]->active)
    {
        pthread_mutex_unlock(&mt->mt_lock);
        return CHITCP_EINVAL;
    }
    else
    {
        mt->timers[id]->active = false;
        remove_timer(mt, id);
        pthread_cond_signal(&mt->mt_cond);
        pthread_mutex_unlock(&mt->mt_lock);
        
        return CHITCP_OK;
    }
}


/* See multitimer.h */
int mt_set_timer_name(multi_timer_t *mt, uint16_t id, const char *name)
{
    strncpy(mt->timers[id]->name, name, MAX_TIMER_NAME_LEN);
    return CHITCP_OK;
}


/* mt_chilog_single_timer - Prints a single timer using chilog
 *
 * level: chilog log level
 *
 * timer: Timer
 *
 * Returns: Always returns CHITCP_OK
 */
int mt_chilog_single_timer(loglevel_t level, single_timer_t *timer)
{
    struct timespec now, diff;
    clock_gettime(CLOCK_REALTIME, &now);

    if(timer->active)
    {
        /* Compute the appropriate value for "diff" here; it should contain
         * the time remaining until the timer times out.
         * Note: The timespec_subtract function can come in handy here*/
        diff.tv_sec = 0;
        diff.tv_nsec = 0;
    }
    else
        chilog(level, "%i %s", timer->id, timer->name);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_chilog(loglevel_t level, multi_timer_t *mt, bool active_only)
{
    if (active_only)
    {
        active_timer_t* curr_timer = mt->active_timers;
        while (curr_timer != NULL)
        {
            mt_chilog_single_timer(level, curr_timer->timer);
            curr_timer = curr_timer->next_timer;
        }
    }
    else
    {
        for (int i=0; i<mt->num_timers; i++)
        {
            mt_chilog_single_timer(level, mt->timers[i]);
        }
    }

    return CHITCP_OK;
}
