/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
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
 *    software withsend specific prior written permission.
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
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))



/* Callback args struct definition */
typedef struct callback_args
{
    serverinfo_t *si;
    chisocketentry_t *entry;

} callback_args_t;


/* Helper Function Forward Declarations 
 * 
 * You can find their descriptions in detail at the bottom of the page
 * 
 * */

int check_buff(serverinfo_t *si, chisocketentry_t *entry);
void create_send_packet(serverinfo_t *si, chisocketentry_t *entry, 
                        uint8_t* payload, uint16_t payload_len, char* flags);
int chitcpd_tcp_event_handle_PACKET_ARRIVAL(serverinfo_t *si, chisocketentry_t *entry);
int send_fin(serverinfo_t *si, chisocketentry_t *entry);
void handle_timeoutrtx(tcp_data_t *tcb, serverinfo_t *si, chisocketentry_t *entry);
void handle_timeoutpst(tcp_data_t *tcb, serverinfo_t *si, chisocketentry_t *entry);


void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_data->mt = (multi_timer_t*)calloc(1, sizeof(multi_timer_t));

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);
    mt_init(tcp_data->mt, 2);
    tcp_data->retrans_queue = NULL;
    tcp_data->RTO = MIN_RTO;
    tcp_data->first_probe = true;

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */
    tcp_data->closing = false;
    tcp_data->closed = false;
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);
    mt_free(tcp_data->mt);

}


int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CONNECT)
    {
        /* If the caller does not have access to the local socket specified, 
         * return "error: connection illegal for this process". If no room 
         * to create a new conenction, return "error: insufficient resources" */

        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;

        tcp_packet_t* packet = calloc(1, sizeof(tcp_packet_t));
        chitcpd_tcp_packet_create(entry, packet, NULL, 0);
        
        tcb->ISS = START_SEQ_NUM ;
        tcb->RCV_WND = circular_buffer_available(&tcb->recv);
        tcb->SND_WND = circular_buffer_available(&tcb->send);

        create_send_packet(si, entry, NULL, 0, "sqw");

        tcb->SND_UNA = tcb->ISS;
        tcb->SND_NXT = tcb->ISS + 1;
        circular_buffer_set_seq_initial(&tcb->send, tcb->SND_NXT);

        chitcpd_update_tcp_state(si, entry, SYN_SENT);
        return CHITCP_OK;
    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
    }
    else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);
    }
    else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        chilog(INFO, "In SYN_RCVD state, received TIMEOUT RTX.");
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutrtx(tcb, si, entry);
    }
    else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutrtx(tcb, si, entry);
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_SEND)
    {
        chilog(DEBUG, "APPLICATION SEND TRIGGERED");

        /* Check and send buffer */
        check_buff(si, entry);
        return CHITCP_OK;

    }
    else if (event == PACKET_ARRIVAL)
    {
        chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);

        /* If in CLOSE_WAIT, send a FIN packet */
        if (entry->tcp_state == CLOSE_WAIT)
        {
            if (!circular_buffer_count(&tcb->send))
            {
                send_fin(si, entry);
            }
        }
        return CHITCP_OK;
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        tcb->RCV_WND = circular_buffer_available(&tcb->recv);

        /* Create and send a packet */
        if (!tcb->pending_packets)
        {
            create_send_packet(si, entry, NULL, 0, "aew"); 
        }
        return CHITCP_OK;
    }
    else if (event == APPLICATION_CLOSE)
    {
        chilog(DEBUG, "APPLICATION CLOSE TRIGGERED FROM ESTABLISHED");
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        tcb->closing = true;

        /* If buffer empty, send a FIN */
        if (!circular_buffer_count(&tcb->send) && (tcb->SND_UNA == tcb->SND_NXT))
        {
            send_fin(si, entry);
        }

        return CHITCP_OK;

    }
    else if (event == TIMEOUT_RTX)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutrtx(tcb, si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutpst(tcb, si, entry);
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);
        
        return CHITCP_OK;
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        tcb->RCV_WND = circular_buffer_available(&tcb->recv);
    }
    else if (event == TIMEOUT_RTX)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutrtx(tcb, si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutpst(tcb, si, entry);
    }
    else
       chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);
        
        return CHITCP_OK;
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        tcb->RCV_WND = circular_buffer_available(&tcb->recv);
    }
    else if (event == TIMEOUT_RTX)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutrtx(tcb, si, entry);
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CLOSE)
    {
        chilog(DEBUG, "APPLICATION CLOSE TRIGGERED FROM CLOSE WAIT");
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        tcb->closing = true;

        send_fin(si, entry);

        return CHITCP_OK;
    }
    else if (event == PACKET_ARRIVAL)
    {
        chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);
        
        return CHITCP_OK;
    }
    else if (event == TIMEOUT_RTX)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutrtx(tcb, si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutpst(tcb, si, entry);
    }
    else
       chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);


    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);
        
        return CHITCP_OK;
    }
    else if (event == TIMEOUT_RTX)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutrtx(tcb, si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutpst(tcb, si, entry);
    }
    else
       chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");
    chitcpd_update_tcp_state(si, entry, CLOSED);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        chitcpd_tcp_event_handle_PACKET_ARRIVAL(si, entry);
        return CHITCP_OK;
    }
    else if (event == TIMEOUT_RTX)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutrtx(tcb, si, entry);
    }
    else if (event == TIMEOUT_PST)
    {
        tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
        handle_timeoutpst(tcb, si, entry);
    }
    else
       chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */


/* See multitimer.h */
void trigger_rtx(multi_timer_t* mt, single_timer_t* timer, void* callback_args)
{
    callback_args_t* cb = (callback_args_t*)callback_args;
    chitcpd_timeout(cb->si, cb->entry, RETRANSMISSION);
}

void trigger_pst(multi_timer_t* mt, single_timer_t* timer, void* callback_args)
{
    callback_args_t* cb = (callback_args_t*)callback_args;
    chitcpd_timeout(cb->si, cb->entry, PERSIST);
}

/* 
 * add_to_rtqueue - Adds a packet and its metadata to the retransmission queue
 * 
 * tcb: tcp data
 * 
 * packet: packet to be added to queue
 * 
 * Returns: nothing
 */
void add_to_rtqueue(tcp_data_t *tcb, tcp_packet_t *packet)
{
    retrans_queue_t *head = tcb->retrans_queue;
    retrans_queue_t *new_entry = calloc(1, sizeof(retrans_queue_t));
    new_entry->time_sent = (struct timespec*)calloc(1, sizeof(struct timespec));
    new_entry->next = NULL;
    new_entry->packet = packet;
    clock_gettime(CLOCK_REALTIME, new_entry->time_sent);
    
    if (head == NULL)
    {
        LL_PREPEND(tcb->retrans_queue,new_entry);
    }
    else
    {
        LL_APPEND(tcb->retrans_queue, new_entry);
    }
    chilog(DEBUG, "Added packet with SEQ %d to queue", SEG_SEQ(packet));
}

/*
 * update_all_R - A function to update RTO, RTT, SRTT, and anything related
 * 
 * tcb: tcb data struct
 * 
 * rcv: time packet was received
 * 
 * sent: time packet was sent
 * 
 * Returns: nothing
 */
void update_all_R(tcp_data_t* tcb, struct timespec *rcv, struct timespec *sent, chisocketentry_t *entry)
{
    uint64_t hold;
    struct timespec RTT;
    double beta = 0.25;
    double alpha = 0.125;

    timespec_subtract(&RTT, rcv, sent);

    if (entry->tcp_state == SYN_RCVD)
    {
        tcb->SRTT = RTT.tv_sec * SECOND;
        tcb->RTTVAR = (RTT.tv_sec * SECOND) / 2;
        tcb->RTO = tcb->SRTT + MAX(CLOCK_GRAN, 4 * tcb->RTTVAR);

    }
    else
    {
        if (tcb->SRTT > RTT.tv_nsec)
        {
            hold = tcb->SRTT - RTT.tv_nsec;
        }
        else
        {
            hold = RTT.tv_nsec - tcb->SRTT;
        }

        tcb->RTTVAR = ((1 - beta) * (tcb->RTTVAR) + beta * abs(tcb->SRTT - hold));
        tcb->SRTT = ((1 - alpha) * (tcb->SRTT) + alpha * hold);
        tcb->RTO = tcb->SRTT + MAX(CLOCK_GRAN, 4 * (tcb->RTTVAR));
    }

    tcb->RTO = MAX(MIN_RTO, tcb->RTO);
    tcb->RTO = MIN(MAX_RTO, tcb->RTO);
}


/*
 * rmv_from_rtqueue - Removes a packet from the retransmission queue
 * 
 * tcb: tcp data
 * 
 * Returns: nothing
 */
void rmv_from_rtqueue(tcp_data_t *tcb, tcp_packet_t *incoming_packet, 
                        serverinfo_t *si, chisocketentry_t *entry)
{
    retrans_queue_t *elt, *tmp;
    retrans_queue_t* queue = tcb->retrans_queue;
    callback_args_t *callback_args = calloc(1, sizeof(callback_args_t));

    callback_args->si = si;
    callback_args->entry = entry;

    LL_FOREACH_SAFE(queue, elt, tmp)
    {
        if (SEG_SEQ(elt->packet) + TCP_PAYLOAD_LEN(elt->packet) < 
                SEG_ACK(incoming_packet))
        {
            struct timespec curr_time;
            clock_gettime(CLOCK_REALTIME, &curr_time);
            LL_DELETE(queue, elt);
            update_all_R(tcb, &curr_time, elt->time_sent, entry);
        }
    }


}

/* 
 * handle_timeoutrtx - A function to handle RTX Timeouts
 * 
 * tcb: tcp data from the server
 * 
 * si: server info
 * 
 * entry: socket entry
 * 
 * Returns: nothing
 */
void handle_timeoutrtx(tcp_data_t *tcb, serverinfo_t *si, chisocketentry_t *entry)
{
    retrans_queue_t *elt;
    retrans_queue_t *queue = tcb->retrans_queue;
    callback_args_t *callback_args = calloc(1, sizeof(callback_args));

    callback_args->si = si;
    callback_args->entry = entry;

    LL_FOREACH(queue, elt)
    {
        chitcpd_send_tcp_packet(si, entry, elt->packet);
        clock_gettime(CLOCK_REALTIME, elt->time_sent);
        chilog(DEBUG, "retransmitted packet with SEQ %d", SEG_SEQ(elt->packet));
    }

    tcb->RTO = MAX(MIN_RTO, tcb->RTO*2);
    tcb->RTO = MIN(MAX_RTO, tcb->RTO*2);

    chilog(DEBUG, "reset rtx timer");
    mt_set_timer(tcb->mt, RETRANSMISSION, tcb->RTO, trigger_rtx, callback_args);

}

/* 
 * handle_timeoutpst - A function to handle PST Timeouts
 * 
 * tcb: tcp data from server
 * 
 * si: server info
 * 
 * entry: socket entry
 * 
 * Returns: nothing
 */
void handle_timeoutpst(tcp_data_t *tcb, serverinfo_t *si, chisocketentry_t *entry)
{
    uint8_t *snd_buff = calloc(1, sizeof(uint8_t*));
    callback_args_t *callback_args = calloc(1, sizeof(callback_args));

    callback_args->si = si;
    callback_args->entry = entry;

    
    if (circular_buffer_count(&tcb->send) == 0)
    {
        chilog(DEBUG, "nothing to send with persist");
        mt_set_timer(tcb->mt, 1, tcb->RTO, trigger_pst, callback_args);
    }
    else
    {
        if (tcb->first_probe == true)
        {
            tcb->first_probe == false;
            circular_buffer_peek(&tcb->send, snd_buff, (uint16_t)1, false);
            tcb->SND_NXT += 1;
            create_send_packet(si, entry, snd_buff, (uint16_t)1, "aew");
            if (tcb->mt->timers[1]->active == true)
            {
                mt_cancel_timer(tcb->mt, 1);
            }
            mt_set_timer(tcb->mt, PERSIST, tcb->RTO, trigger_pst, callback_args);

        }
        else
        {
            chilog(DEBUG, "sending probe with persist");
            circular_buffer_peek(&tcb->send, snd_buff, (uint16_t)1, false);
            create_send_packet(si, entry, snd_buff, (uint16_t)1, "aew");
            if (tcb->first_probe == true)
            {
                mt_cancel_timer(tcb->mt, 1);
            }
            mt_set_timer(tcb->mt, PERSIST, tcb->RTO, trigger_pst, callback_args);
            
        }
    }
}


/* 
 * create_send_packet - Creates a packet and sends it
 * 
 * si: pointer to struct with chiTCP daemon's runtime info
 * 
 * entry: pointer to socket entry for connection being handled
 * 
 * payload: pointer to payload (will be DEEP COPIED to the packet)
 * 
 * payload_len: size of the payload in number of bytes
 * 
 * flags: A string representing flags that need to be set
 * 
 * Returns: nothing
 */
void create_send_packet(serverinfo_t *si, chisocketentry_t *entry, 
                        uint8_t* payload, uint16_t payload_len, char* flags)
{
    
    tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
    tcp_packet_t* packet = calloc(1, sizeof(tcp_packet_t));
    callback_args_t *callback_args = calloc(1, sizeof(callback_args_t));

    callback_args->si = si;
    callback_args->entry = entry;

    /* Create the packet */
    chitcpd_tcp_packet_create(entry, packet, payload, payload_len);

    /* Create the header */
    tcphdr_t* header = TCP_PACKET_HEADER(packet);

    /* Set header flags */
    for (int i = 0; i < strlen(flags); i++)
    {
        if (flags[i] == 'a')
        {
            header->ack = 1;
            header->ack_seq = chitcp_htonl(tcb->RCV_NXT);
        }
        if (flags[i] == 'e')
        {
            header->seq = chitcp_htonl(tcb->SND_NXT);
        }
        if (flags[i] == 'q')
        {
            header->seq = chitcp_htonl(tcb->ISS);
        }
        if (flags[i] == 'w')
        {
            header->win = chitcp_htons(tcb->RCV_WND);
        }
        if (flags[i] == 'f')
        {
            header->fin = 1;
        }
        if (flags[i] == 's')
        {
            header->syn = 1;
        }
    }

    /* Send out, add to retransmission queue, and free the packet */
    chitcpd_send_tcp_packet(si, entry, packet);
    add_to_rtqueue(tcb, packet);
    mt_cancel_timer(tcb->mt, RETRANSMISSION);
    mt_set_timer(tcb->mt, RETRANSMISSION, tcb->RTO, trigger_rtx, callback_args);

}

/*
 * send_fin - Send a fin segment
 * 
 * si: pointer to serverinfo_t struct
 *
 * entry: pointer to socket entry
 *
 * Returns: int
 */
int send_fin(serverinfo_t *si, chisocketentry_t *entry)
{
    chilog(DEBUG, "Sending FIN:");
    tcp_data_t *tcb = &entry->socket_state.active.tcp_data;
    chilog(DEBUG, "Ack: %d, Seq: %d", tcb->RCV_NXT, tcb->SND_NXT);
    
    if (tcb->closing && !tcb->closed)
    {
        /* Create and send packet */
        create_send_packet(si, entry, NULL, 0, "fae");

        tcb->fin_seq = tcb->SND_NXT;
        tcb->SND_NXT += 1;

        /* If in ESTABLISHED state, go to FIN_WAIT_1*/
        if (entry->tcp_state == ESTABLISHED)
        {
            chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
        }
        /* If in CLOSE_WAIT state, go to FIN_WAIT_1 */
        else if (entry->tcp_state == CLOSE_WAIT)
        {
            chitcpd_update_tcp_state(si, entry, LAST_ACK);
        }
    }
    return CHITCP_OK;
}


/* check_buff - Checks to see if anything in the send buffer. If there is,
 * sends it.
 * 
 * si: server info
 * 
 * entry: pointer to socket entry for connection being handled
 * 
 * Returns: int
 */
int check_buff(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcb = &entry->socket_state.active.tcp_data;
    uint16_t window = tcb->SND_WND - (tcb->SND_NXT - tcb->SND_UNA);
    uint8_t *dst_buff = NULL;
    uint16_t bytes_remaining = circular_buffer_count(&tcb->send);

    if (window < bytes_remaining)
    {
        bytes_remaining = window;
    }
    uint32_t bytes_to_send = 0;

    while(bytes_remaining > 0)
    {
        if (bytes_remaining > TCP_MSS)
        {
            bytes_to_send = TCP_MSS;
        }
        else
        {
            bytes_to_send = bytes_remaining;
        }

        int mem = (int) bytes_to_send;
        dst_buff = (uint8_t*)calloc((mem + 1), sizeof(uint8_t));

        int payload_size = circular_buffer_read(&tcb->send, dst_buff, 
                                    bytes_to_send, false);

        create_send_packet(si, entry, dst_buff, (uint16_t)payload_size, "aew");

        tcb->SND_NXT += payload_size;
        bytes_remaining -= bytes_to_send;
    }
    return CHITCP_OK;
}


/*
 * cmp_packets - Compare two packets for utlist sort function
 * 
 * first: first packet
 * 
 * second: second packet
 *
 * Returns: int
*/
int cmp_packets(tcp_packet_list_t *first, tcp_packet_list_t *second) 
{
    if (SEG_SEQ(first->packet) < SEG_SEQ(second->packet))
    {
        return -1;
    }
    else if (SEG_SEQ(first->packet) > SEG_SEQ(second->packet))
    {
        return 1;
    }
    return 0;
}

/* 
 * chitcpd_tcp_event_handle_PACKET_ARRIVAL - handles packet arrivals 
 * across all states
 * 
 * si: pointer to struct with chiTCP daemon's runtime info
 * 
 * entry: pointer to socket entry for connection being handled
 * 
 * Returns: int
 */
int chitcpd_tcp_event_handle_PACKET_ARRIVAL(serverinfo_t *si, 
        chisocketentry_t *entry)
{

    tcp_data_t* tcb = &entry->socket_state.active.tcp_data;
    retrans_queue_t* rt_queue = tcb->retrans_queue;
    tcp_packet_t* packet_inc = NULL;
    struct timespec *time_rcv = (struct timespec*)calloc(1, 
                                    sizeof(struct timespec));
    struct timespec *time_sent;
    if (rt_queue != NULL)
    {
        time_sent = tcb->retrans_queue->time_sent;
    }

    clock_gettime(CLOCK_REALTIME, time_rcv);

    /* If there are pending packets, take one out and process it */
    if (tcb->pending_packets)
    {
        pthread_mutex_lock(&tcb->lock_pending_packets);
        packet_inc = tcb->pending_packets->packet;
        chitcp_packet_list_pop_head(&tcb->pending_packets);
        pthread_mutex_unlock(&tcb->lock_pending_packets);
    }
    else
    {
        /* just say fuck it */
        return CHITCP_OK;
    }



    tcphdr_t* header_inc = TCP_PACKET_HEADER(packet_inc);

    /***************** LISTEN state *****************/
    if (entry->tcp_state == LISTEN)
    {
        /* Check for an ACK */
        if (SEG_ACK(packet_inc))
        {
            chitcp_tcp_packet_free(packet_inc);
            free(packet_inc);
            return CHITCP_OK;
        }
        /* Check for a SYN */
        if (header_inc->syn)
        {
            tcb->RCV_NXT = SEG_SEQ(packet_inc) + 1;
            tcb->IRS = SEG_SEQ(packet_inc);
            circular_buffer_set_seq_initial(&tcb->recv, tcb->RCV_NXT);
            tcb->RCV_WND = circular_buffer_available(&tcb->recv);
            /* Any other control or text is to be queued and processed later */

            /* Continuing */
            create_send_packet(si, entry, NULL, 0, "saqw");
            
            
            tcb->SND_NXT = tcb->ISS + 1;
            tcb->SND_UNA = tcb->ISS;
            circular_buffer_set_seq_initial(&tcb->send, tcb->SND_NXT);

            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
            chitcp_tcp_packet_free(packet_inc);
            free(packet_inc);
            return CHITCP_OK;
        }
    }
    
    /***************** SYN_SENT state *****************/
    if (entry->tcp_state == SYN_SENT)
    {
        /* Check ACK bit */
        if (header_inc->ack)
        {
            if ((SEG_ACK(packet_inc) <= tcb->ISS) || 
                 SEG_ACK(packet_inc) > tcb->SND_NXT)
            {
                return CHITCP_OK;
            }
            if ((tcb->SND_UNA <= SEG_ACK(packet_inc)) && 
                (SEG_ACK(packet_inc) <= tcb->SND_NXT))
            {
                /* it just says its acceptable, unsure if implicit */
            }
        }
        /* Check SYN bit */
        if (header_inc->syn)
        {
            tcb->RCV_NXT = SEG_SEQ(packet_inc) + 1;
            tcb->IRS = SEG_SEQ(packet_inc);
            circular_buffer_set_seq_initial(&tcb->recv, tcb->RCV_NXT);
            if (header_inc->ack)
            {
                tcb->SND_UNA = SEG_ACK(packet_inc);
                tcb->SND_WND = SEG_WND(packet_inc);
            }
            /* remove any acknowledged segements on send buffer */

          
            if (tcb->SND_UNA > tcb->ISS)
            {
                /* Queue transmission here as well */
                tcb->SND_WND = SEG_WND(packet_inc);
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);

                create_send_packet(si, entry, NULL, 0, "awe");
            }
            else
            {
                chitcpd_update_tcp_state(si, entry, SYN_RCVD);

                create_send_packet(si, entry, NULL, 0, "awqs");
            }

        }
        /* If !SYN and !RST, drop segment, return */
        chitcp_tcp_packet_free(packet_inc);
        free(packet_inc);
        return CHITCP_OK;
    }

    /* General Algorithm */
    /***************** Remaining states *****************/
    /* Step 1: Check sequence number */
    bool unacceptable_seg = false;
    if (!SEG_LEN(packet_inc))
    {
        if (!tcb->RCV_WND && (SEG_SEQ(packet_inc) != tcb->RCV_NXT))
        {
            unacceptable_seg = true;
        }
        else if (tcb->RCV_WND > 0)
        {
            if (tcb->RCV_NXT > SEG_SEQ(packet_inc) || 
                SEG_SEQ(packet_inc) >= (tcb->RCV_NXT + tcb->RCV_WND))
            {
                unacceptable_seg = true;
            }
        }
    }
    else if (SEG_LEN(packet_inc) > 0)
    {
        if (!tcb->RCV_WND)
        {
            unacceptable_seg = true;
        }
        else if (tcb->RCV_WND > 0)
        {
            if (tcb->RCV_NXT > SEG_SEQ(packet_inc) || 
                SEG_SEQ(packet_inc) >= (tcb->RCV_NXT + tcb->RCV_WND))
            {
                unacceptable_seg = true;
            }
            if (tcb->RCV_NXT > (SEG_SEQ(packet_inc) + SEG_LEN(packet_inc) - 1) 
                || (SEG_SEQ(packet_inc) + SEG_LEN(packet_inc) - 1) >= 
                (tcb->RCV_NXT + tcb->RCV_WND))
            {
                unacceptable_seg = true;
            }
        }
    }

    if (unacceptable_seg)
    {
        create_send_packet(si, entry, NULL, 0, "aew");
        
        chitcp_tcp_packet_free(packet_inc);
        free(packet_inc);
        return CHITCP_OK;
    }
    if (SEG_SEQ(packet_inc) > tcb->RCV_NXT && SEG_LEN(packet_inc))
    {
        create_send_packet(si, entry, NULL, 0, "aew");

        if (SEG_SEQ(packet_inc) > tcb->RCV_NXT)
        {
            tcp_packet_list_t *new_packet = calloc(1, sizeof(tcp_packet_list_t));
            new_packet->packet = packet_inc;
        
            chilog(DEBUG, "Adding to ood list 2 %d", SEG_SEQ(packet_inc));

            DL_INSERT_INORDER(tcb->ood_packets, new_packet, cmp_packets);
        }

        return CHITCP_OK;
    }
    

    chilog(DEBUG, "%d packet_inc seg_wnd", SEG_WND(packet_inc));



    if (SEG_WND(packet_inc) == 0)
    {
        chilog(DEBUG, "persist activated");
        callback_args_t *callback_args = calloc(1, sizeof(callback_args_t));
        callback_args->si = si;
        callback_args->entry = entry;
        if (tcb->mt->timers[1]->active == true)
        {
            mt_cancel_timer(tcb->mt, 1);
        }
        mt_set_timer(tcb->mt, 1, tcb->RTO, trigger_pst, callback_args);
    }
    else
    {
        if (tcb->mt->timers[1]->active == true)
        {
            mt_cancel_timer(tcb->mt, 1);
        }
    }


    /* Step 4: Check the SYN Bit */
    if (header_inc->syn)
    {
    }

    /* Step 5: Check ACK */
    if (!header_inc->ack)
    {
        chitcp_tcp_packet_free(packet_inc);
        free(packet_inc);
        return CHITCP_OK;
    }
    else
    {
        if (SEG_ACK(packet_inc) == tcb->SND_NXT)
        {
            mt_cancel_timer(tcb->mt, RETRANSMISSION);
        }
        else if (SEG_ACK(packet_inc) >= tcb->SND_UNA)
        {
            callback_args_t *callback_args = calloc(1, sizeof(callback_args));
            callback_args->si = si;
            callback_args->entry = entry;


            rmv_from_rtqueue(tcb, packet_inc, si, entry);

            mt_set_timer(tcb->mt, RETRANSMISSION, tcb->RTO, trigger_rtx, 
                            callback_args);
        }
    }

    if (tcb->ood_packets != NULL)
    {
        if (SEG_ACK(packet_inc) + SEG_LEN(packet_inc) == 
            SEG_SEQ(tcb->ood_packets->packet))
        {
            tcp_packet_list_t *new_packet = calloc(1, sizeof(tcp_packet_list_t));
            new_packet->packet = tcb->ood_packets->packet;

            pthread_mutex_lock(&tcb->lock_pending_packets);
            DL_APPEND(tcb->pending_packets, new_packet);
            pthread_mutex_unlock(&tcb->lock_pending_packets);
            
            chitcp_packet_list_pop_head(&tcb->ood_packets);
        }
    }
        



    /* Step 5: SYN_RCVD */
    if (entry->tcp_state == SYN_RCVD)
    {
        if (tcb->SND_UNA > SEG_ACK(packet_inc) &&  
            (SEG_ACK(packet_inc) > tcb->SND_NXT))
        {
            /* send reset segment -> not supported */
        }
        else
        {
            /* Response to a bug about how chitcpd_update_tcp_state() works */
            if (tcb->SND_UNA < SEG_ACK(packet_inc))
            {
                tcb->SND_UNA = SEG_ACK(packet_inc);
                tcb->SND_WND = SEG_WND(packet_inc);
            }
            chitcpd_update_tcp_state(si, entry, ESTABLISHED);
        }
    }

    /* Step 5: ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT */
    if ((entry->tcp_state == ESTABLISHED) || (entry->tcp_state == FIN_WAIT_1) ||
        (entry->tcp_state == FIN_WAIT_2) || (entry->tcp_state == CLOSE_WAIT))
    {
        /* General step 5 algorithm (ESTABLISHED and CLOSE_WAIT) */
        if (tcb->SND_UNA < SEG_ACK(packet_inc) && 
            tcb->SND_NXT >= SEG_ACK(packet_inc))
        {
            tcb->SND_UNA = SEG_ACK(packet_inc);
            tcb->SND_WND = SEG_WND(packet_inc);
        }

        if (SEG_ACK(packet_inc) > tcb->SND_NXT)
        {

            create_send_packet(si, entry, NULL, 0, "aew");

            chitcp_tcp_packet_free(packet_inc);
            free(packet_inc);
            return CHITCP_OK;
        }
        /* Update Send Window */
        tcb->SND_WND = SEG_WND(packet_inc);


        /* Step 5: FIN_WAIT_1 */
        if (entry->tcp_state == FIN_WAIT_1)
        {
            if (SEG_ACK(packet_inc) == tcb->fin_seq + 1)
            {
                chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
            }
        }

        /* Step 5: FIN_WAIT_2 */
        if (entry->tcp_state == FIN_WAIT_2)
        {
            chilog(DEBUG, "FIN_WAIT_2 check ack");
            if (tcb->retrans_queue == NULL)
            {
                create_send_packet(si, entry, NULL, 0, "aew");
            }
        }
        /* Step 5: CLOSING */
        if (entry->tcp_state == CLOSING)
        {
            
            if (SEG_ACK(packet_inc) == tcb->fin_seq + 1)
            {
                chitcpd_update_tcp_state(si, entry, TIME_WAIT);
            }
            else
            {
                //ignore last segment
            }
        return CHITCP_OK;
        }
    }
    /* Step 5: LAST_ACK */
    if (entry->tcp_state == LAST_ACK)
    {
        //delete the TCB
        chitcpd_update_tcp_state(si, entry, CLOSED);
        return CHITCP_OK;
    }
    /* Step 7: Process segment text */
    if (SEG_LEN(packet_inc))
    {
        circular_buffer_write(&tcb->recv, TCP_PAYLOAD_START(packet_inc), 
        SEG_LEN(packet_inc), false);
        tcb->RCV_NXT = circular_buffer_next(&tcb->recv);
    }
    
    /* If there are things in the buffer, send it */
    if (circular_buffer_count(&tcb->send) > 0)
    {
        check_buff(si, entry);
    } else if (tcb->closing && (entry->tcp_state == ESTABLISHED 
        || entry->tcp_state == CLOSE_WAIT))
    {
        send_fin(si, entry);
    }
    

    /* Step 8: Check FIN */
    if (header_inc->fin)
    {
        if (entry->tcp_state == SYN_RCVD || entry->tcp_state == ESTABLISHED)
        {
            chilog(DEBUG, "FIN FOUND IN ESTABLISHED");
            chilog(DEBUG, "Sending ACK:");
            tcb->RCV_NXT = SEG_SEQ(packet_inc) + 1;

            create_send_packet(si, entry, NULL, 0, "aew");

            chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);
            chitcp_tcp_packet_free(packet_inc);
            free(packet_inc);
            return CHITCP_OK;
        }

        create_send_packet(si, entry, NULL, 0, "aew");


        if (entry->tcp_state == FIN_WAIT_1)
        {
            chilog(DEBUG, "FIN DETECTED IN FIN_WAIT_1");
            send_fin(si, entry);
            if (SEG_ACK(packet_inc) == tcb->SND_NXT)
            {

                tcb->RCV_NXT = SEG_SEQ(packet_inc) + 1;
                tcb->SND_NXT = SEG_ACK(packet_inc);


                chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                chitcpd_update_tcp_state(si, entry, CLOSED);
                chitcp_tcp_packet_free(packet_inc);
                free(packet_inc);
                return CHITCP_OK;
            }
            else 
            {
                chitcpd_update_tcp_state(si, entry, CLOSING);
                chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                chitcpd_update_tcp_state(si, entry, CLOSED);
                return CHITCP_OK;
            }
        }
        if (entry->tcp_state == FIN_WAIT_2)
        {
            chilog(DEBUG, "FIN DETECTED IN FIN_WAIT_2");
            tcb->RCV_NXT = SEG_SEQ(packet_inc) + 1;
            tcb->SND_NXT = SEG_ACK(packet_inc);
            create_send_packet(si, entry, NULL, 0, "aew");

            chitcpd_update_tcp_state(si, entry, TIME_WAIT);
            chitcpd_update_tcp_state(si, entry, CLOSED);
            chitcp_tcp_packet_free(packet_inc);
            free(packet_inc);
            return CHITCP_OK;
        }
    }

    /* Step 9: Return */
    chitcp_tcp_packet_free(packet_inc);
    free(packet_inc);
    return CHITCP_OK;

}