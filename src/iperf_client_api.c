/*
 * iperf, Copyright (c) 2014, 2015, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
#include <time.h>
#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_util.h"
#include "iperf_locale.h"
#include "net.h"
#include "timer.h"

int burst_count = 0;

int
iperf_create_streams(struct iperf_test *test)
{
    int i, s;
    struct iperf_stream *sp;

    int orig_bind_port = test->bind_port;
    for (i = 0; i < test->num_streams; ++i) {

        test->bind_port = orig_bind_port;
	if (orig_bind_port)
	    test->bind_port += i;
        if ((s = test->protocol->connect(test)) < 0)
            return -1;

	if (test->sender)
	    FD_SET(s, &test->write_set);
	else
	    FD_SET(s, &test->read_set);

	if (s > test->max_fd) test->max_fd = s;

        sp = iperf_new_stream(test, s);
        if (!sp)
            return -1;

        /* Perform the new stream callback */
        if (test->on_new_stream)
            test->on_new_stream(sp);
    }

    return 0;
}

int client_recv(struct iperf_stream *sp)
{
    char buffer[2000];
    int r = Nread(sp->socket, buffer, 2000, Ptcp);
    return r;
}

static void
test_timer_proc(TimerClientData client_data, struct timeval *nowP)
{
    struct iperf_test *test = client_data.p;

    test->timer = NULL;
    test->done = 1;
}

static void
client_stats_timer_proc(TimerClientData client_data, struct timeval *nowP)
{
    struct iperf_test *test = client_data.p;

    if (test->done)
        return;
    if (test->stats_callback)
	test->stats_callback(test);
}

static void
client_reporter_timer_proc(TimerClientData client_data, struct timeval *nowP)
{
    struct iperf_test *test = client_data.p;

    if (test->done)
        return;
    if (test->reporter_callback)
	test->reporter_callback(test);
}

static int
create_client_timers(struct iperf_test * test)
{
    struct timeval now;
    TimerClientData cd;

    if (gettimeofday(&now, NULL) < 0) {
	i_errno = IEINITTEST;
	return -1;
    }
    cd.p = test;
    test->timer = test->stats_timer = test->reporter_timer = NULL;
    if (test->duration != 0) {
	test->done = 0;
        test->timer = tmr_create(&now, test_timer_proc, cd, ( test->duration + test->omit ) * SEC_TO_US, 0);
        if (test->timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
	}
    } 
    if (test->stats_interval != 0) {
        test->stats_timer = tmr_create(&now, client_stats_timer_proc, cd, test->stats_interval * SEC_TO_US, 1);
        if (test->stats_timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
	}
    }
    if (test->reporter_interval != 0) {
        test->reporter_timer = tmr_create(&now, client_reporter_timer_proc, cd, test->reporter_interval * SEC_TO_US, 1);
        if (test->reporter_timer == NULL) {
            i_errno = IEINITTEST;
            return -1;
	}
    }
    return 0;
}

static void
client_omit_timer_proc(TimerClientData client_data, struct timeval *nowP)
{
    struct iperf_test *test = client_data.p;

    test->omit_timer = NULL;
    test->omitting = 0;
    iperf_reset_stats(test);
    if (test->verbose && !test->json_output && test->reporter_interval == 0)
        iprintf(test, "%s", report_omit_done);

    /* Reset the timers. */
    if (test->stats_timer != NULL)
        tmr_reset(nowP, test->stats_timer);
    if (test->reporter_timer != NULL)
        tmr_reset(nowP, test->reporter_timer);
}

static int
create_client_omit_timer(struct iperf_test * test)
{
    struct timeval now;
    TimerClientData cd;

    if (test->omit == 0) {
	test->omit_timer = NULL;
        test->omitting = 0;
    } else {
	if (gettimeofday(&now, NULL) < 0) {
	    i_errno = IEINITTEST;
	    return -1;
	}
	test->omitting = 1;
	cd.p = test;
	test->omit_timer = tmr_create(&now, client_omit_timer_proc, cd, test->omit * SEC_TO_US, 0);
	if (test->omit_timer == NULL) {
	    i_errno = IEINITTEST;
	    return -1;
	}
    }
    return 0;
}

int
iperf_handle_message_client(struct iperf_test *test)
{
    int rval;
    int32_t err;

    /*!!! Why is this read() and not Nread()? */
    if ((rval = read(test->ctrl_sck, (char*) &test->state, sizeof(signed char))) <= 0) {
        if (rval == 0) {
            i_errno = IECTRLCLOSE;
            return -1;
        } else {
            i_errno = IERECVMESSAGE;
            return -1;
        }
    }

    switch (test->state) {
        case PARAM_EXCHANGE:
            if (iperf_exchange_parameters(test) < 0)
                return -1;
            /* after exchanging parameters, we know if the client supports mptcp
             * if so we initialize the json structures */
            if ((test->remote_iperf_supports_mptcp) && (!test->json_output))
                if (iperf_json_start(test))
                    return -1;
            if (test->on_connect)
                test->on_connect(test);
            break;
        case CREATE_STREAMS:
            if (iperf_create_streams(test) < 0)
                return -1;
            break;
        case TEST_START:
            if (iperf_init_test(test) < 0)
                return -1;
            if (create_client_timers(test) < 0)
                return -1;
            if (create_client_omit_timer(test) < 0)
                return -1;
            break;
        case TEST_RUNNING:
            break;
        case EXCHANGE_RESULTS:
            if (iperf_exchange_results(test) < 0)
                return -1;
            break;
        case DISPLAY_RESULTS:
            if (test->on_test_finish)
                test->on_test_finish(test);
            iperf_client_end(test);
            break;
        case IPERF_DONE:
            break;
        case SERVER_TERMINATE:
            i_errno = IESERVERTERM;

	    /*
	     * Temporarily be in DISPLAY_RESULTS phase so we can get
	     * ending summary statistics.
	     */
	    signed char oldstate = test->state;
	    cpu_util(test->cpu_util);
	    test->state = DISPLAY_RESULTS;
	    test->reporter_callback(test);
	    test->state = oldstate;
            return -1;
        case ACCESS_DENIED:
            i_errno = IEACCESSDENIED;
            return -1;
        case SERVER_ERROR:
            if (Nread(test->ctrl_sck, (char*) &err, sizeof(err), Ptcp) < 0) {
                i_errno = IECTRLREAD;
                return -1;
            }
	    i_errno = ntohl(err);
            if (Nread(test->ctrl_sck, (char*) &err, sizeof(err), Ptcp) < 0) {
                i_errno = IECTRLREAD;
                return -1;
            }
            errno = ntohl(err);
            return -1;
        default:
            i_errno = IEMESSAGE;
            return -1;
    }

    return 0;
}

#include <ifaddrs.h>
#include <stdbool.h>

bool isHostInterface(char *iface){
    struct ifaddrs  *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        if(strcmp(ifa->ifa_name, iface)==0)
            return true;
    freeifaddrs(ifaddr);
    return false;
}

/* get IP of the requested interface and family
 * set family = 0 to get IP of any family if you don't care about family */
struct sockaddr_storage * getIPfromInterface(struct iperf_test *test, int family, char * iface)
{
    if ((family != AF_INET) && (family != AF_INET6) && (family != 0)) {
        if (test->debug)
            printf ("invalid family value\n");
        return NULL;
    }

    struct ifaddrs  *ifaddr, *ifa;
    struct sockaddr_storage *addr;
    addr = malloc(sizeof(struct sockaddr_storage));

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    /* Walk through linked list, maintaining head pointer so we
       can free list later */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr_storage));
        /*
        if (test->debug) {
            char *host = ip_to_str(ifa->ifa_addr);
            printf("\tInterface : <%s>\n", ifa->ifa_name);
            printf("\t  Address : <%s>\n", host );
        } */
        if(strcmp(ifa->ifa_name, iface) == 0) {
            if (((addr->ss_family == AF_INET)  && (family == AF_INET))
             || ((addr->ss_family == AF_INET6) && (family == AF_INET6))) {
                freeifaddrs(ifaddr);
                return addr;
            }
            if ((family == 0) &&
                ((addr->ss_family == AF_INET) || (addr->ss_family == AF_INET6))) {
                freeifaddrs(ifaddr);
                return addr;
            }
        }
    }
    fprintf(stderr, "cannot find IP for this interface\n");
    freeifaddrs(ifaddr);
    free(addr);
    return NULL;
}
int get_server_family(struct iperf_test *test) {
    struct addrinfo hints, *server_res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = test->settings->domain;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(test->server_hostname, NULL, &hints, &server_res) != 0) {
        return AF_UNSPEC;
    }
    return server_res->ai_family;
}

/* parse subflow list and get their ips which match server IP family */
/* also set test->num_subflows as number of requested subflows */

int get_local_ips_for_subflows(struct iperf_test *test, int family)
{
    char *token;
    struct iperf_subflow *sf;
    char *requested_subflows = malloc( sizeof(char)*strlen(test->requested_subflows) + 1);
    /* strsep will modify the input string, so we need to provide the copy */
    strcpy(requested_subflows, test->requested_subflows);

    while ((token = strsep(&requested_subflows, ",")))
    {
        if (test->debug)
            printf("%s \n",token);
        // this is initial subflow.
        if (test->num_subflows == 0) {
            if (isHostInterface(token)) {
                // look up for IP address
                // test->bind_address = malloc(INET6_ADDRSTRLEN);
                struct sockaddr_storage *sa = getIPfromInterface(test, family, token);
                if (sa == NULL)
                    return -1;
                test->bind_address  = ip_to_str(sa);
            } else
                // this is an address, just store it
                test->bind_address = strdup(token);
        }
        // next subflows
        else {
            sf = (struct iperf_subflow *) malloc(sizeof(struct iperf_subflow));
            sf->local_addr = malloc(sizeof(struct sockaddr_storage));
            if (isHostInterface(token)) {
                // this is an interface, get its IP address first
                sf->ifacename  = token;
                sf->local_addr = getIPfromInterface(test, family, token);
                if (test->debug)    printf("sf address: %s\n", ip_to_str(sf->local_addr));
            }
            // if this is an address, just store it
            else {
                sf->local_addr = str_to_ip(token);
            }
            // insert element 'sf' into head (test->subflows) of list
            SLIST_INSERT_HEAD(&test->subflows, sf, subflows);
        }
        test->num_subflows++;
    }

    free(requested_subflows);

    /* if there is the subflow argument (-m) is empty, set sf count as 1 */
    if (test->num_subflows == 0)
        test->num_subflows = 1;

    if (test->num_subflows > MAX_SUBFLOWS) {
        i_errno = IENUMSUBFLOWS;
        return -1;
    }
    return 0;
}

/* iperf_connect -- client to server connection function */
int
iperf_connect(struct iperf_test *test)
{
    FD_ZERO(&test->read_set);
    FD_ZERO(&test->write_set);

    make_cookie(test->cookie);

    /* Create and connect the control channel */
    if (test->ctrl_sck < 0)
    {
        if (test->debug)
            printf("connect to server:\t domain: %d, bind_address: %s, server: %s, server port: %d \n",
                test->settings->domain, test->bind_address, test->server_hostname, test->server_port);

        if (test->mptcp_enabled) {
            /* parse requested subflows, set family based on server_res (-c) */
            if (get_local_ips_for_subflows(test, get_server_family(test)) < 0)
                return -1;
        }
        // Create the control channel using an ephemeral port
        test->ctrl_sck = netdial(test->settings->domain, Ptcp, test->bind_address, 0, test->server_hostname, test->server_port, test->mptcp_scheduler);
    }
    if (test->ctrl_sck < 0) {
        i_errno = IECONNECT;
        return -1;
    }

    if (Nwrite(test->ctrl_sck, test->cookie, COOKIE_SIZE, Ptcp) < 0) {
        i_errno = IESENDCOOKIE;
        return -1;
    }

    FD_SET(test->ctrl_sck, &test->read_set);
    if (test->ctrl_sck > test->max_fd) test->max_fd = test->ctrl_sck;

    return 0;
}


int
iperf_client_end(struct iperf_test *test)
{
    struct iperf_stream *sp;

    /* Close all stream sockets */
    SLIST_FOREACH(sp, &test->streams, streams) {
        close(sp->socket);
    }

    /* show final summary */
    test->reporter_callback(test);

    if (iperf_set_send_state(test, IPERF_DONE) != 0)
        return -1;

    return 0;
}


int
iperf_run_client(struct iperf_test * test)
{
    int startup;
    int result = 0;
    int receives = 0;
    fd_set read_set, write_set;
    struct timeval now;
    struct timeval* timeout = NULL;
    struct iperf_stream *sp;

    if (test->affinity != -1)
	if (iperf_setaffinity(test, test->affinity) != 0)
	    return -1;

    // if (test->json_output)
	if (iperf_json_start(test) < 0)
	    return -1;

    // if (test->json_output) {
	cJSON_AddItemToObject(test->json_start, "version", cJSON_CreateString(version));
	cJSON_AddItemToObject(test->json_start, "system_info", cJSON_CreateString(get_system_info()));
    // } else
    if (test->verbose) {
	iprintf(test, "%s\n", version);
	iprintf(test, "%s", "");
	iprintf(test, "%s\n", get_system_info());
	iflush(test);
    }

    /* Start the client and connect to the server */
    if (iperf_connect(test) < 0)
        return -1;

    /* Begin calculating CPU utilization */
    cpu_util(NULL);

    /* Seeding from time */
    srand(time(NULL));

    startup = 1;

    while (test->state != IPERF_DONE) {
	memcpy(&read_set, &test->read_set, sizeof(fd_set));
	memcpy(&write_set, &test->write_set, sizeof(fd_set));


        SLIST_FOREACH(sp, &test->streams, streams)
        {
	    FD_SET(sp->socket, &read_set);

	    /* only monitor write buffer of socket if we want to send data */
	    if ((test->on_burst) && (test->user_interact))
	        FD_SET(sp->socket, &write_set);
	    else
	        FD_CLR(sp->socket, &write_set);
        }

        /* timeout = how long to the next timed event */
	(void) gettimeofday(&now, NULL);
	timeout = tmr_timeout(&now);

	result = select(test->max_fd + 1, &read_set, &write_set, NULL, timeout);
	if (result < 0 && errno != EINTR) {
  	    i_errno = IESELECT;
	    return -1;
	}
	if (result > 0) {
	    if (FD_ISSET(test->ctrl_sck, &read_set)) {
		if (iperf_handle_message_client(test) < 0) {
		    return -1;
		}
		FD_CLR(test->ctrl_sck, &read_set);
	    }
	}

	if (test->state == TEST_RUNNING) {
            // printf("Test is in running state \n");

	    /* Is this our first time really running? */
	    if (startup) {
	        startup = 0;

		// Set non-blocking for non-UDP tests
		if (test->protocol->id != Pudp) {
		    SLIST_FOREACH(sp, &test->streams, streams) {
			setnonblocking(sp->socket, 1);
		    }
		}
	    }

            // struct interaction *interact;
            SLIST_FOREACH(sp, &test->streams, streams)
            {
                if (FD_ISSET(sp->socket, &read_set)) {
                    receives = client_recv(sp);
                    if(receives < 0)
                        perror("client_recv");
                    else if(receives > 700) {
                    //     interact = (struct interaction *) malloc(sizeof(struct interaction));
                    //     interact->response_time  = now;
                        (void) gettimeofday(&now, NULL);
                        printf("%lu.%lu: server reply %d bytes, on subflow: %d\n",
                                now.tv_sec % 10, now.tv_usec, receives, sp->id);
                        printf("======================== \n");
                        printf("Request-response delay: %f\n", timeval_diff(&test->last_request_time, &now));
                    }
                    else if (receives > 0) {
                        // this RTT calculation is wrong
                        // (void) gettimeofday(&now, NULL);
                        // printf("RTT: %f\n", timeval_diff(&test->last_request_time, &now));
                    }

                };

            };

            if ((test->on_burst) && (test->user_interact)) {

                if (test->verbose)
                    printf("burst_count = %d \n", test->burst_count);


                if (test->reverse) {
                    // Reverse mode. Client receives.
                    if (iperf_recv(test, &read_set) < 0)
                        return -1;
                } else {
                    // Regular mode. Client sends.
                    if (iperf_send(test, &write_set) < 0)
                        return -1;
                }
            }

            /* Run the timers. */
            (void) gettimeofday(&now, NULL);
            tmr_run(&now);

	    /* Is the test done yet? */
	    if ((!test->omitting) &&
	        ((test->duration != 0 && test->done) ||
	         (test->settings->bytes != 0 && test->bytes_sent >= test->settings->bytes) ||
	         (test->settings->blocks != 0 && test->blocks_sent >= test->settings->blocks))) {

		// Unset non-blocking for non-UDP tests
		if (test->protocol->id != Pudp) {
		    SLIST_FOREACH(sp, &test->streams, streams) {
			setnonblocking(sp->socket, 0);
		    }
		}

		/* Yes, done!  Send TEST_END. */
		test->done = 1;
		cpu_util(test->cpu_util);
		test->stats_callback(test);
		if (iperf_set_send_state(test, TEST_END) != 0)
		    return -1;
	    }
	}
	// If we're in reverse mode, continue draining the data
	// connection(s) even if test is over.  This prevents a
	// deadlock where the server side fills up its pipe(s)
	// and gets blocked, so it can't receive state changes
	// from the client side.
	else if (test->reverse && test->state == TEST_END) {
	    if (iperf_recv(test, &read_set) < 0)
		return -1;
	}
    }

    if ((test->json_output) ||
        (test->remote_iperf_supports_mptcp)) {
	if (iperf_json_finish(test) < 0)
	    return -1;
    } else {
	iprintf(test, "\n");
	iprintf(test, "%s", report_done);
    }

    iflush(test);

    return 0;
}
