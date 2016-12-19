/*
 * iperf, Copyright (c) 2014, 2016, The Regents of the University of
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
#include "iperf_config.h"

/* use Linux UAPI */
#include <linux/tcp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_tcp.h"
#include "net.h"

#if defined(HAVE_FLOWLABEL)
#include "flowlabel.h"
#endif /* HAVE_FLOWLABEL */

/* iperf_tcp_recv
 *
 * receives the data for TCP
 */
int
iperf_tcp_recv(struct iperf_stream *sp)
{
    int r;

    r = Nread(sp->socket, sp->buffer, sp->settings->blksize, Ptcp);

    if (r < 0)
        return r;

    sp->result->bytes_received += r;
    sp->result->bytes_received_this_interval += r;

    return r;
}


/* iperf_tcp_send 
 *
 * sends the data for TCP
 */
int
iperf_tcp_send(struct iperf_stream *sp)
{
    int r;

    if (sp->test->zerocopy)
	r = Nsendfile(sp->buffer_fd, sp->socket, sp->buffer, sp->settings->blksize);
    else
	r = Nwrite(sp->socket, sp->buffer, sp->settings->blksize, Ptcp);

    if (r < 0)
        return r;

    sp->result->bytes_sent += r;
    sp->result->bytes_sent_this_interval += r;

    return r;
}


/* iperf_tcp_accept
 *
 * accept a new TCP stream connection
 */
int
iperf_tcp_accept(struct iperf_test * test)
{
    int     s;
    signed char rbuf = ACCESS_DENIED;
    char    cookie[COOKIE_SIZE];
    socklen_t len;
    struct sockaddr_storage addr;

    len = sizeof(addr);
    if ((s = accept(test->listener, (struct sockaddr *) &addr, &len)) < 0) {
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if (Nread(s, cookie, COOKIE_SIZE, Ptcp) < 0) {
        i_errno = IERECVCOOKIE;
        return -1;
    }

    if (strcmp(test->cookie, cookie) != 0) {
        if (Nwrite(s, (char*) &rbuf, sizeof(rbuf), Ptcp) < 0) {
            i_errno = IESENDMESSAGE;
            return -1;
        }
        close(s);
    }

    return s;
}


/* iperf_tcp_listen
 *
 * start up a listener for TCP stream connections
 */
int
iperf_tcp_listen(struct iperf_test *test)
{
    struct addrinfo hints, *res;
    char portstr[6];
    int s, opt;
    int saved_errno;

    s = test->listener;

    /*
     * If certain parameters are specified (such as socket buffer
     * size), then throw away the listening socket (the one for which
     * we just accepted the control connection) and recreate it with
     * those parameters.  That way, when new data connections are
     * set, they'll have all the correct parameters in place.
     *
     * It's not clear whether this is a requirement or a convenience.
     */
    if (test->no_delay || test->settings->mss || test->settings->socket_bufsize) {
        FD_CLR(s, &test->read_set);
        close(s);

        snprintf(portstr, 6, "%d", test->server_port);
        memset(&hints, 0, sizeof(hints));

	/*
	 * If binding to the wildcard address with no explicit address
	 * family specified, then force us to get an AF_INET6 socket.
	 * More details in the comments in netanounce().
	 */
	if (test->settings->domain == AF_UNSPEC && !test->bind_address) {
	    hints.ai_family = AF_INET6;
	}
	else {
	    hints.ai_family = test->settings->domain;
	}
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        if (getaddrinfo(test->bind_address, portstr, &hints, &res) != 0) {
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        if ((s = socket(res->ai_family, SOCK_STREAM, 0)) < 0) {
	    freeaddrinfo(res);
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        if (test->no_delay) {
            opt = 1;
            if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETNODELAY;
                return -1;
            }
        }
        // XXX: Setting MSS is very buggy!
        if ((opt = test->settings->mss)) {
            if (setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETMSS;
                return -1;
            }
        }
        if ((opt = test->settings->socket_bufsize)) {
            if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETBUF;
                return -1;
            }
            if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
                i_errno = IESETBUF;
                return -1;
            }
        }
	if (test->debug) {
	    socklen_t optlen = sizeof(opt);
	    if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, &optlen) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
		i_errno = IESETBUF;
		return -1;
	    }
	    printf("SO_SNDBUF is %u\n", opt);
	}
#if defined(HAVE_TCP_CONGESTION)
	if (test->congestion) {
	    if (setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, test->congestion, strlen(test->congestion)) < 0) {
		close(s);
		freeaddrinfo(res);
		i_errno = IESETCONGESTION;
		return -1;
	    } 
	}
#endif /* HAVE_TCP_CONGESTION */
#if defined(HAVE_SO_MAX_PACING_RATE)
    /* If socket pacing is available and not disabled, try it. */
    if (! test->no_fq_socket_pacing) {
	/* Convert bits per second to bytes per second */
	unsigned int rate = test->settings->rate / 8;
	if (rate > 0) {
	    if (test->debug) {
		printf("Setting fair-queue socket pacing to %u\n", rate);
	    }
	    if (setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &rate, sizeof(rate)) < 0) {
		warning("Unable to set socket pacing, using application pacing instead");
		test->no_fq_socket_pacing = 1;
	    }
	}
    }
#endif /* HAVE_SO_MAX_PACING_RATE */
        opt = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
            close(s);
	    freeaddrinfo(res);
	    errno = saved_errno;
            i_errno = IEREUSEADDR;
            return -1;
        }

	/*
	 * If we got an IPv6 socket, figure out if it shoudl accept IPv4
	 * connections as well.  See documentation in netannounce() for
	 * more details.
	 */
#if defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
	if (res->ai_family == AF_INET6 && (test->settings->domain == AF_UNSPEC || test->settings->domain == AF_INET)) {
	    if (test->settings->domain == AF_UNSPEC)
		opt = 0;
	    else 
		opt = 1;
	    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, 
			   (char *) &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
		close(s);
		freeaddrinfo(res);
		errno = saved_errno;
		i_errno = IEV6ONLY;
		return -1;
	    }
	}
#endif /* IPV6_V6ONLY */

        if (bind(s, (struct sockaddr *) res->ai_addr, res->ai_addrlen) < 0) {
	    saved_errno = errno;
            close(s);
	    freeaddrinfo(res);
	    errno = saved_errno;
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        freeaddrinfo(res);

        if (listen(s, 5) < 0) {
            i_errno = IESTREAMLISTEN;
            return -1;
        }

        test->listener = s;
    }

    return s;
}

#include <ifaddrs.h>
#include <stdbool.h>

bool isHostInterface(char *iface){
    struct ifaddrs  *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1)    {
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

// mptcp create subflow :)

void create_subflow(struct iperf_test *test, int s, struct iperf_subflow *sf, struct sockaddr_storage * server_addr)
{
    unsigned int optlen;
    struct mptcp_sub_tuple *sub_tuple;
    char str[INET6_ADDRSTRLEN];

    unsigned short family = sf->local_addr->ss_family;

    if (family == AF_INET) {
        optlen = sizeof(struct mptcp_sub_tuple) +
                2 * sizeof(struct sockaddr_in);
        sub_tuple = malloc(optlen);
        struct sockaddr_in  *addr;
        // source
        addr = (struct sockaddr_in*) &sub_tuple->addrs[0];

        addr->sin_family = family;
        addr->sin_addr = ((struct sockaddr_in *) sf->local_addr)->sin_addr;
        addr->sin_port = 0;
        //addr->sin_port = htons(test->bind_port + 10001);

        if (test->debug){
            inet_ntop(family, &(addr->sin_addr), str, INET_ADDRSTRLEN);
            printf("\nnew subflow on local IP: %s\n", str);
        }
        // destination
        addr++;
        addr->sin_family = family;
        addr->sin_port = htons(PORT);
        addr->sin_addr = ((struct sockaddr_in*) server_addr)->sin_addr;
    }
    else if (family == AF_INET6) {
        optlen = sizeof(struct mptcp_sub_tuple) +
                2 * sizeof(struct sockaddr_in6);
        sub_tuple = malloc(optlen);
        struct sockaddr_in6  *addr;
        // source
        addr = (struct sockaddr_in6 *) &sub_tuple->addrs[0];

        addr->sin6_family = family;
        addr->sin6_addr = ((struct sockaddr_in6*) sf->local_addr)->sin6_addr;
        addr->sin6_port = 0;

        if (test->debug){
            inet_ntop(family, &(addr->sin6_addr), str, INET6_ADDRSTRLEN);
            printf("\nnew subflow on local IPv6: %s\n", str);
        }
        // destination
        addr++;
        addr->sin6_family = family;
        addr->sin6_port = htons(PORT);
        addr->sin6_addr = ((struct sockaddr_in6*) server_addr)->sin6_addr;
    }
    else {
        printf("Create subflow: Don't know this address family: %d %hu\n", family,sf->local_addr->ss_family);
        return;
    }

    // open new subflow here
    getsockopt(s, IPPROTO_TCP, MPTCP_OPEN_SUB_TUPLE, sub_tuple, &optlen);
    perror("create subflow");
}

void insert_subflow(struct iperf_test *test, int s, uint8_t id)
{
    struct iperf_subflow *sf;
    /* check if the subflow already existed in the list */
    SLIST_FOREACH(sf, &test->subflows, subflows) {
        if(sf->id == id)    return;
    }
    sf = malloc(sizeof(struct iperf_subflow));
    sf->id = id;
    sf->socket = s;

    sf->result = calloc(1, sizeof(struct iperf_stream_result));
    sf->result->start_time     = test->start_time;
    sf->result->bytes_received = sf->result->bytes_sent = 0;
    TAILQ_INIT(&sf->result->interval_results);

    SLIST_INSERT_HEAD(&test->subflows, sf, subflows);
}

void get_subflow_tuple(struct iperf_test *test, int s, uint8_t  id)
{
    unsigned int optlen;
    struct mptcp_sub_tuple *sub_tuple;
    struct sockaddr *sin;

    optlen = 100;
    sub_tuple = malloc(optlen);

    sub_tuple->id = id;

    getsockopt(s, IPPROTO_TCP, MPTCP_GET_SUB_TUPLE, sub_tuple, &optlen);
    perror("get subflows");
    sin = (struct sockaddr*) &sub_tuple->addrs[0];

    char str[INET6_ADDRSTRLEN];
    if(sin->sa_family == AF_INET) {
        struct sockaddr_in *sin4;
        sin4 = (struct sockaddr_in*) &sub_tuple->addrs[0];
        inet_ntop(sin4->sin_family, &(sin4->sin_addr), str, INET_ADDRSTRLEN);
        printf("\t ip src: %s src port: %hu\n", str, ntohs(sin4->sin_port));
        sin4++;
        inet_ntop(sin4->sin_family, &(sin4->sin_addr), str, INET_ADDRSTRLEN);
        printf("\t ip dst: %s dst port: %hu\n", str, ntohs(sin4->sin_port));
    }
    if(sin->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6;
        sin6 = (struct sockaddr_in6*) &sub_tuple->addrs[0];
        inet_ntop(sin6->sin6_family, &(sin6->sin6_addr), str, INET6_ADDRSTRLEN);
        printf("\t ip src: %s src port: %hu\n", str, ntohs(sin6->sin6_port));
        sin6++;
        inet_ntop(sin6->sin6_family, &(sin6->sin6_addr), str, INET6_ADDRSTRLEN);
        printf("\t ip dst: %s dst port: %hu\n", str, ntohs(sin6->sin6_port));
    }
}

void remove_sf_list(struct iperf_test *test)
{
    struct iperf_subflow * datap;

    while (!SLIST_EMPTY( &test->subflows )) {
        datap = SLIST_FIRST(&test->subflows);
        SLIST_REMOVE_HEAD(&test->subflows, subflows);
        free(datap);
    }
}

int get_subflow_ids(struct iperf_test *test, int get_tuple, int s)
{
    unsigned int optlen;
    // what is the correct length?
    optlen = 42;
    struct mptcp_sub_ids *ids;
    ids = malloc(optlen);

    int e = getsockopt(s, IPPROTO_TCP, MPTCP_GET_SUB_IDS, ids, &optlen);
    if (e < 0) {
        if (test->debug)    perror("get subflow ids");
        /* this means MPTCP does not work */
        test->mptcp_enabled = 0;
        return 0;
    }
    int i;
    if (test->debug)        printf(" Num of subflows: %d \n", ids->sub_count);
    for(i = 0; i < ids->sub_count; i++){
        if (test->debug) {
            printf("  Subflow id: %i\t",  ids->sub_status[i].id);
          //printf("  is attached: %i\n", ids->sub_status[i].attached);
          //printf("  pre-established: %i\n", ids->sub_status[i].pre_established);
            printf("  fully established: %i\n", ids->sub_status[i].fully_established);
        }
        if (get_tuple)
            get_subflow_tuple(test, s, ids->sub_status[i].id);
        if (ids->sub_status[i].fully_established){
            insert_subflow(test, s, ids->sub_status[i].id);
            test->mptcp_enabled = 1;
        }
    }
    return ids->sub_count;
}


/* parse subflow list and get their ips which match server IP family */
int get_local_ips_for_subflows(struct iperf_test *test, int family)
{
    char *token;
    struct iperf_subflow *sf;

    while ((token = strsep(&test->requested_subflows, ",")))
    {
        if (test->debug)
            printf("%s \n",token);
        // this is initial subflow.
        if (test->num_subflows == 0) {
            if (isHostInterface(token)) {
                // look up for IP address
                test->bind_address = malloc(INET6_ADDRSTRLEN);
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

    if (test->num_subflows > MAX_SUBFLOWS) {
        i_errno = IENUMSUBFLOWS;
        return -1;
    }
    return 0;
}

/* iperf_tcp_connect
 *
 * connect to a TCP stream listener
 */
int
iperf_tcp_connect(struct iperf_test *test)
{
    struct addrinfo hints, *local_res, *server_res;
    char portstr[6];
    int s, opt;
    int saved_errno;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = test->settings->domain;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", test->server_port);
    if (getaddrinfo(test->server_hostname, portstr, &hints, &server_res) != 0) {
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    /* we set requested family based on server_res (-c) */
    if (test->mptcp_enabled) {
        if (get_local_ips_for_subflows(test, server_res->ai_family) < 0)
            return -1;
    }

    /* if mptcp is enabled, this is the local IP that initial subflow uses*/
    if (test->bind_address) {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = server_res->ai_family;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(test->bind_address, NULL, &hints, &local_res) != 0) {
            freeaddrinfo(server_res);
            i_errno = IESTREAMCONNECT;
            return -1;
        }
    }

    if ((s = socket(server_res->ai_family, SOCK_STREAM, 0)) < 0) {
	if (test->bind_address)
	    freeaddrinfo(local_res);
	freeaddrinfo(server_res);
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if (test->bind_address) {
        struct sockaddr_in *lcladdr;
        lcladdr = (struct sockaddr_in *)local_res->ai_addr;
        lcladdr->sin_port = htons(test->bind_port);
        local_res->ai_addr = (struct sockaddr *)lcladdr;

        if (bind(s, (struct sockaddr *) local_res->ai_addr, local_res->ai_addrlen) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(local_res);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESTREAMCONNECT;
            return -1;
        }
        freeaddrinfo(local_res);
    }

    /* Set socket options */
    if (test->no_delay) {
        opt = 1;
        if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETNODELAY;
            return -1;
        }
    }
    if ((opt = test->settings->mss)) {
        if (setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETMSS;
            return -1;
        }
    }
    if ((opt = test->settings->socket_bufsize)) {
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
    }
    if (test->debug) {
	socklen_t optlen = sizeof(opt);
	if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, &optlen) < 0) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
	    i_errno = IESETBUF;
	    return -1;
	}
	printf("SO_SNDBUF is %u\n", opt);
    }
#if defined(HAVE_FLOWLABEL)
    if (test->settings->flowlabel) {
        if (server_res->ai_addr->sa_family != AF_INET6) {
	    saved_errno = errno;
	    close(s);
	    freeaddrinfo(server_res);
	    errno = saved_errno;
            i_errno = IESETFLOW;
            return -1;
	} else {
	    struct sockaddr_in6* sa6P = (struct sockaddr_in6*) server_res->ai_addr;
            char freq_buf[sizeof(struct in6_flowlabel_req)];
            struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)freq_buf;
            int freq_len = sizeof(*freq);

            memset(freq, 0, sizeof(*freq));
            freq->flr_label = htonl(test->settings->flowlabel & IPV6_FLOWINFO_FLOWLABEL);
            freq->flr_action = IPV6_FL_A_GET;
            freq->flr_flags = IPV6_FL_F_CREATE;
            freq->flr_share = IPV6_FL_F_CREATE | IPV6_FL_S_EXCL;
            memcpy(&freq->flr_dst, &sa6P->sin6_addr, 16);

            if (setsockopt(s, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, freq_len) < 0) {
		saved_errno = errno;
                close(s);
                freeaddrinfo(server_res);
		errno = saved_errno;
                i_errno = IESETFLOW;
                return -1;
            }
            sa6P->sin6_flowinfo = freq->flr_label;

            opt = 1;
            if (setsockopt(s, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &opt, sizeof(opt)) < 0) {
		saved_errno = errno;
                close(s);
                freeaddrinfo(server_res);
		errno = saved_errno;
                i_errno = IESETFLOW;
                return -1;
            } 
	}
    }
#endif /* HAVE_FLOWLABEL */

#if defined(HAVE_TCP_CONGESTION)
    if (test->congestion) {
	if (setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, test->congestion, strlen(test->congestion)) < 0) {
	    close(s);
	    freeaddrinfo(server_res);
	    i_errno = IESETCONGESTION;
	    return -1;
	}
    }
#endif /* HAVE_TCP_CONGESTION */

#if defined(HAVE_SO_MAX_PACING_RATE)
    /* If socket pacing is available and not disabled, try it. */
    if (! test->no_fq_socket_pacing) {
	/* Convert bits per second to bytes per second */
	unsigned int rate = test->settings->rate / 8;
	if (rate > 0) {
	    if (test->debug) {
		printf("Socket pacing set to %u\n", rate);
	    }
	    if (setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &rate, sizeof(rate)) < 0) {
		warning("Unable to set socket pacing, using application pacing instead");
		test->no_fq_socket_pacing = 1;
	    }
	}
    }
#endif /* HAVE_SO_MAX_PACING_RATE */

    if (connect(s, (struct sockaddr *) server_res->ai_addr, server_res->ai_addrlen) < 0 && errno != EINPROGRESS) {
	saved_errno = errno;
	close(s);
	freeaddrinfo(server_res);
	errno = saved_errno;
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    printf("number of subflows: %d\n", test->num_subflows);
    struct iperf_subflow *sf;
    struct iperf_ip_addrs *server_ip;

    /* create subflows as requested by the slist,
    test->subflows is the head of list */

    SLIST_FOREACH( sf, &test->subflows, subflows) {
        int created = 0;
        int family = ((struct sockaddr*) sf->local_addr)->sa_family;
        if (!SLIST_EMPTY(&test->remote_ip_addrs)) {
            SLIST_FOREACH(server_ip, &test->remote_ip_addrs, ip_addrs)
               if (family == server_ip->family) {
                   create_subflow(test, s, sf, str_to_ip(server_ip->ip));
                   created = 1;
                   break;
               }
            if (!created)
                printf("not found any server IP in the same family\n");
        }
        else if (family == server_res->ai_family) {
            create_subflow(test, s, sf, (struct sockaddr_storage*) server_res->ai_addr);
        }
        else
            printf("local IP does not in the same family with server IP\n");
    }

    remove_sf_list(test);
    get_subflow_ids(test, 1, s);

    freeaddrinfo(server_res);

    /* Send cookie for verification */
    if (Nwrite(s, test->cookie, COOKIE_SIZE, Ptcp) < 0) {
	saved_errno = errno;
	close(s);
	errno = saved_errno;
        i_errno = IESENDCOOKIE;
        return -1;
    }

    return s;
}
