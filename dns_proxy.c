/*
 * A simple DNS proxy
 *
 * Author: leegoogol
 * Email: buckgugle@gmail.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libev/ev.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <ares.h>
#include <netdb.h>
#include "list.h"

struct receive_query {
	struct list_head node;
	struct sockaddr saddr;
	int addr_len;
	time_t query_time;
	unsigned char data[1500];
	int data_len;
};

struct forward_query {
	struct list_head node;
	struct sockaddr saddr;
	int addr_len;
	time_t query_time;
	unsigned short tx_id;
	unsigned short ns_type;
	unsigned short ns_class;
	char *domain_name;
};

static struct list_head receive_query_list_head;
pthread_mutex_t receive_query_list_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t receive_query_list_cond = PTHREAD_COND_INITIALIZER;

static ares_channel channel;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);


static int g_listen_sock;

void print_hex(const unsigned char *data, int data_len)
{
	int i;
	for (i=0; i<data_len; i++) {
		if (i % 16 == 0) {
			printf("\n");
		}
		printf("%02x ", data[i]);
	}
	printf("\n");
}

void *forward_query_thread(void *arg)
{
	struct receive_query *e, *t;
	struct forward_query *fwd;
	long domain_name_len;

	pthread_detach(pthread_self());

	while (1) {
		pthread_mutex_lock(&receive_query_list_lock);
		
		if (list_empty(&receive_query_list_head)) {
			pthread_cond_wait(&receive_query_list_cond, &receive_query_list_lock);
		}

		list_for_each_entry_safe(e, t, &receive_query_list_head, node) {
			fwd = calloc(1, sizeof(struct forward_query));
			if (!fwd) {
				printf("Out Off Memory, Exit\n\n");
				exit(1);
			}
			if (ARES_SUCCESS == ares_expand_name(e->data + 12, e->data, e->data_len, &fwd->domain_name, &domain_name_len)) {
				fwd->tx_id = ntohs(*(unsigned short *)(e->data));
				fwd->ns_type = ntohs(*(unsigned short *)(e->data+12+domain_name_len));
				fwd->ns_class = ntohs(*(unsigned short *)(e->data+12+domain_name_len+2));
				printf("domain_name: %s, domain_name_len: %d, tx_id: %u, ns_type: %u, ns_class: %u\n", 
						fwd->domain_name, domain_name_len, fwd->tx_id, fwd->ns_type, fwd->ns_class);
				//ares_free_string(fwd->domain_name);
				fwd->addr_len = e->addr_len;
				memcpy(&fwd->saddr, &e->saddr, e->addr_len);
				ares_query(channel, fwd->domain_name, fwd->ns_class, fwd->ns_type, query_callback, fwd);
			} else {
				free(fwd);
			}
			list_del(&e->node);
			free(e);
		}
		pthread_mutex_unlock(&receive_query_list_lock);
	}
}

void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{
	struct forward_query *fwd = (struct forward_query *)arg;
    if (status == ARES_SUCCESS) {
#if 1 //this section can be delete
        char *names;
        long name_len;
        struct hostent *host;
        ares_expand_name(abuf+12, abuf, alen, &names, &name_len);
        printf("query success !!!!!!!!!!!!!!!!!\n");
        printf("names: %s\n", names);
        ares_free_string(names);
        if (ARES_SUCCESS == ares_parse_a_reply(abuf, alen, &host, NULL, NULL)) {
            char ip[INET6_ADDRSTRLEN];
            int i = 0;
            printf("Official name %s\n", host->h_name);
            for (i = 0; host->h_addr_list[i]; ++i) {
                inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
                printf("%s\n", ip);
            }
            ares_free_hostent(host);
        } else {
            printf("error : %s\n", ares_strerror(status));
        }
#endif
		//replace tx_id
#if 0
		unsigned char data[1500];
		memcpy(data, abuf, alen);
		*(unsigned short *)data = htons(fwd->tx_id);
		sendto(g_listen_sock, data, alen, 0, (struct sockaddr*)&fwd->saddr, fwd->addr_len);
#else
		*(unsigned short *)abuf = htons(fwd->tx_id);
		sendto(g_listen_sock, abuf, alen, 0, (struct sockaddr*)&fwd->saddr, fwd->addr_len);
#endif

    } else {
        printf("query error : [%s]\n", ares_strerror(status));
		if (abuf) {
			printf("abuf = %p, alen = %d\n", abuf, alen);
			print_hex(abuf, alen);

			//if abuf not NULL, meaning query completed
			*(unsigned short *)abuf = htons(fwd->tx_id);
			sendto(g_listen_sock, abuf, alen, 0, (struct sockaddr*)&fwd->saddr, fwd->addr_len);
		}
    }

	if (fwd) {
		ares_free_string(fwd->domain_name);
		free(fwd);
	}
}

/*
 * @return: 1 error, 0 success
 */
int set_dns_server(ares_channel channel, const char *ip_string)
{
    struct ares_addr_node serv_nodes = {0};
    serv_nodes.next = NULL;
    serv_nodes.family = AF_INET;
    ares_inet_pton(AF_INET, ip_string, (void*)&serv_nodes.addr.addr4);
    if (ARES_SUCCESS != ares_set_servers(channel, &serv_nodes)) {
        printf("ares_set_servers error\n");
		return 1;
	}
	return 0;
}

static void state_cb(void *data, int s, int read, int write)
{
    printf("Change state fd %d read:%d write:%d\n", s, read, write);
    if (0 != read) {
        printf("wakeup .....\n");
        fflush(stdout);
        pthread_cond_signal(&cond);
    }
}

static void wait_ares(ares_channel channel)
{
    for(;;){
        struct timeval *tvp, tv;
        fd_set read_fds, write_fds;
        int nfds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if(nfds == 0){
            //break;
            //sleep(1);
            pthread_mutex_lock(&mutex);
            printf("waiting.........\n");
            fflush(stdout);
            pthread_cond_wait(&cond, &mutex);
            pthread_mutex_unlock(&mutex);
            continue;
        }
        tvp = ares_timeout(channel, NULL, &tv);
        select(nfds, &read_fds, &write_fds, NULL, tvp);
        ares_process(channel, &read_fds, &write_fds);
    }
}


void *ares_query_thread(void *arg)
{
    int status;
    struct ares_options options;
    int optmask = 0;
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("ares_library_init: %s\n", ares_strerror(status));
		exit(3);
    }   
    //options.sock_state_cb_data;
    options.sock_state_cb = state_cb;
    optmask |= ARES_OPT_SOCK_STATE_CB;
    status = ares_init_options(&channel, &options, optmask);
    if(status != ARES_SUCCESS) {
        printf("ares_init_options: %s\n", ares_strerror(status));
		exit(2);
    }   

    {   
        char ip_str[32];
        struct ares_addr_node *serv = NULL;
        //set_dns_server(channel, "114.114.114.114");
        if (0 != set_dns_server(channel, (char *)arg)) {
			printf("set_dns_server upstream [%s] error\n", (char *)arg);
			exit(1);
		}
        ares_get_servers(channel, &serv);
        if (serv) {
            printf("serv ip: %s\n", ares_inet_ntop(serv->family, &serv->addr.addr4, ip_str, sizeof(ip_str)));
            ares_free_data(serv);
        }   
	}

    wait_ares(channel);
    printf("c-ares version: %s\n", ares_version(NULL));
    ares_destroy(channel);
    ares_library_cleanup();
    printf("fin\n");
    return NULL;	
}

static void dns_listener_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	char buf[2048];
	int rc;
	struct receive_query *entry;
	int query_sock;

	entry = calloc(1, sizeof(struct receive_query));
	if (entry == NULL) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}
	entry->addr_len = sizeof(entry->saddr);

	entry->data_len = recvfrom(w->fd, entry->data, sizeof(entry->data), 0, &entry->saddr, &entry->addr_len);
	if (entry->data_len > 12) {	//DNS header 12 bytes
		entry->query_time = time(NULL);
		
		pthread_mutex_lock(&receive_query_list_lock);
		list_add_tail(&entry->node, &receive_query_list_head);
		pthread_cond_signal(&receive_query_list_cond);
		pthread_mutex_unlock(&receive_query_list_lock);

		printf("receive query success\n\n");
	} else {
		free(entry);
		printf("receive query error\n\n");
	}
}


int main(int argc, char **argv)
{
	struct sockaddr_in serv;
	int sock, reuse = 1;
	int local_port;
	char *dns_ip;
	struct ev_loop *loop = NULL;
	ev_io listen_watch;
	ev_timer timer_watch;
	pthread_t tid, ares_tid;

	if (argc != 3) {
		printf("Usage: %s <local port> <upstream dns server>\n", argv[0]);
		return 1;
	} else {
		local_port = atoi(argv[1]);
		dns_ip = argv[2];
	}

	INIT_LIST_HEAD(&receive_query_list_head);

	sock = socket(AF_INET, SOCK_DGRAM, 0);	
	if (sock < 0) {
		perror("socket()\n");
		return 2;
	}
	g_listen_sock = sock;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_port = htons(local_port);
	serv.sin_addr.s_addr = htonl(INADDR_ANY);

	bind(sock, (struct sockaddr*)&serv, sizeof(serv));

	pthread_create(&tid, NULL, forward_query_thread, NULL);
	pthread_create(&ares_tid, NULL, ares_query_thread, dns_ip);

	loop = ev_default_loop(0);
	ev_init(&listen_watch, dns_listener_cb);
	ev_io_set(&listen_watch, sock, EV_READ);
	ev_io_start(loop, &listen_watch);

	ev_run(loop, 0);
	return 0;
}
