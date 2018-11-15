/*
 * simple dns proxy test client
 * Author: leegoogol
 * Email: buckrudy@gmail.com
 */
#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/nameser.h>

static pthread_cond_t cond= PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


int set_signal_handler(int sig, void (*sig_handle)(int sig));
void sig_alrm(int sig);

ares_channel channel;

/*
 * typedef void (*ares_callback)(void *arg, int status,
 *                int timeouts, unsigned char *abuf, int alen)
 *                               */
void query_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{
	if (status != ARES_SUCCESS) {
		printf("query error !!!!!!!!!!!!!!!!!!!\n");
	} else {
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
    }
}

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

static void callback(void *arg, int status, int timeouts, struct hostent *host)
{
    if(!host || status != ARES_SUCCESS){
        printf("Failed to lookup %s\n", ares_strerror(status));
        return;
    }
    printf("Found address name %s\n", host->h_name);
    char ip[INET6_ADDRSTRLEN];
    int i = 0;
    for (i = 0; host->h_addr_list[i]; ++i) {
        inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
        printf("%s\n", ip);
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

int main(int argc, char **argv)
{
    int status;
    struct ares_options options;
    int optmask = 0;

    if (argc != 2) {
        printf("Usage: %s <dns server ip>\n", argv[0]);
        return 1;
    }

    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("ares_library_init: %s\n", ares_strerror(status));
        return 1;
    }
    //options.sock_state_cb_data;
    options.sock_state_cb = state_cb;
    optmask |= ARES_OPT_SOCK_STATE_CB;
    status = ares_init_options(&channel, &options, optmask);
    if(status != ARES_SUCCESS) {
        printf("ares_init_options: %s\n", ares_strerror(status));
        return 1;
    }
    {
        char ip_str[32];
        struct ares_addr_node *serv = NULL;
        if (0 != set_dns_server(channel, argv[1])) {
			printf("set_dns_server error\n");
			exit(1);
		}
        ares_get_servers(channel, &serv);
        if (serv) {
            printf("serv ip: %s\n", ares_inet_ntop(serv->family, &serv->addr.addr4, ip_str, sizeof(ip_str)));
            ares_free_data(serv);
        }
    }
    ares_gethostbyname(channel, "www.baidu.com", AF_INET, callback, NULL);
    ares_gethostbyname(channel, "www.163.com", AF_INET, callback, NULL);
    ares_query(channel, "www.sina.cn", ns_c_in, ns_t_a, query_callback, NULL);
    ares_query(channel, "www.baidu.com", ns_c_in, ns_t_cname, query_callback, NULL);
    set_signal_handler(SIGALRM, sig_alrm);
    alarm(10);
    wait_ares(channel);
    printf("c-ares version: %s\n", ares_version(NULL));
    ares_destroy(channel);
    ares_library_cleanup();
    printf("fin\n");
    return 0;
}

int set_signal_handler(int sig, void (*sig_handle)(int sig))
{
    struct sigaction act = {0};
    act.sa_handler = sig_handle;
    act.sa_flags |= SA_RESTART;
    return sigaction(sig, &act, NULL);
}

static char *domains[] = {
    "www.zhihu.com",
    "www.iqiyi.com",
};
static int i = 0;

void sig_alrm(int sig)
{
    ares_gethostbyname(channel, domains[i++], AF_INET, callback, NULL);
    if (i<sizeof(domains)/sizeof(domains[0]))
        alarm(10);
}
