#ifndef SCANNER_H
#define SCANNER_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <string.h>  
#include <stdlib.h>   
#include <pthread.h>
#include <unistd.h>
#include <pcap.h>
#include <ifaddrs.h>
#include "../includes/ft_nmap.h"

#define CAPTURE_TIMEOUT 1000
#define MAX_THREADS 250
#define DEFAULT_TIMEOUT 2

typedef struct {
    char service_name[1024];
    int port;
    bool is_open;
    int scan_type;
} tport_result;

typedef struct {
    pcap_t *handle;
    int raw_socket;
    t_scan_config *config;
    tport_result *results;
    pthread_mutex_t *mutex;
} t_context;

typedef struct {
    t_context *ctx;
    int start_port_index;
    int end_port_index;
    int thread_id;
} t_thread_data;

int initialize_scanner(t_context *ctx);
void *scan_thread(void *arg);
void perform_scan(t_context *ctx);
void cleanup_scanner(t_context *ctx);
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr __attribute__((unused)), const u_char *packet);
void scan_port( t_context *ctx);
char *detect_service_version(const char *target, int port, int config_timeout);
const char *detect_os(const char *target, int timeout);

#endif
