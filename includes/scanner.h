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
#include "../includes/ft_nmap.h"

#define CAPTURE_TIMEOUT 1000
#define MAX_THREADS 250
#define DEFAULT_TIMEOUT 2

//define scanner context
typedef struct {
    pcap_t *handle;
    int raw_socket;
    t_scan_config *config;
} t_context;

typedef struct {
    int port;
    enum {
        PORT_UNKNOWN,
        PORT_OPEN,
        PORT_CLOSED,
        PORT_FILTERED,
        PORT_UNFILTERED,
        PORT_OPEN_FILTERED
    } status;
} t_scan_result;

int initialize_scanner(t_context *ctx);
void scan_port(t_context *g_context);

#endif
