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

#define CAPTURE_TIMEOUT 1000
#define MAX_THREADS 250
#define DEFAULT_TIMEOUT 2

//define scan types
typedef enum {
    SCAN_SYN = 1,
    SCAN_NULL = 2,
    SCAN_ACK = 4,
    SCAN_FIN = 8,
    SCAN_XMAS = 16,
    SCAN_UDP = 32
} scan_type_t;

//define configuration structure
typedef struct {
    char target_ip[16];
    int start_port;
    int end_port;
    int thread_count;
    unsigned int scan_types;
    double timeout;
    pthread_mutex_t mutex;
} t_config;

//define scanner context
typedef struct {
    pcap_t *handle;
    int raw_socket;
    pthread_mutex_t *mutex;
    t_config *config;
} t_context;

int initialize_scanner(t_context *ctx);

#endif