#ifndef SCANNER_H
#define SCANNER_H
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pcap/pcap.h>

#define CAPTURE_TIMEOUT 1000

typedef struct {
    pcap_t *handle;
    int raw_socket;
    pthread_mutex_t *mutex;
} t_context;

int initialize_scanner(t_context *ctx);

#endif