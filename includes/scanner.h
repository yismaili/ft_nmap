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
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <errno.h> 

#define SYN_SCAN  0
#define FIN_SCAN  1
#define NULL_SCAN 2
#define XMAS_SCAN 3
#define ACK_SCAN  4

typedef struct {
    char service_name[1024];
    int port;
    bool is_open;
    int scan_type;
} t_result;

typedef struct {
    char local_ip[INET6_ADDRSTRLEN];
    struct in_addr dest_ip;
    int total_open_host;
    struct timespec start_time, finish_time;
    int raw_socket;
    pcap_t *handle;
    t_scan_config *config;
    t_result *results;
    pthread_mutex_t *mutex;
} t_context;

typedef struct {
    t_context *ctx;
    int start_port_index;
    int end_port_index;
    int thread_id;
} t_thread_data;

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int start_packet_sniffer(t_context *ctx);
void* capture_syn_ack_response(void* ptr);
void retrieve_local_ip_address(t_context *ctx);
int init_row_socket(t_context *ctx);
void execute_network_scan(t_context *ctx, const char* target, int scan_type);
void get_source_network_interface(t_context *ctx, int scan_type, struct in_addr* target_in_addr);
void craft_tcp_packet(t_context *ctx,char* datagram, const char* source_ip, struct iphdr* iph, struct tcphdr* tcph, int scan_type);
void resolve_ip_to_hostname(const char* ip, char* buffer);
unsigned short calculate_ip_tcp_checksum(unsigned short* ptr, int nbytes);
void scan_port(t_context *ctx, char *ip_addr);
void cleanup_scanner(t_context *ctx);
const char* format_ipv4_address_to_string(const struct in_addr* addr);
void execute_network_scan_2(t_context *ctx, const char* target, int scan_type);
#endif
