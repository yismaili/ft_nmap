#include "../../includes/scanner.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
    struct ethhdr *ethhdr = (struct ethhdr*)packet;
    t_context *ctx = (t_context *)user;
    int total_open_host = 0;
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    
    if (iph->protocol == IPPROTO_TCP) {
        int ip_header_len = iph->ihl * 4;
        
        struct tcphdr *tcph = (struct tcphdr*)((u_char *)iph + ip_header_len);
        if (iph->saddr == ctx->dest_ip.s_addr) {
            char scan_type[20] = "Unknown";

            if (tcph->syn == 1 && tcph->ack == 1) {
                strcpy(scan_type, "SYN-ACK Response");
            } else if (tcph->syn == 1 && tcph->ack == 0) {
                strcpy(scan_type, "SYN Scan");
            } else if (tcph->fin == 1 && tcph->psh == 1 && tcph->urg == 1) {
                strcpy(scan_type, "XMAS Scan");
            } else if (tcph->fin == 1) {
                strcpy(scan_type, "FIN Scan");
            } else if (tcph->syn == 0 && tcph->ack == 0 && tcph->fin == 0 && tcph->psh == 0 && tcph->urg == 0) {
                strcpy(scan_type, "NULL Scan");
            }

            char source_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(iph->saddr), source_ip_str, INET_ADDRSTRLEN);
            
            uint16_t port = ntohs(tcph->source);
            if (strcmp(scan_type, "Unknown") != 0)
                printf("Scan Type: %s | Open Port: %s:%d\n", scan_type, source_ip_str, port);
            fflush(stdout);
            
            if (strcmp(scan_type, "SYN-ACK Response") == 0) {
                total_open_host++;
            }  
        }
    }
}


int start_packet_sniffer(t_context *ctx) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[100];

    pthread_mutex_lock(ctx->mutex_lock);
    
    ctx->handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (ctx->handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        pthread_mutex_unlock(ctx->mutex_lock);
        return -1;
    }

    snprintf(filter_exp, sizeof(filter_exp), "tcp and src host %s", inet_ntoa(ctx->dest_ip));
    if (pcap_compile(ctx->handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
        pcap_close(ctx->handle);
        pthread_mutex_unlock(ctx->mutex_lock);
        return -1;
    }
    
    if (pcap_setfilter(ctx->handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
        pcap_freecode(&fp);
        pcap_close(ctx->handle);
        pthread_mutex_unlock(ctx->mutex_lock);
        return -1;
    }

    pcap_loop(ctx->handle, 1, packet_handler, (u_char*)ctx);
    
    pcap_freecode(&fp);
    pcap_close(ctx->handle);
    pthread_mutex_unlock(ctx->mutex_lock);

    return 0;
}

const char* format_ipv4_address_to_string(const struct in_addr* addr)
{
    static char buf[INET_ADDRSTRLEN];

    return inet_ntop(AF_INET, addr, buf, sizeof buf);
}

void* capture_syn_ack_response(void* ptr) 
{
    t_context *ctx = (t_context*)ptr;
    start_packet_sniffer(ctx);
    return NULL;
}

