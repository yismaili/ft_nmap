#include "../../includes/scanner.h"


void print_h(struct ethhdr *ethhdr,struct iphdr *iph,  struct tcphdr *tcph) 
{
    // Parse Ethernet header
    printf("\n=== Ethernet Header ===\n");
    printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2],
           ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5]);
    printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2],
           ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5]);
    printf("EtherType: 0x%04x\n", ntohs(ethhdr->h_proto));

    // Parse IP header

    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), dest_ip, INET_ADDRSTRLEN);

    printf("\n=== IP Header ===\n");
    printf("Source IP Address: %s\n", src_ip);
    printf("Destination IP Address: %s\n", dest_ip);
    printf("Protocol: %d\n", iph->protocol);
    printf("Header Length: %d bytes\n", iph->ihl * 4);
    printf("Total Length: %d bytes\n", ntohs(iph->tot_len));
    printf("TTL (Time to Live): %d\n", iph->ttl);

    // Check if it's a TCP packet
    if (iph->protocol == IPPROTO_TCP) 
    {
        printf("\n=== TCP Header ===\n");
        printf("Source Port: %d\n", ntohs(tcph->source));
        printf("Destination Port: %d\n", ntohs(tcph->dest));
        printf("Sequence Number: %u\n", ntohl(tcph->seq));
        printf("Acknowledgment Number: %u\n", ntohl(tcph->ack_seq));
        printf("Header Length: %d bytes\n", tcph->doff * 4);
        printf("Flags: ");
        if (tcph->syn) printf("SYN ");
        if (tcph->ack) printf("ACK ");
        if (tcph->fin) printf("FIN ");
        if (tcph->rst) printf("RST ");
        if (tcph->psh) printf("PSH ");
        if (tcph->urg) printf("URG ");
        printf("\n");
        printf("Window Size: %d\n", ntohs(tcph->window));
        printf("Checksum: 0x%04x\n", ntohs(tcph->check));
    }
    else
    {
        printf("\nNon-TCP packet. Skipping TCP header parsing.\n");
    }
}


void start_port_timing(t_result *result) 
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    result->start_time = (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

void end_port_timing(t_result *result) 
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    result->end_time = (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
    result->response_time = result->end_time - result->start_time;
}

const char* format_ipv4_address_to_string(const struct in_addr* addr)
{
    static char buf[INET_ADDRSTRLEN];

    return inet_ntop(AF_INET, addr, buf, sizeof buf);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
    struct ethhdr *ethhdr = (struct ethhdr*)packet;
    t_context *ctx = (t_context *)user;
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    
    if (iph->protocol == IPPROTO_UDP) 
    {
        int ip_header_len = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr*)((u_char*)iph + ip_header_len);
        
        if (iph->saddr == ctx->dest_ip.s_addr)
        {
            uint16_t port = ntohs(udph->source);
            int result_idx = -1;
            
            // Find matching port in our configuration
            for (int i = 0; i < ctx->config->port_count; i++) {
                if (ctx->config->ports[i] == port) {
                    result_idx = i;
                    break;
                }
            }
            
            if (result_idx != -1) 
            {
                // If we receive a UDP response, the port is likely open
                ctx->results[result_idx].state = OPEN;
                end_port_timing(&ctx->results[result_idx]);
                
                // Try to get service name
                struct servent *service = getservbyport(htons(port), "udp");
                if (service) {
                    strncpy(ctx->results[result_idx].service_name, service->s_name, sizeof(ctx->results[result_idx].service_name) - 1);
                    ctx->results[result_idx].service_name[sizeof(ctx->results[result_idx].service_name) - 1] = '\0';
                }
                else{
                     ctx->results[result_idx].state = CLOSED;
                }
            }
        }
    }
    
    if (iph->protocol == IPPROTO_TCP) 
    {
        int ip_header_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)((u_char *)iph + ip_header_len);
        
        if (iph->saddr == ctx->dest_ip.s_addr)
        {
            int tcp_responses = -1;
            uint16_t port = ntohs(tcph->source);

            int result_idx = -1;
            for (int i = 0; i < ctx->config->port_count; i++)
            {
                if (ctx->config->ports[i] == port) 
                {
                    result_idx = i;
                    break;
                }
            }

            if (result_idx == -1)
                return;

            if (tcph->syn == 1 && tcph->ack == 1) 
            {
                tcp_responses = SYN_SCAN;
                ctx->results[result_idx].state = OPEN;
                end_port_timing(&ctx->results[result_idx]);
            } 
            else if (tcph->rst == 1) 
            {
                ctx->results[result_idx].state = FILTERED;
                end_port_timing(&ctx->results[result_idx]);
            }

            if (tcp_responses != -1)
            {
                struct servent *service = getservbyport(htons(port), "tcp");
                if (service) {
                    strncpy(ctx->results[result_idx].service_name, service->s_name,sizeof(ctx->results[result_idx].service_name) - 1);
                    ctx->results[result_idx].service_name[sizeof(ctx->results[result_idx].service_name) - 1] = '\0';
                }else{
                    ctx->results[result_idx].state = CLOSED;
                }
            }
        }
    }
}

void *start_packet_sniffer(void* ptr) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp_bpf;
    char filter_exp[100];
    struct timeval timeout;
    fd_set read_fds;
    int fd;
    t_context *ctx = (t_context*)ptr;

    pthread_mutex_lock(ctx->mutex_lock);
    char *interface = retrieve_network_interface(ctx->source_ip);
    ctx->handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    // printf("---%s---\n",interface);
    if (ctx->handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s\n", errbuf);
        pthread_mutex_unlock(ctx->mutex_lock);
        return NULL;
    }

    fd = pcap_get_selectable_fd(ctx->handle);
    if (fd == -1) {
        fprintf(stderr, "pcap handle doesn't support select()\n");
        pcap_close(ctx->handle);
        pthread_mutex_unlock(ctx->mutex_lock);
        return NULL;
    }

    snprintf(filter_exp, sizeof(filter_exp), "(tcp or udp) and src host %s", inet_ntoa(ctx->dest_ip));
    if (pcap_compile(ctx->handle, &fp_bpf, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) 
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
        pcap_close(ctx->handle);
        pthread_mutex_unlock(ctx->mutex_lock);
        return NULL;
    }
    if (pcap_setfilter(ctx->handle, &fp_bpf) == -1) 
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
        pcap_freecode(&fp_bpf);
        pcap_close(ctx->handle);
        pthread_mutex_unlock(ctx->mutex_lock);
        return NULL;
    }

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    int ready = select(fd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready == -1) {
        fprintf(stderr, "Select error: %s\n", strerror(errno));
    } else if (ready == 0) {
        pcap_freecode(&fp_bpf);
        pcap_close(ctx->handle);
        pthread_mutex_unlock(ctx->mutex_lock);
        return NULL;
    }

    if (FD_ISSET(fd, &read_fds)) {
        if (ctx->config->port_count < 4)
            pcap_loop(ctx->handle, 1, packet_handler, (u_char*)ctx);
        else
            pcap_loop(ctx->handle, 4, packet_handler, (u_char*)ctx);
    }
    
    pcap_freecode(&fp_bpf);
    pcap_close(ctx->handle);
    pthread_mutex_unlock(ctx->mutex_lock);

    return NULL;
}