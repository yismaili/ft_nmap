#include "../../includes/scanner.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
{
    struct ethhdr *ethhdr = (struct ethhdr*)packet;
    t_context *ctx = (t_context *)user;
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    
    if (iph->protocol == IPPROTO_TCP) 
    {
        int ip_header_len = iph->ihl * 4;
        
        struct tcphdr *tcph = (struct tcphdr*)((u_char *)iph + ip_header_len);
        if (iph->saddr == ctx->dest_ip.s_addr)
        {
            int scan_type = -1;
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
                scan_type = SYN_SCAN;
                ctx->results[result_idx].is_open = true;
                
                if (ctx->config->version_detection) {
                    char *version = detect_service_version(
                        format_ipv4_address_to_string(&(ctx->dest_ip)), 
                        port,
                        ctx->config->timeout
                    );
                    if (version) {
                        strncpy(ctx->results[result_idx].service_version, 
                               version, 
                               sizeof(ctx->results[result_idx].service_version) - 1);
                        free(version);
                    }
                }
            } else if (tcph->rst == 1) 
            {
                if (ctx->results[result_idx].scan_type == FIN_SCAN || ctx->results[result_idx].scan_type == NULL_SCAN ||
                    ctx->results[result_idx].scan_type == XMAS_SCAN) {
                    ctx->results[result_idx].is_open = false;
                }
            }

            if (scan_type != -1)
            {
                ctx->results[result_idx].scan_type = scan_type;
                struct servent *service = getservbyport(htons(port), "tcp");
                if (service)
                    strncpy(ctx->results[result_idx].service_name, service->s_name, sizeof(ctx->results[result_idx].service_name) - 1);
                
                char source_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(iph->saddr), source_ip_str, INET_ADDRSTRLEN);
                fflush(stdout);
            }
        }
    }
}


int start_packet_sniffer(t_context *ctx) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[100];
    struct timeval timeout;
    fd_set read_fds;
    int fd;

    pthread_mutex_lock(ctx->mutex_lock);
    
    ctx->handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (ctx->handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
        pthread_mutex_unlock(ctx->mutex_lock);
        return -1;
    }

    fd = pcap_get_selectable_fd(ctx->handle);
    if (fd == -1) {
        fprintf(stderr, "pcap handle doesn't support select()\n");
        pcap_close(ctx->handle);
        ctx->handle = NULL;
        pthread_mutex_unlock(ctx->mutex_lock);
        return -1;
    }

    snprintf(filter_exp, sizeof(filter_exp), "tcp and src host %s", inet_ntoa(ctx->dest_ip));
    if (pcap_compile(ctx->handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) 
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
        pcap_close(ctx->handle);
        ctx->handle = NULL;
        pthread_mutex_unlock(ctx->mutex_lock);
        return -1;
    }
    
    if (pcap_setfilter(ctx->handle, &fp) == -1) 
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(ctx->handle));
        pcap_freecode(&fp);
        pcap_close(ctx->handle);
        ctx->handle = NULL;
        pthread_mutex_unlock(ctx->mutex_lock);
        return -1;
    }

    timeout.tv_sec = ctx->config->timeout;
    timeout.tv_usec = 0;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    int ready = select(fd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready == -1) {
        fprintf(stderr, "Select error: %s\n", strerror(errno));
    } else if (ready == 0) {
        pcap_freecode(&fp);
        pcap_close(ctx->handle);
        ctx->handle = NULL;
        pthread_mutex_unlock(ctx->mutex_lock);
        return 0;
    }

    if (FD_ISSET(fd, &read_fds)) {
        pcap_loop(ctx->handle, ctx->config->port_count, packet_handler, (u_char*)ctx);
    }
    
    pcap_freecode(&fp);
    pcap_close(ctx->handle);
    ctx->handle = NULL;
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

