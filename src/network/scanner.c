#include "../../includes/scanner.h"

int initialize_scanner(t_context *ctx) 
{
    char errbuf[PCAP_ERRBUF_SIZE];

    ctx->raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ctx->raw_socket < 0) 
    {
        perror("Failed to create raw socket");
        return -1;
    }

    int one = 1;
    if (setsockopt(ctx->raw_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("Failed to set IP_HDRINCL");
        close(ctx->raw_socket);
        return -1;
    }

    ctx->handle = pcap_open_live("any", 65535, 1, CAPTURE_TIMEOUT, errbuf);
    if (ctx->handle == NULL)
    {
        fprintf(stderr, "Failed to open pcap: %s\n", errbuf);
        close(ctx->raw_socket);
        return -1;
    }

    ctx->mutex = malloc(sizeof(pthread_mutex_t));
    if (pthread_mutex_init(ctx->mutex, NULL) != 0)
    {
        fprintf(stderr, "Failed to initialize mutex\n");
        pcap_close(ctx->handle);
        close(ctx->raw_socket);
        return -1;
    }
    
    return 0;
}

static void send_probe_packet(t_context *ctx, const char *target_ip, int port, int scan_type) 
{
    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    struct ip *ip_header = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));
    struct sockaddr_in dest;
    
    memset(packet, 0, sizeof(packet));
    
    // IP header setup
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_len = htons(sizeof(packet));
    ip_header->ip_id = htons(rand());
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_TCP;
    
    if (scan_type == 5) 
    {
        ip_header->ip_p = IPPROTO_UDP;
    }
    
    inet_pton(AF_INET, target_ip, &(ip_header->ip_dst));

    if (scan_type != 5) 
    {
        tcp_header->th_sport = htons(rand() % 65535);
        tcp_header->th_dport = htons(port);
        tcp_header->th_seq = htonl(rand());
        tcp_header->th_off = 5;
        tcp_header->th_win = htons(65535);
        
        switch (scan_type) 
        {
            case 0:  // SYN 
                tcp_header->th_flags = TH_SYN;
                break;
            case 1:  // NULL 
                tcp_header->th_flags = 0;
                break;
            case 2:  // ACK 
                tcp_header->th_flags = TH_ACK;
                break;
            case 3:  // FIN 
                tcp_header->th_flags = TH_FIN;
                break;
            case 4:  // XMAS
                tcp_header->th_flags = TH_FIN | TH_PUSH | TH_URG;
                break;
        }
    }
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &(dest.sin_addr));
    
    pthread_mutex_lock(ctx->mutex);
    sendto(ctx->raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
    pthread_mutex_unlock(ctx->mutex);
}

void scan_port( t_context *ctx) 
{
    int j = 0, i;

    while (j < ctx->config->ip_count)
    {
        i = 0;
        while (i < ctx->config->port_count) 
        {
            int port = ctx->config->ports[i];
            
            if (ctx->config->scan_types.syn)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 0);
            if (ctx->config->scan_types.null)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 1);
            if (ctx->config->scan_types.ack)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 2);
            if (ctx->config->scan_types.fin)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 3);
            if (ctx->config->scan_types.xmas)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 4);
            if (ctx->config->scan_types.udp)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 5);
            i++;
        }
        j++;
    }
    
    return;
}

void *scan_thread(void *arg) 
{
    t_thread_data *data_thread = (t_thread_data *)arg;
    t_context *ctx = data_thread->ctx;
    int j = 0, i;

    while (j < ctx->config->ip_count)
    {
        i = 0;
        while (i < ctx->config->port_count) 
        {
            int port = ctx->config->ports[i];
            
            if (ctx->config->scan_types.syn)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 0);
            if (ctx->config->scan_types.null)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 1);
            if (ctx->config->scan_types.ack)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 2);
            if (ctx->config->scan_types.fin)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 3);
            if (ctx->config->scan_types.xmas)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 4);
            if (ctx->config->scan_types.udp)
                send_probe_packet(ctx, ctx->config->target_ips[j], port, 5);
            i++;
        }
        j++;
    }
    
    return NULL;
}

void perform_scan(t_context *ctx) { 
    pthread_t threads[MAX_THREADS];
    t_thread_data thread_data[MAX_THREADS];
    int ports_per_thread = ctx->config->port_count / ctx->config->thread_count;
    int remaining_ports = ctx->config->port_count % ctx->config->thread_count;
    int current_port_index = 0;
    int i = 0;

    while(i < ctx->config->thread_count) 
    {
        thread_data[i].ctx = ctx;
        thread_data[i].thread_id = i;
        thread_data[i].start_port_index = current_port_index;
        int additional_ports = 0;
        if (i < remaining_ports)
            additional_ports = 1;

        thread_data[i].end_port_index = current_port_index + ports_per_thread + additional_ports - 1;
        pthread_create(&threads[i], NULL, scan_thread, &thread_data[i]);
        current_port_index = thread_data[i].end_port_index + 1;
        i++;
    }
    
    i = 0;
    while (i < ctx->config->thread_count) 
    {
        pthread_join(threads[i], NULL);
        i++;
    }
    
    sleep(CAPTURE_TIMEOUT / 1000);
    pcap_breakloop(ctx->handle);
}

void cleanup_scanner(t_context *ctx) {
    if (ctx->mutex) {
        pthread_mutex_destroy(ctx->mutex);
        free(ctx->mutex);
        ctx->mutex = NULL;
    }
    
    if (ctx->handle) {
        pcap_close(ctx->handle);
        ctx->handle = NULL;
    }
    
    if (ctx->raw_socket >= 0) {
        close(ctx->raw_socket);
        ctx->raw_socket = -1;
    }
}

