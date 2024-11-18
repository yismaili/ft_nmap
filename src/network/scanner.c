#include "../../includes/scanner.h"

int initialize_scanner(t_context *ctx) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // create raw socket
    ctx->raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ctx->raw_socket < 0) {
        perror("Failed to create raw socket");
        return -1;
    }

    // set socket options 
    int one = 1;
    if (setsockopt(ctx->raw_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Failed to set IP_HDRINCL");
        close(ctx->raw_socket);
        return -1;
    }

    // init pcap
    ctx->handle = pcap_open_live("any", 65535, 1, CAPTURE_TIMEOUT, errbuf);
    if (ctx->handle == NULL) {
        fprintf(stderr, "Failed to open pcap: %s\n", errbuf);
        close(ctx->raw_socket);
        return -1;
    }

    return 0;
}

static uint16_t calculate_checksum(uint16_t *addr, int len) {
    long sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len > 0)
        sum += *(unsigned char *)addr;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static void send_probe_packet(t_context *ctx, const char *target_ip, int port, int scan_type) {
    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    struct ip *ip_header = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));
    struct sockaddr_in dest;
    
    t_scan_result result = {
        .port = port,
        .status = PORT_UNKNOWN
    };
    
    memset(packet, 0, sizeof(packet));
    
    // Set up IP header
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_len = sizeof(packet);
    ip_header->ip_id = htons(rand());
    ip_header->ip_ttl = 64;
    ip_header->ip_p = (scan_type == 5) ? IPPROTO_UDP : IPPROTO_TCP;
    inet_pton(AF_INET, target_ip, &(ip_header->ip_dst));

    // Set up TCP header
    if (scan_type != 5) {  // Not UDP
        tcp_header->th_sport = htons(rand() % 65535);
        tcp_header->th_dport = htons(port);
        tcp_header->th_seq = htonl(rand());
        tcp_header->th_off = 5;
        tcp_header->th_win = htons(65535);
        
        // Set appropriate flags based on scan type
        switch (scan_type) {
            case 0: // SYN
                tcp_header->th_flags = TH_SYN;
                break;
            case 1: // NULL
                tcp_header->th_flags = 0;
                break;
            case 2: // ACK
                tcp_header->th_flags = TH_ACK;
                break;
            case 3: // FIN
                tcp_header->th_flags = TH_FIN;
                break;
            case 4: // XMAS
                tcp_header->th_flags = TH_FIN | TH_PUSH | TH_URG;
                break;
        }
        tcp_header->th_sum = calculate_checksum((uint16_t *)tcp_header, sizeof(struct tcphdr));
    }
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &(dest.sin_addr));
    
    if (sendto(ctx->raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) 
    {
        perror("Failed to send packet");
    } else 
    {
        printf("Port %d scan type %d: status %d\n", port, scan_type, result.status);
    }
    usleep(1000);  // Rate limiting
}



void scan_port(t_context *ctx) {
    //gettimeofday(&ctx->config->start_time, NULL);
    
    // Iterate through all ports
        printf("hi %d\n", ctx->config->port_count);
    for (int i = 0; i < ctx->config->port_count; i++) {
        int port = ctx->config->ports[i];
        if (ctx->config->scan_types.syn)
            send_probe_packet(ctx, ctx->config->target_ips[0], port, 0);
        if (ctx->config->scan_types.null)
            send_probe_packet(ctx, ctx->config->target_ips[0], port, 1);
        if (ctx->config->scan_types.ack)
            send_probe_packet(ctx, ctx->config->target_ips[0], port, 2);
        if (ctx->config->scan_types.fin)
            send_probe_packet(ctx, ctx->config->target_ips[0], port, 3);
        if (ctx->config->scan_types.xmas)
            send_probe_packet(ctx, ctx->config->target_ips[0], port, 4);
        if (ctx->config->scan_types.udp)
            send_probe_packet(ctx, ctx->config->target_ips[0], port, 5);
    }
    
    // gettimeofday(&ctx->config->end_time, NULL);
}
