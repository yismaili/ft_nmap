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

static void craft_tcp_packet(char *packet, const t_context *ctx, int port, scan_type_t scan_type) {
    struct ip *ip_header = (struct ip *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));

    // fill IP header
    memset(packet, 0, sizeof(struct ip) + sizeof(struct tcphdr));
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ip_header->ip_id = htons(rand());
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_TCP;
    inet_pton(AF_INET, ctx->config->target_ips[0], &ip_header->ip_dst);

    // fill TCP header
    tcp_header->th_sport = htons(12345); 
    tcp_header->th_dport = htons(port);
    tcp_header->th_seq = htonl(rand());
    tcp_header->th_off = 5;
    tcp_header->th_win = htons(65535);

    switch (scan_type) {
    case SCAN_SYN:
        tcp_header->th_flags = TH_SYN;
        break;
    case SCAN_NULL:
        tcp_header->th_flags = 0;
        break;
    case SCAN_ACK:
        tcp_header->th_flags = TH_ACK;
        break;
    case SCAN_FIN:
        tcp_header->th_flags = TH_FIN;
        break;
    case SCAN_XMAS:
        tcp_header->th_flags = TH_FIN | TH_PUSH | TH_URG;
        break;
    case SCAN_UDP:
        break;
    default:
        break;
}
}



void scan_port(int port, t_context *g_context) {
    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    struct sockaddr_in dest;

    t_scan_result result = {
        .port = port,
        .status = PORT_UNKNOWN
    };

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    printf("in scan port %s\n", g_context->config->target_ips[0]);
    if (inet_pton(AF_INET, g_context->config->target_ips[0], &dest.sin_addr) <= 0) {
        perror("Invalid IP address");
        return;
    }
    int scan = SCAN_SYN;

    while (scan <= SCAN_UDP) {
        if (g_context->config->scan_types.ack & scan) 
        {
            craft_tcp_packet(packet, g_context, port, scan);
            if (sendto(g_context->raw_socket, packet, sizeof(packet), 0,(struct sockaddr *)&dest, sizeof(dest)) < 0) 
            {
                perror("Failed to send packet");
            } else 
            {
                printf("Port %d scan type %d: status %d\n", port, scan, result.status);
            }
            sleep(2);
        }
        scan <<= 1;
    }
}
