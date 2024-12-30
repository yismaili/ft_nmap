#include "../../includes/scanner.h"

int init_row_socket(t_context *ctx) 
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
    return 0;
}

void execute_network_scan(t_context *ctx, const char* target, int scan_type)
{
    struct in_addr target_in_addr;
    pthread_t sniffer_thread;

    if (inet_pton(AF_INET, target, &target_in_addr) <= 0) {
        printf("Invalid target IP address: %s\n", target);
        return;
    }
    if (pthread_create(&sniffer_thread, NULL, start_packet_sniffer, ctx) < 0)
    {
        printf("Could not create sniffer thread");
        exit(2);
    }
    send_scan_packets(ctx, scan_type, &target_in_addr);
    pthread_join(sniffer_thread, NULL);
}

void send_scan_packets(t_context *ctx, int scan_type, struct in_addr* target_in_addr)
{
    char buffer_packet[4096];
    struct iphdr* iph = (struct iphdr*)buffer_packet;
    int i = 0;

    ctx->dest_ip.s_addr = inet_addr(format_ipv4_address_to_string(target_in_addr));
    if (ctx->dest_ip.s_addr == -1) {
        printf("Invalid address\n");
        exit(2);
    }

    if (scan_type == 5) {
        while (i < ctx->config->port_count) {
            int port = ctx->config->ports[i];
            struct sockaddr_in dest;
            start_port_timing(&ctx->results[i]);
            craft_udp_packet(ctx, buffer_packet, ctx->source_ip, iph, port);
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = ctx->dest_ip.s_addr;

            if (sendto(ctx->raw_socket, buffer_packet, sizeof(struct iphdr) + sizeof(struct udphdr),
                0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
                printf("Error sending UDP packet.");
                exit(2);
            }
            i++;
        }
    } else {
        struct tcphdr* tcph = (struct tcphdr*)(buffer_packet + sizeof(struct ip));
        craft_tcp_packet(ctx, buffer_packet, ctx->source_ip, iph, tcph, scan_type);
        while (i < ctx->config->port_count) 
        {
            int port = ctx->config->ports[i];
            struct sockaddr_in dest;
            struct pseudo_header psh;
            start_port_timing(&ctx->results[i]);

            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = ctx->dest_ip.s_addr;
            tcph->dest = htons(port);
            tcph->check = 0;
            if (sendto(ctx->raw_socket, buffer_packet, sizeof(struct iphdr) + sizeof(struct tcphdr),
                0, (struct sockaddr*)&dest, sizeof(dest)) < 0){
                printf("Error sending syn packet.");
                exit(2);
            }
            i++;
        }
    }
}


void craft_tcp_packet(t_context *ctx,char* buffer_packet, const char* source_ip, struct iphdr* iph, struct tcphdr* tcph, int scan_type)
{
    memset(buffer_packet, 0, 4096);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htons(46156);
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = ctx->dest_ip.s_addr;
    iph->check = calculate_ip_tcp_checksum((unsigned short*)buffer_packet, iph->tot_len >> 1);

    tcph->source = htons(46156);
    tcph->dest = htons(80);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->window = htons(14600);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;

    switch(scan_type) {
        case 0: 
            tcph->syn = 1;
            break;
        case 1: 
            break;
        case 2: 
            tcph->ack = 1;
            break;
        case 3:
            tcph->fin = 1;
            break;
        case 4: 
            tcph->fin = 1;
            tcph->psh = 1;
            tcph->urg = 1;
            break;
        case 5: // UDP scan
            break;
        default:
            tcph->syn = 1;
            break;
    }
}

void craft_udp_packet(t_context *ctx, char* buffer_packet, const char* source_ip, struct iphdr* iph, int port)
{
    memset(buffer_packet, 0, 4096);
    struct udphdr* udph = (struct udphdr*)(buffer_packet + sizeof(struct iphdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    iph->id = htons(46156);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = ctx->dest_ip.s_addr;

    udph->source = htons(46156);
    udph->dest = htons(port);
    udph->len = htons(sizeof(struct udphdr));
    udph->check = 0;
    iph->check = calculate_ip_tcp_checksum((unsigned short*)buffer_packet, iph->tot_len >> 1);
}

