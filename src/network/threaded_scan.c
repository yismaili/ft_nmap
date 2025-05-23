#include "../includes/scanner.h"

void perform_scan_thread(t_context *ctx, int scan_type, struct in_addr* target_in_addr, int port) 
{
    char buffer_packet[4096] = {0};
    struct iphdr* iph = (struct iphdr*)buffer_packet;

    ctx->dest_ip.s_addr = inet_addr(format_ipv4_address_to_string(target_in_addr));
    if (ctx->dest_ip.s_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid address\n");
        return;
    }
    if (scan_type == UDP_SCAN){
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest)); 
        craft_udp_packet(ctx, buffer_packet, ctx->source_ip, iph, port);
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = ctx->dest_ip.s_addr;

        if (sendto(ctx->raw_socket, buffer_packet, sizeof(struct iphdr) + sizeof(struct udphdr),
            0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            printf("Error sending UDP packet.");
            cleanup_program(ctx->config, ctx);
            exit(2);
        }
    }else{
        struct tcphdr* tcph = (struct tcphdr*)(buffer_packet + sizeof(struct ip));
        craft_tcp_packet(ctx, buffer_packet, ctx->source_ip, iph, tcph, scan_type, port);
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        struct pseudo_header psh;

        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = ctx->dest_ip.s_addr;
        tcph->dest = htons(port);
        tcph->check = 0;

        psh.source_address = inet_addr(ctx->source_ip);
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));
        memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

        tcph->check = calculate_ip_tcp_checksum((unsigned short*)&psh, sizeof(struct pseudo_header));

        if (sendto(ctx->raw_socket, buffer_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            perror("Error sending SYN packet");
            cleanup_program(ctx->config, ctx);
            exit(2);
        }
    }
}

void scan_port_thread(t_context *ctx, char *ip_addr, int port) 
{
    struct in_addr target_in_addr;

    if (inet_pton(AF_INET, ip_addr, &target_in_addr) <= 0) {
        fprintf(stderr, "Invalid target IP address: %s\n", ip_addr);
        return;
    }

    if (ctx->config->scan_types.syn) {
        perform_scan_thread(ctx, SYN_SCAN, &target_in_addr, port);
    }
    if (ctx->config->scan_types.null) {
        perform_scan_thread(ctx, NULL_SCAN, &target_in_addr, port);
    }
    if (ctx->config->scan_types.ack) {
        perform_scan_thread(ctx, ACK_SCAN, &target_in_addr, port);
    }
    if (ctx->config->scan_types.fin) {
        perform_scan_thread(ctx, FIN_SCAN, &target_in_addr, port);
    }
    if (ctx->config->scan_types.xmas) {
        perform_scan_thread(ctx, XMAS_SCAN, &target_in_addr, port);
    }
    if (ctx->config->scan_types.udp) {
        perform_scan_thread(ctx, UDP_SCAN, &target_in_addr, port);
    }
}

void* thread_scan_ports(void *arg) {
    t_thread_data *thread_data = (t_thread_data*)arg;
    t_context *ctx = thread_data->ctx;

    pthread_t sniffer_thread;
    if (pthread_create(&sniffer_thread, NULL, start_packet_sniffer, ctx) != 0) {
        perror("Could not create sniffer thread");
        return NULL;
    }
    for (int i = thread_data->start_port_index; i < thread_data->end_port_index; i++) 
    {
        start_port_timing(&ctx->results[i]);
        scan_port_thread(ctx, thread_data->target_ip, ctx->config->ports[i]);
    }

    pthread_join(sniffer_thread, NULL);
    return NULL;
}

void start_threaded_scan(t_context *ctx, char *target_ip) 
{
    pthread_t *threads = malloc(ctx->config->thread_count * sizeof(pthread_t));
    t_thread_data *thread_data = malloc(ctx->config->thread_count * sizeof(t_thread_data));

    if (!threads || !thread_data) {
        perror("Failed to allocate memory for threads");
        free(threads);
        free(thread_data);
        return;
    }

    int ports_per_thread = ctx->config->port_count / ctx->config->thread_count;
    int remainder_ports = ctx->config->port_count % ctx->config->thread_count;

    for (int i = 0; i < ctx->config->thread_count; i++) {
        thread_data[i].ctx = ctx;
        thread_data[i].start_port_index = i * ports_per_thread;
        thread_data[i].end_port_index = thread_data[i].start_port_index + ports_per_thread;
        thread_data[i].target_ip = target_ip;

        if (i == ctx->config->thread_count - 1) {
            thread_data[i].end_port_index += remainder_ports; 
        }

        if (pthread_create(&threads[i], NULL, thread_scan_ports, &thread_data[i]) != 0) {
            perror("Failed to create thread");
            free(threads);
            free(thread_data);
            return;
        }
    }

    for (int i = 0; i < ctx->config->thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    print_scan_results(ctx, target_ip); 
    free(threads);
    free(thread_data);
    init_results(ctx);
}
