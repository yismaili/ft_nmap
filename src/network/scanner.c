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