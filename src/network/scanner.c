#include "../../includes/scanner.h"
#include <unistd.h>

int initialize_scanner(t_context *ctx) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Create raw socket
    ctx->raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ctx->raw_socket < 0) {
        perror("Failed to create raw socket");
        return -1;
    }

    // Set socket options 
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


int main() {
    t_context ctx;

    if (initialize_scanner(&ctx) == 0) {
        printf("successfully.\n");

        pcap_close(ctx.handle);
        close(ctx.raw_socket);
        printf("Resources cleaned up.\n");
    } else {
        fprintf(stderr, "Failed\n");
    }

    return 0;
}

