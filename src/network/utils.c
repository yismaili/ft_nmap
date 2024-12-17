#include "../../includes/scanner.h"

unsigned short calculate_ip_tcp_checksum(unsigned short* ptr, int nbytes)
{
    register long sum;
    register short answer;
    unsigned short oddbyte;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

void scan_port(t_context *ctx, char *ip_addr) 
{
    if (ctx->config->scan_types.syn)
        execute_network_scan(ctx, ip_addr, SYN_SCAN); 
    if (ctx->config->scan_types.null)
        execute_network_scan(ctx, ip_addr, NULL_SCAN);
    if (ctx->config->scan_types.ack)
        execute_network_scan(ctx, ip_addr, ACK_SCAN);
    if (ctx->config->scan_types.fin)
        execute_network_scan(ctx, ip_addr, FIN_SCAN);
    if (ctx->config->scan_types.xmas)
        execute_network_scan(ctx, ip_addr, XMAS_SCAN);
    if (ctx->config->scan_types.udp)
        execute_network_scan(ctx, ip_addr, 0);
    print_scan_results(ctx, ip_addr);    
}

void cleanup_scanner(t_context *ctx) 
{
    if (ctx->mutex_lock) {
        pthread_mutex_destroy(ctx->mutex_lock);
        free(ctx->mutex_lock);
        ctx->mutex_lock = NULL;
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

void print_scan_results(t_context *ctx, const char* target_ip) 
{
    printf("\nScan Results for IP: %s\n", target_ip);
    printf("------------------------------\n");

    printf("Open Ports:\n");
    printf("Port\tService\t\tScan Results\n");
    printf("----------------------------------------\n");

    bool open_ports_found = false;

    for (int i = 0; i < ctx->config->port_count; i++) {
        int port = ctx->config->ports[i];
        t_result* result = &ctx->results[i];
        if (result->is_open) {
            open_ports_found = true;
            printf("%d\t%s\t\t", port,result->service_name[0] ? result->service_name : "Unknown");
            switch(result->scan_type) {
                case SYN_SCAN:
                    printf("SYN(Open)");
                    break;
                case FIN_SCAN:
                    printf("FIN(Open)");
                    break;
                case NULL_SCAN:
                    printf("NULL(Open)");
                    break;
                case XMAS_SCAN:
                    printf("XMAS(Open)");
                    break;
                default:
                    printf("Open");
                    break;
            }
            printf("\n");
        }
    }

    if (!open_ports_found) {
        printf("No open ports found.\n");
    } else {
        ctx->total_open_host++;
    }
}
