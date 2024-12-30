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
        execute_network_scan(ctx, ip_addr, UDP_SCAN);
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
    printf("============================================================\n");

    // Print header with proper column alignment
    printf("%-6s %-20s %-15s %-10s\n", 
           "PORT", "SERVICE", "STATE", "RESPONSE TIME");
    printf("------------------------------------------------------------\n");

    bool open_ports_found = false;
    double total_time = 0;
    int responded_ports = 0;

    for (int i = 0; i < ctx->config->port_count; i++) {
        int port = ctx->config->ports[i];
        t_result* result = &ctx->results[i];
        
        if (result->is_open) {
            open_ports_found = true;
            
            // Format port number
            char port_str[32];
            snprintf(port_str, sizeof(port_str), "%d", port);

            // Format service name (truncate if too long)
            char service_str[21];  // 20 chars + null terminator
            snprintf(service_str, sizeof(service_str), "%s", 
                    result->service_name[0] ? result->service_name : "Unknown");

            // Format scan type
            const char* scan_type;
            switch(result->scan_type) {
                case SYN_SCAN:
                    scan_type = "SYN";
                    break;
                case FIN_SCAN:
                    scan_type = "FIN";
                    break;
                case NULL_SCAN:
                    scan_type = "NULL";
                    break;
                case XMAS_SCAN:
                    scan_type = "XMAS";
                    break;
                default:
                    scan_type = "Unknown";
                    break;
            }

            // Print formatted line with timing
            printf("%-6s %-20s %-15s %.3fs\n",
                   port_str,
                   service_str,
                   scan_type,
                   result->response_time);

            total_time += result->response_time;
            responded_ports++;
        }
    }

    printf("------------------------------------------------------------\n");

    if (!open_ports_found) {
        printf("No open ports found.\n");
    } else {
        ctx->total_open_host++;
        
        // Print timing statistics
        printf("\nTiming Statistics:\n");
        printf("Total Scan Time: %.3f seconds\n", total_time);
        if (responded_ports > 0) {
            printf("Average Response Time: %.3f seconds\n", total_time / responded_ports);
        }
    }

    // Print summary
    printf("\nScan Summary:\n");
    printf("- Ports scanned: %d\n", ctx->config->port_count);
    printf("- Open ports found: %d\n", responded_ports);
    printf("============================================================\n\n");
}

