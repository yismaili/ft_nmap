#include "../../includes/scanner.h"
#include <stdatomic.h>

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
    init_results(ctx);
}

void init_results(t_context *ctx)
 {
  for (int i = 0; i < ctx->config->port_count; i++) 
    {
        ctx->results[i].port = ctx->config->ports[i];
        ctx->results[i].state = FILTERED;
        ctx->results[i].service_name[0] = '\0';
		ctx->results[i].service_version[0] = '\0';
    }
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
    printf("=================================================================\n");

    // Print header with proper column alignment
    if (ctx->config->version_detection) {
      printf("%-6s %-10s %-20s %-10s %-10s\n",
           "PORT", "SERVICE", "VERSION", "STATE", "TIME");
    } else {
      printf("%-6s %-10s %-10s %-10s %-10s\n",
           "PORT", "SERVICE", "VERSION", "STATE", "TIME");
    }
    printf("-----------------------------------------------------------------\n");

    bool open_ports_found = false;
    double total_time = 0;
    int responded_ports = 0;

    for (int i = 0; i < ctx->config->port_count; i++) {
        int port = ctx->config->ports[i];
        t_result* result = &ctx->results[i];
        
        char port_str[32];
        snprintf(port_str, sizeof(port_str), "%d", port);

        char service_str[21];
        char version_str[21];
        snprintf(service_str, sizeof(service_str), "%s", 
                result->service_name[0] ? result->service_name : "Unknown");
        snprintf(version_str, sizeof(version_str), "%s", 
                result->service_version[0] ? result->service_version : "Unknown");
        if ((ctx->config->port_count == 1024 && result->state == OPEN)||(ctx->config->port_count != 1024 && result->state != OPEN) || (ctx->config->port_count != 1024 && result->state == OPEN))
        {
            //  const char* state = result->state == OPEN ? "\033[32mopen\033[0m" : "\033[31mfiltered\033[0m";
             const char* state;
            if (result->state == OPEN)
                state = "\033[32mopen\033[0m";
            else if (result->state == CLOSED)
                state = "\033[31mclosed\033[0m";
            else if (result->state == FILTERED)
                state = "\033[31mfiltered\033[0m";
            if (ctx->config->version_detection) {
              printf("%-6s %-10s %-20s %-19s %.3fs\n",
                  port_str,
                  service_str,
                  version_str,
                  state,
                  result->response_time);
            } else {
              printf("%-6s %-10s %-19s %.3fs\n",
                  port_str,
                  service_str,
                  state,
                  result->response_time);
            }

        }

        if (result->state == OPEN) {
            open_ports_found = true;
            responded_ports++;
        }
        total_time += result->response_time;
    }

    printf("-----------------------------------------------------------------\n");

    printf("\nTiming Statistics:\n");
    printf("Total Scan Time: %.3f seconds\n", total_time);
    if (ctx->config->port_count > 0) {
        printf("Average Response Time: %.3f seconds\n", total_time / ctx->config->port_count);
    }
    
    printf("\nScan Summary:\n");
    printf("- Ports scanned: %d\n", ctx->config->port_count);
    printf("- Open ports: %d\n", responded_ports);
    printf("- Closed ports: %d\n", ctx->config->port_count - responded_ports);

    // if (open_ports_found) {
    //     ctx->total_open_host++;
    // }

    printf("=================================================================\n\n");
}
