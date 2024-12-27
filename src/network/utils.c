#include "../../includes/scanner.h"

void resolve_ip_to_hostname(const char* ip, char* buffer)
{
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip);
    dest.sin_port = 0;

    if (getnameinfo((struct sockaddr*)&dest, sizeof(dest), buffer, NI_MAXHOST, NULL, 0, NI_NAMEREQD) != 0)
        strcpy(buffer, "Hostname can't be determined");
}

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
    if (ctx->config->scan_types.syn){
        execute_network_scan(ctx, ip_addr, SYN_SCAN);
    }  
    if (ctx->config->scan_types.null)
    {
        execute_network_scan(ctx, ip_addr, NULL_SCAN);
    }
    if (ctx->config->scan_types.ack){
        execute_network_scan(ctx, ip_addr, ACK_SCAN);
    }
    if (ctx->config->scan_types.fin)
    {
        execute_network_scan(ctx, ip_addr, FIN_SCAN);
    }
    if (ctx->config->scan_types.xmas)
    {
        execute_network_scan(ctx, ip_addr, XMAS_SCAN);
    }
    if (ctx->config->scan_types.udp){
        execute_network_scan(ctx, ip_addr, UDP_SCAN);
    }
    print_scan_results(ctx, ip_addr);    
}

void cleanup_scanner(t_context *ctx) 
{
		if (!ctx) return;

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

    if (ctx->results) {
        free(ctx->results);
        ctx->results = NULL;
    }
}

void print_scan_results(t_context *ctx, const char* target_ip) 
{
    printf("\nScan Results for IP: %s\n", target_ip);
    printf("------------------------------------\n");

    printf("Open Ports:\n");
    if (ctx->config->version_detection) {
        printf("Port\tService\t\tScan Type\t\tState\t\tVersion\n");
        printf("----------------------------------------------------------------------------\n");
    } else {
        printf("Port\tService\t\tScan Type\t\tState\n");
        printf("------------------------------------------------------------\n");
    }

    bool open_ports_found = false;

    for (int i = 0; i < ctx->config->port_count; i++) {
        int port = ctx->config->ports[i];
        t_result* result = &ctx->results[i];
        if (result->state == PORT_STATE_OPEN || result->state == PORT_STATE_OPEN_FILTERED) {
            open_ports_found = true;
            const char *protocol = NULL;
            switch(result->scan_type) {
                case SYN_SCAN:
                case FIN_SCAN:
                case NULL_SCAN:
                case XMAS_SCAN:
                    protocol = "tcp";
                    break;
                case UDP_SCAN:
                    protocol = "udp";
                    break;
                default:
                    protocol = NULL;
                    break;
            }
            const char *service_name = NULL;
            if (result->service_name[0] != '\0') {
                service_name = result->service_name;
            } else if (protocol != NULL) {
                struct servent *service = getservbyport(htons(port), protocol);
                if (service) {
                    service_name = service->s_name;
                } else {
                    service_name = "Unknown";
                }
            } else {
                service_name = "Unknown";
            }

            printf("%d\t%s\t\t", port, service_name);
            
            switch(result->scan_type) {
                case SYN_SCAN:
                    printf("SYN");
                    break;
                case FIN_SCAN:
                    printf("FIN");
                    break;
                case NULL_SCAN:
                    printf("NULL");
                    break;
                case XMAS_SCAN:
                    printf("XMAS");
                    break;
                case UDP_SCAN:
                    printf("UDP");
                    break;
                default:
                    break;
            }
            
          switch(result->state) {
            case PORT_STATE_OPEN:
                printf("\t\t\tOpen");
                break;
            case PORT_STATE_CLOSED:
                printf("\t\t\tClosed");
                break;
            case PORT_STATE_FILTERED:
                printf("\t\t\tFiltered");
                break;
            case PORT_STATE_OPEN_FILTERED:
                printf("\t\t\tOpen Filtered");
                break;
            case PORT_STATE_UNFILTERED:
                printf("\t\t\tUnfiltered");
                break;
            default:
                break;
        }

						if (ctx->config->version_detection) {
                printf("\t\t%s\t\t", 
                        result->service_version[0] ?
											  result->service_version :
											  "Unknown"
											);
            }
            printf("\n");
        }
    }

    if (!open_ports_found) {
        printf("No open ports found.\n");
    }
}
