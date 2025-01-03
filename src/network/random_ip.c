#include "../../includes/ft_nmap.h"

char* generate_random_ip() {
    struct in_addr ip_addr;
    uint32_t ip;
    
    do {
        ip = (rand() % 0xffffffff);
        
        // Skip private IP ranges
        if ((ip & 0xff000000) == 0x0a000000 ||  // 10.0.0.0/8
            (ip & 0xfff00000) == 0xac100000 ||  // 172.16.0.0/12
            (ip & 0xffff0000) == 0xc0a80000 ||  // 192.168.0.0/16
            (ip & 0xff000000) == 0x7f000000) {  // 127.0.0.0/8
            continue;
        }
        
        break;
    } while (1);
    
    ip_addr.s_addr = htonl(ip);
    
    char *ip_str = malloc(INET_ADDRSTRLEN);
    if (!ip_str) return NULL;
    
    inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN);
    return ip_str;
}
