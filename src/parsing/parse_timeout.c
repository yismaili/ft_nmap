#include "../../includes/ft_nmap.h"

bool parse_timeout(char *timeout_str, t_scan_config *config) {
    const char *ptr = timeout_str;
    
    while (*ptr) {
        if (!isdigit(*ptr)) {
            fprintf(stderr, "Invalid timeout value: must be a positive number\n");
            return false;
        }
        ptr++;
    }
    
    int timeout_val = atoi(timeout_str);
    if (timeout_val <= 0) {
        fprintf(stderr, "Timeout must be greater than 0\n");
        return false;
    }
    
    if (timeout_val > 30) {
        fprintf(stderr, "Timeout cannot exceed 30 seconds\n");
        return false;
    }
    
    config->timeout = timeout_val;
    return true;
} 
