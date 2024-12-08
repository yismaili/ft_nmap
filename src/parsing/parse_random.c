#include "../../includes/ft_nmap.h"

bool parse_random(char *random_str, t_scan_config *config) {
    const char *ptr = random_str;
    
    while (*ptr) {
        if (!isdigit(*ptr)) {
            fprintf(stderr, "Invalid random hosts value: must be a positive number\n");
            return false;
        }
        ptr++;
    }
    
    int random_val = atoi(random_str);
    if (random_val <= 0) {
        fprintf(stderr, "Random hosts count must be greater than 0\n");
        return false;
    }
    
    if (random_val > 1000) {
        fprintf(stderr, "Random hosts count cannot exceed 1000\n");
        return false;
    }
    
    config->random_hosts = random_val;
    
    config->target_ips = malloc(random_val * sizeof(char*));
    if (!config->target_ips) {
        fprintf(stderr, "Memory allocation failed\n");
        return false;
    }
    
    srand(time(NULL));
    for (int i = 0; i < random_val; i++) {
        config->target_ips[i] = generate_random_ip();
        if (!config->target_ips[i]) {
            for (int j = 0; j < i; j++) {
                free(config->target_ips[j]);
            }
            free(config->target_ips);
            fprintf(stderr, "Failed to generate random IP\n");
            return false;
        }
    }
    
    config->ip_count = random_val;
    return true;
} 