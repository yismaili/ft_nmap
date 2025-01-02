#include "../../includes/ft_nmap.h"

int is_valid_ipv4(char *str) {
  struct sockaddr_in sa;
  int result = inet_pton(AF_INET, str, &(sa.sin_addr));
  return result != 0;
}

int is_valid_hostname(char *str) {
  struct addrinfo hints, *res;
  int result;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  result = getaddrinfo(str, NULL, &hints, &res);
  if (result == 0) {
    freeaddrinfo(res);
    return 1;
  } else {
    return 0;
  }
}

bool parse_ips(char *ips, t_scan_config *config) {
    char *ips_copy = strdup(ips);
    char *token;
    char *delim = ", ";
    int new_ip_count = 0;

    token = strtok(ips_copy, delim);
    while (token != NULL) {
        if (!is_valid_ipv4(token) && !is_valid_hostname(token)) {
            fprintf(stderr, "Error: Invalid IP address or hostname: '%s'\n", token);
            free(ips_copy);
            return false;
        }
        new_ip_count++;
        token = strtok(NULL, delim);
    }
    free(ips_copy);

    char **new_target_ips = (char **)malloc((config->ip_count + new_ip_count) * sizeof(char *));
    if (new_target_ips == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for target IPs.\n");
        return false;
    }

    for (int i = 0; i < config->ip_count; i++) {
        new_target_ips[i] = config->target_ips[i];
    }

    token = strtok(ips, delim);
    int i = config->ip_count;
    while (token != NULL) {
        char *resolved_ip = NULL;

        if (is_valid_ipv4(token)) {
            resolved_ip = strdup(token);
        } else if (is_valid_hostname(token)) {
            resolved_ip = resolve_dns(token);
            if (resolved_ip == NULL) {
                fprintf(stderr, "Error: Failed to resolve hostname: '%s'\n", token);
                for (int j = 0; j < i; j++) {
                    if (j >= config->ip_count) {
                        free(new_target_ips[j]);
                    }
                }
                free(new_target_ips);
                return false;
            }
        }

        if (resolved_ip != NULL) {
            new_target_ips[i] = resolved_ip;
            i++;
        }

        token = strtok(NULL, delim);
    }

    if (config->target_ips != NULL) {
        free(config->target_ips);
    }
    
    config->target_ips = new_target_ips;
    config->ip_count = i;
    return true;
}
