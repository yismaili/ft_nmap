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
  int ip_count = 0;
  config->target_ips = NULL;

  token = strtok(ips_copy, delim);
  while (token != NULL) {
    if (!is_valid_ipv4(token) && !is_valid_hostname(token)) {
      fprintf(stderr, "Error: Invalid IP address or hostname: '%s'\n", token);
      free(ips_copy);
      return false;
    }
    ip_count++;
    token = strtok(NULL, delim);
  }

  free(ips_copy);

  config->target_ips = (char **)malloc(ip_count * sizeof(char *));
  if (config->target_ips == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory for target IPs.\n");
    return false;
  }

  token = strtok(ips, delim);
  int i = 0;
  while (token != NULL) {
    if (strlen(token) > 0 &&
        (is_valid_ipv4(token) || is_valid_hostname(token))) {
      config->target_ips[i] = strdup(token);
      if (config->target_ips[i] == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for target IP.\n");
        for (int j = 0; j < i; j++) {
          free(config->target_ips[j]);
        }
        free(config->target_ips);
        return false;
      }
      i++;
    }
    token = strtok(NULL, delim);
  }

  config->ip_count = i;
  return true;
}
