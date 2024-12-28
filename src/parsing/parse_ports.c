#include "../../includes/ft_nmap.h"

bool parse_ports(char *ports, t_scan_config *config) {
  const char *ptr = ports;
  while (*ptr) {
    if (!isdigit(*ptr) && *ptr != ',' && *ptr != '-') {
      fprintf(stderr, "Invalid character in port specification: '%c'\n", *ptr);
      return (false);
    }
    ptr++;
  }

  char seen_ports[65536 / 8] = {0};
  int port_count = 0;
  int *port_array = malloc(sizeof(int) * 1024);

  if (!port_array) {
    fprintf(stderr, "Memory allocation failed\n");
    return (false);
  }

  char *token = strtok(ports, ",");
  while (token != NULL) {
    int start_port, end_port;
    char extra_chars[32];

    int matched = sscanf(token, "%d-%d%s", &start_port, &end_port, extra_chars);

    if (strchr(token, '-')) {
      if (matched != 2) {
        fprintf(stderr, "Invalid port range format: %s\n", token);
        free(port_array);
        return (false);
      }

      if (start_port <= 0 || start_port > 65535 || end_port <= 0 ||
          end_port > 65535) {
        fprintf(stderr, "Ports must be between 1 and 65535\n");
        free(port_array);
        return (false);
      }

      if (start_port > end_port) {
        fprintf(stderr, "Invalid port range: %d-%d\n", start_port, end_port);
        free(port_array);
        return (false);
      }

      for (int i = start_port; i <= end_port && port_count < 1024; i++) {
        if (!(seen_ports[i / 8] & (1 << (i % 8)))) {
          seen_ports[i / 8] |= (1 << (i % 8));
          port_array[port_count++] = i;
        }
      }

      if (port_count >= 1024) {
        fprintf(stderr, "Warning: Port limit of 1024 reached. Some ports were omitted.\n");
        break;
      }
    } else {
      matched = sscanf(token, "%d%s", &start_port, extra_chars);
      if (matched != 1) {
        fprintf(stderr, "Invalid port format: %s\n", token);
        free(port_array);
        return (false);
      }

      if (start_port <= 0 || start_port > 65535) {
        fprintf(stderr, "Ports must be between 1 and 65535\n");
        free(port_array);
        return (false);
      }

      if (port_count >= 1024) {
        fprintf(stderr, "Warning: Port limit of 1024 reached. Some ports were omitted.\n");
        break;
      }

      if (!(seen_ports[start_port / 8] & (1 << (start_port % 8)))) {
        seen_ports[start_port / 8] |= (1 << (start_port % 8));
        port_array[port_count++] = start_port;
      }
    }

    token = strtok(NULL, ",");
  }

  config->ports = port_array;
  config->port_count = port_count;
  return (true);
}
