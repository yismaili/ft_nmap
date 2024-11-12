#include "../includes/ft_nmap.h"

void init_config(t_scan_config *config) {
  config->target_ips = NULL;
  config->ip_count = 0;
  config->ports = NULL;
  config->port_count = 0;
  config->thread_count = 0;
  config->scan_types.syn = false;
  config->scan_types.null = false;
  config->scan_types.ack = false;
  config->scan_types.fin = false;
  config->scan_types.xmas = false;
  config->scan_types.udp = false;
}

int main(int argc, char **argv) {
  t_scan_config config;
  init_config(&config);

  if (!parse_arguments(argc, argv, &config)) {
    return (1);
  }

  return (0);
}
