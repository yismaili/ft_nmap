#include "../../includes/ft_nmap.h"

void print_help_menu(void) {
  printf("Usage: ft_nmap [OPTIONS]\n");
  printf("Options:\n");
  printf("  --help\tPrint this help screen\n");
  printf("  --ports\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
  printf("  --ip\t\tip addresses to scan in dot format\n");
  printf("  --file\tFile name containing IP addresses to scan\n");
  printf("  --speedup\t[250 max] number of parallel threads to use\n");
  printf("  --scan\tSYN/NULL/FIN/XMAS/ACK/UDP\n");
}

bool parse_arguments(int argc, char **argv, t_scan_config *config) {
  int i = 1;

  while (i < argc) {
    if (strcmp(argv[i], "--help") == 0) {
      print_help_menu();
      i++;
    } else if (strcmp(argv[i], "--ports") == 0 ||
               strcmp(argv[i], "--ip") == 0 || strcmp(argv[i], "--file") == 0 ||
               strcmp(argv[i], "--speedup") == 0 ||
               strcmp(argv[i], "--scan") == 0) {

      if (i + 1 >= argc) {
        fprintf(stderr, "Missing argument for %s\n", argv[i]);
        return (false);
      }

      if (strcmp(argv[i], "--ports") == 0) {
        if (!parse_ports(argv[i + 1], config)) {
          return (false);
        };
      } else if (strcmp(argv[i], "--speedup") == 0) {
        if (!parse_speedup(argv[i + 1], config)) {
          return (false);
        }
      } else if (strcmp(argv[i], "--scan") == 0) {
        if (!parse_scan(argv[i + 1], config)) {
          return (false);
        }
      } else if (strcmp(argv[i], "--ip") == 0) {
        if (!parse_ips(argv[i + 1], config)) {
          return (false);
        }
      } else if (strcmp(argv[i], "--file") == 0) {
        if (!parse_file(argv[i + 1], config)) {
          return (false);
        }
      }

      i += 2;

    } else {
      fprintf(stderr, "Invalid flag: %s\n", argv[i]);
      return (false);
    }
  }

  if (config->scan_types.syn == false && config->scan_types.null == false &&
      config->scan_types.fin == false && config->scan_types.xmas == false &&
      config->scan_types.ack == false && config->scan_types.udp == false) {
    config->scan_types.syn = true;
    config->scan_types.null = true;
    config->scan_types.ack = true;
    config->scan_types.fin = true;
    config->scan_types.xmas = true;
    config->scan_types.udp = true;
  }

  if (config->ports == NULL) {
    config->ports = malloc(sizeof(int) * 1024);
    for (int i = 0; i <= 1024; i++) {
      config->ports[i] = i + 1;
    }
    config->port_count = 1024;
  }
  return (true);
}
