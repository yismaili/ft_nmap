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
        parse_ports(argv[i + 1], config);
      }

      i += 2;

    } else {
      fprintf(stderr, "Invalid flag: %s\n", argv[i]);
      return (false);
    }
  }
  return (true);
}
