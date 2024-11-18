#include "../../includes/ft_nmap.h"

bool parse_scan(char *scan_type, t_scan_config *config) {
  if (strcmp(scan_type, "SYN") == 0) {
    config->scan_types.syn = true;
  } else if (strcmp(scan_type, "NULL") == 0) {
    config->scan_types.null = true;
  } else if (strcmp(scan_type, "FIN") == 0) {
    config->scan_types.fin = true;
  } else if (strcmp(scan_type, "XMAS") == 0) {
    config->scan_types.xmas = true;
  } else if (strcmp(scan_type, "ACK") == 0) {
    config->scan_types.ack = true;
  } else if (strcmp(scan_type, "UDP") == 0) {
    config->scan_types.udp = true;
  } else {
    fprintf(stderr, "Invalid scan type: %s\n", scan_type);
    return (false);
  }
  return (true);
}
