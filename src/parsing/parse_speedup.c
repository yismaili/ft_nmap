#include "../../includes/ft_nmap.h"

bool parse_speedup(char *speedup, t_scan_config *config) {
  const char *ptr = speedup;

  while (*ptr) {
    if (!isdigit(*ptr)) {
      fprintf(stderr, "Non-digit in speedup specification: '%c'\n", *ptr);
      return (false);
    }
    ptr++;
  }

  int valid_speedup = atoi(speedup);
  if (valid_speedup > 250 || valid_speedup < 0) {
    fprintf(stderr, "Speedup cannot exceed 250\n");
    return (false);
  }

  config->thread_count = atoi(speedup);
  return (true);
}
