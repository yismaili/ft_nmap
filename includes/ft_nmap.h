#ifndef FT_NMAP_H
#define FT_NMAP_H
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

typedef struct e_scan_type {
  bool syn;
  bool null;
  bool ack;
  bool fin;
  bool xmas;
  bool udp;
} t_scan_type;

typedef struct s_scan_config {
  char **target_ips;
  int ip_count;
  int *ports;
  int port_count;
  t_scan_type scan_types;
  int thread_count;
  double start_time;
} t_scan_config;

bool parse_arguments(int argc, char **argv, t_scan_config *config);
void print_help_menu(void);
void parse_ports(char *ports, t_scan_config *config);

#endif
