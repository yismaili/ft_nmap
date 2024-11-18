#ifndef FT_NMAP_H
#define FT_NMAP_H
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netdb.h>

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
bool parse_ports(char *ports, t_scan_config *config);
bool parse_speedup(char *speedup, t_scan_config *config);
bool parse_scan(char *scan_type, t_scan_config *config);
bool parse_ips(char *ips, t_scan_config *config);
bool parse_file(char *filename, t_scan_config *config);
int is_valid_ipv4(char *str);
int is_valid_hostname(char *str);

#endif
