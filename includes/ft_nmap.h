#ifndef FT_NMAP_H
#define FT_NMAP_H
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define BUFFER_SIZE 4096

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
	bool hide_source_ip;
	bool bypass_ids;
	bool os_detection;
	bool version_detection;
	int timeout;
	int random_hosts;
  char *logfile;
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
char *resolve_dns(const char *hostname);
bool parse_timeout(char *timeout_str, t_scan_config *config);
bool parse_random(char *random_str, t_scan_config *config);
char* generate_random_ip(void);

#endif
