#include "../includes/ft_nmap.h"
#include "../includes/scanner.h"
#include <errno.h>

void init_config(t_scan_config *config) {
  config->target_ips = NULL;
  config->ip_count = 0;
  config->ports = NULL;
  config->port_count = 0;
  config->thread_count = 0;
	config->hide_source_ip = false;
	config->bypass_ids = false;
	config->os_detection = false;
	config->version_detection = false;
  config->timeout = 5;
  config->scan_types.syn = false;
  config->scan_types.null = false;
  config->scan_types.ack = false;
  config->scan_types.fin = false;
  config->scan_types.xmas = false;
  config->scan_types.udp = false;
  config->random_hosts = 0;
  config->logfile = NULL;
}

void setup_logging(t_scan_config *config) {
    if (config->logfile) {
        FILE *log_file = freopen(config->logfile, "w", stdout);
        if (!log_file) {
            fprintf(stderr, "Error: Could not open logfile %s\n", config->logfile);
            exit(1);
        }
        dup2(fileno(stdout), fileno(stderr));
    }
}

void debug_config(t_scan_config config) {
  printf("Scanning IP addresses: ");
  for (int i = 0; i < config.ip_count; i++) {
    printf("%s, ", config.target_ips[i]);
  }

  printf("\nScanning ports: ");
  for (int i = 0; i < config.port_count; i++) {
    printf("%d, ", config.ports[i]);
  }

  printf("\nUsing %d threads\n", config.thread_count);

  printf("syn: %d\n", config.scan_types.syn);
  printf("null: %d\n", config.scan_types.null);
  printf("ack: %d\n", config.scan_types.ack);
  printf("fin: %d\n", config.scan_types.fin);
  printf("xmas: %d\n", config.scan_types.xmas);
  printf("udp: %d\n", config.scan_types.udp);
}



int main(int argc, char **argv) 
{
    t_context context;
    t_scan_config config;
    int total_open_host = 0;
    struct timespec start_time, finish_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    memset(&config, 0, sizeof(config));
    init_config(&config);
    context.total_open_host = 0;
    
    context.mutex_lock = malloc(sizeof(pthread_mutex_t));
    if (pthread_mutex_init(context.mutex_lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize mutex\n");
        exit(2);
    }
    
    if (!parse_arguments(argc, argv, &config)) {
        printf("Usage: %s --ip <target_ip> [--ports <start-end>] [--speedup <threads>]\n", argv[0]);
        exit(2);
    }
    // debug_config(config);
    context.config = &config;
  	setup_logging(&config);
    context.results = calloc(config.port_count, sizeof(t_result));
    if (!context.results) {
        fprintf(stderr, "Failed to allocate memory for results\n");
        exit(2);
    }
  
    for (int i = 0; i < config.port_count; i++) 
    {
        context.results[i].port = config.ports[i];
        context.results[i].state = CLOSED;
        context.results[i].service_name[0] = '\0';
				context.results[i].service_version[0] = '\0';
    }

    retrieve_source_ip_address(&context);
    if (init_row_socket(&context) < 0) {
        fprintf(stderr, "Failed to initialize scanner\n");
        exit(2);
    }
    int i = 0; 

    while (i < config.ip_count)
    {
      if (config.thread_count == 0)
        scan_port(&context,config.target_ips[i]);
      else
        start_threaded_scan(&context, config.target_ips[i]);
      i++;
    }
    if (config.os_detection) {
        for (int i = 0; i < config.ip_count; i++) {
            const char *os = detect_os(config.target_ips[i], config.timeout);
            printf("Detected OS for %s: %s\n", config.target_ips[i], os);
        }
    }

    if (context.results) {
        free(context.results);
    }
    return 0;
}
