#include "../includes/ft_nmap.h"
#include "../includes/scanner.h"
#include <errno.h>
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

    init_config(&config);
    memset(&config, 0, sizeof(config));
    
    // Initialize mutex
    context.mutex_lock = malloc(sizeof(pthread_mutex_t));
    if (pthread_mutex_init(context.mutex_lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize mutex\n");
        exit(2);
    }
    
    if (!parse_arguments(argc, argv, &config)) {
        printf("Usage: %s --ip <target_ip> [--ports <start-end>] [--speedup <threads>]\n", argv[0]);
        exit(2);
    }
    context.config = &config;

    retrieve_local_ip_address(&context);
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
        start_threaded_scan(&context);
      i++;
    }
    clock_gettime(CLOCK_MONOTONIC, &finish_time);

    double program_duration = (finish_time.tv_sec - start_time.tv_sec);
    program_duration += (finish_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

    int hours_duration = program_duration / 3600;
    int mins_duration = (int)(program_duration / 60) % 60;
    double secs_duration = fmod(program_duration, 60);

    printf("\nTotal active host: %d\n",total_open_host);
    printf("Scan duration    : %d hour(s) %d min(s) %.05lf sec(s)\n", hours_duration, mins_duration, secs_duration);
  
    return 0;
}