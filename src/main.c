#include "../includes/ft_nmap.h"
#include "../includes/scanner.h"

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



int main(int argc, char **argv) {
   // init config
    t_context context;
    t_scan_config config;

    init_config(&config);
    memset(&config, 0, sizeof(config));
    if (!parse_arguments(argc, argv, &config)) {
        printf("Usage: %s --ip <target_ip> [--ports <start-end>] [--speedup <threads>]\n", argv[0]);
        exit(2);
    }

  // debug_config(config);

    context.config = &config;
    clock_gettime(CLOCK_MONOTONIC, &(context.start_time));
    if (initialize_scanner(&context) < 0) {
        fprintf(stderr, "Failed to initialize scanner\n");
        exit(2);
    }
    if (config.thread_count == 0)
    {
        scan_port(&context);
    }
    else{
      perform_scan( &context);
      cleanup_scanner(&context);
    }

    return 0;
}