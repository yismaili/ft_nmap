#include "../includes/ft_nmap.h"
#include "../includes/scanner.h"

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
  config->timeout = 2;
  config->scan_types.syn = false;
  config->scan_types.null = false;
  config->scan_types.ack = false;
  config->scan_types.fin = false;
  config->scan_types.xmas = false;
  config->scan_types.udp = false;
  config->random_hosts = 0;
  config->logfile = NULL;
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

int main(int argc, char **argv) {
    // init config
    t_context context;
    t_scan_config config;

    init_config(&config);
    memset(&context, 0, sizeof(context)); // Initialize context

    if (!parse_arguments(argc, argv, &config)) {
        printf("Usage: %s --ip <target_ip> [--ports <start-end>] [--speedup <threads>]\n", argv[0]);
        exit(2);
    }

    context.config = &config; // Set the config in context

    setup_logging(&config);

    if (initialize_scanner(&context) < 0) {
        fprintf(stderr, "Failed to initialize scanner\n");
        exit(2);
    }

    if (config.thread_count == 0) {
        scan_port(&context); // Call scan_port if no threads
    } else {
        perform_scan(&context); // Call perform_scan if threads are specified
    }

    if (config.os_detection) {
        for (int i = 0; i < config.ip_count; i++) {
            const char *os = detect_os(config.target_ips[i], config.timeout);
            printf("Detected OS for %s: %s\n", config.target_ips[i], os);
        }
    }

    cleanup_scanner(&context); // Clean up resources
    return 0;
}