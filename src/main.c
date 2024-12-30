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

void cleanup_program(t_scan_config *config, t_context *context) {
    cleanup_scanner(context);
    
    if (config->target_ips) {
        for (int i = 0; i < config->ip_count; i++) {
            free(config->target_ips[i]);
        }
        free(config->target_ips);
				config->target_ips = NULL;
    }
    if (config->ports) {
        free(config->ports);
				config->ports = NULL;
    }
    if (config->logfile) {
        free(config->logfile);
				config->logfile = NULL;
    }
}

int main(int argc, char **argv) 
{
    t_context context;
		memset(&context, 0, sizeof(t_context));
    context.raw_socket = -1;
    context.handle = NULL;
    context.mutex_lock = NULL;
    context.results = NULL;

    t_scan_config config;
    int total_open_host = 0;
    struct timespec start_time, finish_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    memset(&config, 0, sizeof(config));
    init_config(&config);
    context.total_open_host = 0;
    
    context.mutex_lock = malloc(sizeof(pthread_mutex_t));
    if (!context.mutex_lock || pthread_mutex_init(context.mutex_lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize mutex\n");
        cleanup_program(&config, &context);
        exit(2);
    }
    
    if (!parse_arguments(argc, argv, &config)) {
        printf("Usage: %s --ip <target_ip> [--ports <start-end>] [--speedup <threads>]\n", argv[0]);
        cleanup_program(&config, &context);
        exit(2);
    }

    context.config = &config;

		setup_logging(&config);
    // Initialize results array
    context.results = calloc(config.port_count, sizeof(t_result));
    if (!context.results) {
        fprintf(stderr, "Failed to allocate memory for results\n");
        cleanup_program(&config, &context);
        exit(2);
    }
  
    for (int i = 0; i < config.port_count; i++) {
        context.results[i].port = config.ports[i];
        context.results[i].is_open = false;
        context.results[i].scan_type = -1;
        context.results[i].service_name[0] = '\0';
				context.results[i].service_version[0] = '\0';
        if (config.scan_types.udp) {
            context.results[i].state = PORT_STATE_OPEN_FILTERED;
        } else {
            context.results[i].state = PORT_STATE_UNKNOWN;
        }
    }

    retrieve_source_ip_address(&context);
    if (init_row_socket(&context) < 0) {
        fprintf(stderr, "Failed to initialize scanner\n");
        cleanup_program(&config, &context);
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
            printf("\nDetected OS for %s: %s\n", config.target_ips[i], os);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &finish_time);

    double program_duration = (finish_time.tv_sec - start_time.tv_sec);
    program_duration += (finish_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

    int hours_duration = program_duration / 3600;
    int mins_duration = (int)(program_duration / 60) % 60;
    double secs_duration = fmod(program_duration, 60);

    printf("\nTotal active host: %d\n",context.total_open_host);
    printf("Scan duration    : %d hour(s) %d min(s) %.05lf sec(s)\n", hours_duration, mins_duration, secs_duration);

		cleanup_program(&config, &context);
    return 0;
}
