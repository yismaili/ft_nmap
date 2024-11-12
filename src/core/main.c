#include "../../includes/scanner.h"
int parse_arguments(int argc, char **argv, t_config *config) {
    int i = 1;

    if (argc < 2) 
        return -1;
    // init defaults
    config->start_port = 22;
    config->end_port = 9999;
    config->thread_count = 1;
    config->scan_types = SCAN_SYN;
    config->timeout = DEFAULT_TIMEOUT;

    // parse arg
    while (i < argc)
    {
        if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
            strncpy(config->target_ip, argv[++i], 15);
            config->target_ip[15] = '\0';
        } 
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) 
        {
            sscanf(argv[++i], "%d-%d", &config->start_port, &config->end_port);
        } 
        else if (strcmp(argv[i], "--speedup") == 0 && i + 1 < argc) 
        {
            config->thread_count = atoi(argv[++i]);
            if (config->thread_count > MAX_THREADS)
            {
                config->thread_count = MAX_THREADS;
            }
        }
        i++;
    }
    return 0;
}

int main(int argc, char **argv) {
   // init config
    t_config config;
    t_context g_context;
    
    memset(&config, 0, sizeof(config));
    pthread_mutex_init(&config.mutex, NULL);

    if (parse_arguments(argc, argv, &config) < 0) {
        printf("Usage: %s --ip <target_ip> [--ports <start-end>] [--speedup <threads>]\n", argv[0]);
        exit(2);
    }

    // printf("  target ip: %s\n", config.target_ip);
    // printf("  thread count: %d\n", config.thread_count);
    // printf("  port range: %d to %d\n", config.start_port, config.end_port);

    //init context
    g_context.config = &config;
    if (initialize_scanner(&g_context) < 0) {
        fprintf(stderr, "Failed to initialize scanner\n");
        exit(2);
    }

    // Scan each port in the specified range sequentially
    for (int port = config.start_port; port <= config.end_port; ++port) {
        printf("hhhh %d\n", port);
        scan_port(port, &g_context);
    }

    // Cleanup
    close(g_context.raw_socket);

    return 0;
}