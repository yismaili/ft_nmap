#include "../../includes/ft_nmap.h"

void print_help_menu(void) {
  printf("Usage: ft_nmap [OPTIONS]\n");
  printf("Options:\n");
  printf("  --help\tPrint this help screen\n");
  printf("  --ports\tports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
  printf("  --ip\t\tip addresses to scan in dot format\n");
  printf("  --file\tFile name containing IP addresses to scan\n");
  printf("  --speedup\t[250 max] number of parallel threads to use\n");
  printf("  --scan\tSYN/NULL/FIN/XMAS/ACK/UDP\n");
	printf("  --hide-ip\tHide the source IP address when sending packets\n");
	printf("  --bypass-ids\tBypass IDS/Firewall detection\n");
	printf("  --os\t\tEnable OS detection\n");
	printf("  --version\tEnable version detection\n");
	printf("  --timeout\tSet timeout in seconds (default: 2)\n");
	printf("  --random\tNumber of random hosts to scan\n");
	printf("  --logfile\tRedirect output to specified log file\n");
}

typedef struct {
    bool help;
    bool ports;
    bool ip;
    bool file;
    bool speedup;
    bool scan;
    bool hide_ip;
    bool bypass_ids;
    bool os;
    bool version;
    bool timeout;
    bool random;
    bool logfile;
} t_used_flags;

bool parse_arguments(int argc, char **argv, t_scan_config *config) {
    int i = 1;
    t_used_flags used = {0};

    while (i < argc) {
        if (strcmp(argv[i], "--help") == 0) {
            if (used.help) {
                fprintf(stderr, "Error: --help flag can only be used once\n");
                return false;
            }
            used.help = true;
            print_help_menu();
            i++;
        } else if (strcmp(argv[i], "--hide-ip") == 0) {
            if (used.hide_ip) {
                fprintf(stderr, "Error: --hide-ip flag can only be used once\n");
                return false;
            }
            used.hide_ip = true;
            config->hide_source_ip = true;
            i++;
        } else if (strcmp(argv[i], "--bypass-ids") == 0) {
            if (used.bypass_ids) {
                fprintf(stderr, "Error: --bypass-ids flag can only be used once\n");
                return false;
            }
            used.bypass_ids = true;
            config->bypass_ids = true;
            i++;
        } else if (strcmp(argv[i], "--os") == 0) {
            if (used.os) {
                fprintf(stderr, "Error: --os flag can only be used once\n");
                return false;
            }
            used.os = true;
            config->os_detection = true;
            i++;
        } else if (strcmp(argv[i], "--version") == 0) {
            if (used.version) {
                fprintf(stderr, "Error: --version flag can only be used once\n");
                return false;
            }
            used.version = true;
            config->version_detection = true;
            i++;
        } else if (strcmp(argv[i], "--ports") == 0 ||
                   strcmp(argv[i], "--ip") == 0 ||
                   strcmp(argv[i], "--file") == 0 ||
                   strcmp(argv[i], "--speedup") == 0 ||
                   strcmp(argv[i], "--scan") == 0 ||
                   strcmp(argv[i], "--timeout") == 0 ||
                   strcmp(argv[i], "--random") == 0 ||
                   strcmp(argv[i], "--logfile") == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Missing argument for %s\n", argv[i]);
                return false;
            }

            if ((strcmp(argv[i], "--ports") == 0 && used.ports) ||
                (strcmp(argv[i], "--ip") == 0 && used.ip) ||
                (strcmp(argv[i], "--file") == 0 && used.file) ||
                (strcmp(argv[i], "--speedup") == 0 && used.speedup) ||
                (strcmp(argv[i], "--scan") == 0 && used.scan) ||
                (strcmp(argv[i], "--timeout") == 0 && used.timeout) ||
                (strcmp(argv[i], "--random") == 0 && used.random) ||
                (strcmp(argv[i], "--logfile") == 0 && used.logfile)) {
                fprintf(stderr, "Error: %s flag can only be used once\n", argv[i]);
                return false;
            }

            if (strcmp(argv[i], "--ports") == 0) {
                used.ports = true;
                if (!parse_ports(argv[i + 1], config)) return false;
            } else if (strcmp(argv[i], "--speedup") == 0) {
                used.speedup = true;
                if (!parse_speedup(argv[i + 1], config)) return false;
            } else if (strcmp(argv[i], "--scan") == 0) {
                used.scan = true;
                if (!parse_scan(argv[i + 1], config)) return false;
            } else if (strcmp(argv[i], "--ip") == 0) {
                used.ip = true;
                if (!parse_ips(argv[i + 1], config)) return false;
            } else if (strcmp(argv[i], "--file") == 0) {
                used.file = true;
                if (!parse_file(argv[i + 1], config)) return false;
            } else if (strcmp(argv[i], "--timeout") == 0) {
                used.timeout = true;
                if (!parse_timeout(argv[i + 1], config)) return false;
            } else if (strcmp(argv[i], "--random") == 0) {
                used.random = true;
                if (!parse_random(argv[i + 1], config)) return false;
            } else if (strcmp(argv[i], "--logfile") == 0) {
                used.logfile = true;
                config->logfile = strdup(argv[i + 1]);
            }

            i += 2;
        } else {
            fprintf(stderr, "Invalid flag: %s\n", argv[i]);
            return false;
        }
    }

    if (config->scan_types.syn == false && config->scan_types.null == false &&
        config->scan_types.fin == false && config->scan_types.xmas == false &&
        config->scan_types.ack == false && config->scan_types.udp == false) {
        config->scan_types.syn = true;
        config->scan_types.null = true;
        config->scan_types.ack = true;
        config->scan_types.fin = true;
        config->scan_types.xmas = true;
        config->scan_types.udp = true;
    }

    if (config->ports == NULL) {
        config->ports = malloc(sizeof(int) * 1024);
        for (int i = 0; i <= 1024; i++) {
            config->ports[i] = i + 1;
        }
        config->port_count = 1024;
    }

    return true;
}
