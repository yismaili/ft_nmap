#include "../../includes/ft_nmap.h"

char *trim_whitespace(char *str) {
    char *end;

    while (isspace(*str)) {
        str++;
    }

    if (*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) {
        end--;
    }

    *(end + 1) = 0;

    return str;
}

bool parse_file(char *filename, t_scan_config *config) {
    FILE *fp;
    char line[256];
    int target_count = 0;
    char **targets;
    int line_number = 0;

    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open file '%s'\n", filename);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        line_number++;
        char *trimmed = trim_whitespace(line);
        
        if (*trimmed == '\0' || *trimmed == '#')
            continue;

        if (!is_valid_ipv4(trimmed) && !is_valid_hostname(trimmed)) {
            printf("Error: Invalid target '%s' at line %d\n", trimmed, line_number);
            fclose(fp);
            return false;
        }
        target_count++;
    }

    if (target_count == 0) {
        fprintf(stderr, "Error: No valid targets found in file '%s'\n", filename);
        fclose(fp);
        return false;
    }

    targets = calloc(target_count, sizeof(char*));
    if (!targets) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(fp);
        return false;
    }

    rewind(fp);
    int idx = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim_whitespace(line);
        
        if (*trimmed && *trimmed != '#' && 
            (is_valid_ipv4(trimmed) || is_valid_hostname(trimmed))) {
            targets[idx] = strdup(trimmed);
            if (!targets[idx]) {
                for (int i = 0; i < idx; i++) {
                    free(targets[i]);
                }
                free(targets);
                fclose(fp);
                fprintf(stderr, "Memory allocation failed\n");
                return false;
            }
            idx++;
        }
    }

    fclose(fp);

    config->target_ips = targets;
    config->ip_count = target_count;

    return true;
}
