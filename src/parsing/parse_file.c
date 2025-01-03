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

  char **new_targets = calloc(target_count + config->ip_count, sizeof(char *));
  if (!new_targets) {
    fprintf(stderr, "Memory allocation failed\n");
    fclose(fp);
    return false;
  }

  for (int i = 0; i < config->ip_count; i++) {
    new_targets[i] = config->target_ips[i];
  }
  if (config->target_ips) {
    free(config->target_ips);
  }

  rewind(fp);

  int idx = config->ip_count;
  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim_whitespace(line);
    char *resolved_ip = NULL;

    if (*trimmed == '\0' || *trimmed == '#')
      continue;

    if (is_valid_ipv4(trimmed)) {
      resolved_ip = strdup(trimmed);
    } else if (is_valid_hostname(trimmed)) {
      resolved_ip = resolve_dns(trimmed);
      if (resolved_ip == NULL) {
        printf("Error: Failed to resolve hostname '%s' at line %d\n", trimmed,
               line_number);
        for (int i = 0; i < idx; i++) {
          free(new_targets[i]);
        }
        free(new_targets);
        fclose(fp);
        return false;
      }
    }

    if (resolved_ip != NULL) {
      new_targets[idx] = resolved_ip;
      idx++;
    }
  }

  fclose(fp);
  config->target_ips = new_targets;
  config->ip_count = idx;
  return true;
}
