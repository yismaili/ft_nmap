#include "../../includes/ft_nmap.h"

char *resolve_dns(const char *hostname) {
  struct hostent *host = gethostbyname(hostname);
  if (host == NULL)
    return NULL;

  char *ip = malloc(16);
  inet_ntop(AF_INET, host->h_addr_list[0], ip, 16);
  return ip;
}
