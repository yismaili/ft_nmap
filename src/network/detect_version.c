#include "../../includes/ft_nmap.h"

char *detect_service_version(const char *ip_address, int port, int config_timeout) {
  int sockfd;
  struct sockaddr_in server_addr;
  char buffer[BUFFER_SIZE];

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    return strdup("Socket creation failed");
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, ip_address, &server_addr.sin_addr) <= 0) {
    close(sockfd);
    return strdup("Invalid IP address");
  }

  struct timeval timeout;
  timeout.tv_sec = config_timeout;
  timeout.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    close(sockfd);
    return strdup("Unknown");
  }

  const char *probes[] = {
      "GET / HTTP/1.0\r\n\r\n",
      "SSH-2.0-OpenSSH_8.2p1\r\n",
      "220\r\n",
      "EHLO nmap\r\n",
      "\x00",
      NULL
  };

  for (int i = 0; probes[i] != NULL; i++) {
      close(sockfd);
      sockfd = socket(AF_INET, SOCK_STREAM, 0);
      if (sockfd < 0) continue;

      if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return strdup("Unknown");
      }

      if (send(sockfd, probes[i], strlen(probes[i]), 0) < 0) {
          continue;
      }

      ssize_t bytes_read = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
      if (bytes_read > 0) {
          buffer[bytes_read] = '\0';
          
          if (strstr(buffer, "SSH-")) {
              char version[256];
              sscanf(buffer, "SSH-%*s %255[^\r\n]", version);
              return strdup(version);
          }
          if (strstr(buffer, "220")) {
              char *version_start = strstr(buffer, "220");
              if (version_start) {
                  version_start += strlen("220 ");
                  char *end = strchr(version_start, '\r');
                  if (end) *end = '\0';
                  return strdup(version_start);
              }
          }
          if (strstr(buffer, "HTTP/")) {
              char *server_header = strstr(buffer, "Server:");
              if (server_header) {
                  server_header += strlen("Server: ");
                  char *end = strchr(server_header, '\r');
                  if (end)
                      *end = '\0';
                  return strdup(server_header);
              } else {
                  char version_buffer[256];
                  char *end = strchr(buffer, '\r');
                  if (end)
                      *end = '\0';
                  snprintf(version_buffer, sizeof(version_buffer), "HTTP Server: %.242s", buffer);
                  return strdup(version_buffer);
              }
          } else {
              return strdup("Unknown");
          }
      }
  }

  return strdup("Unknown");
}
