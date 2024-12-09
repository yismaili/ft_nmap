#include "../../includes/scanner.h"

unsigned short calculate_checksum(unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

typedef struct {
  const char *name;
  int initial_ttl;
  int tcp_window_size;
  int ip_id_sequence;
} OSFingerprint;

OSFingerprint os_signatures[] = {
    {"Linux 2.6.x", 64, 5840, 1},   {"Windows 10/11", 128, 64240, 2},
    {"macOS Sonoma", 64, 65535, 3}, {"FreeBSD 13.x", 64, 65535, 4},
    {"OpenBSD 7.x", 64, 16384, 5},
};

const char *detect_os(const char *target, int config_timeout) {
  int signatures_count = sizeof(os_signatures) / sizeof(OSFingerprint);
  struct sockaddr_in dest;
  char buffer[65536];
  int one = 1;
  char source_ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifaddr, *ifa;
  int source_ip_found = 0;

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs failed");
    return "Unknown";
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
      continue;

    struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
    if (inet_ntop(AF_INET, &addr->sin_addr, source_ip, INET_ADDRSTRLEN) !=
            NULL &&
        strcmp(source_ip, "127.0.0.1") != 0) {
      source_ip_found = 1;
      break;
    }
  }

  if (!source_ip_found) {
    freeifaddrs(ifaddr);
    return "Unknown";
  }

  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock < 0) {
    perror("Socket creation failed");
    return "Unknown";
  }

  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("Failed to set IP_HDRINCL");
    close(sock);
    return "Unknown";
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
    perror("Failed to set SO_REUSEADDR");
    close(sock);
    return "Unknown";
  }

  struct timeval timeout;
  timeout.tv_sec = config_timeout;
  timeout.tv_usec = 0;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) <
      0) {
    perror("Failed to set receive timeout");
    close(sock);
    return "Unknown";
  }

  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr(target);
  dest.sin_port = htons(80);

  char packet[4096];
  struct iphdr *ip = (struct iphdr *)packet;
  struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

  memset(packet, 0, sizeof(packet));

  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
  ip->id = htons(54321);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  ip->check = 0;
  ip->saddr = inet_addr(source_ip);
  ip->daddr = dest.sin_addr.s_addr;

  tcp->source = htons(12345);
  tcp->dest = htons(80);
  tcp->seq = htonl(rand());
  tcp->ack_seq = 0;
  tcp->doff = 5;
  tcp->syn = 1;
  tcp->window = htons(5840);
  tcp->check = 0;
  tcp->urg_ptr = 0;

  ip->check = calculate_checksum((unsigned short *)packet, ip->ihl * 4);

  struct {
    int ttl;
    int window_size;
    int ip_id_seq;
  } probe_results = {0};

  int probe_count = 3;
  for (int p = 0; p < probe_count; p++) {
    if (sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *)&dest,
               sizeof(dest)) < 0) {
      perror("Failed to send packet");
      continue;
    }

    usleep(100000);

    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                  (struct sockaddr *)&from, &fromlen);

    if (bytes_received > 0) {
      struct iphdr *resp_ip = (struct iphdr *)buffer;
      struct tcphdr *resp_tcp = (struct tcphdr *)(buffer + (resp_ip->ihl * 4));

      probe_results.ttl = resp_ip->ttl;
      probe_results.window_size = ntohs(resp_tcp->window);
      probe_results.ip_id_seq = ntohs(resp_ip->id);
      break;
    }
  }

  close(sock);

  int best_match_index = -1;
  int best_match_score = 0;

  for (int i = 0; i < signatures_count; i++) {
    int score = 0;
    if (abs(probe_results.ttl - os_signatures[i].initial_ttl) <= 16)
      score += 2;
    if (abs(probe_results.window_size - os_signatures[i].tcp_window_size) <=
        512)
      score += 3;
    if (probe_results.ip_id_seq == os_signatures[i].ip_id_sequence)
      score += 1;

    if (score > best_match_score) {
      best_match_score = score;
      best_match_index = i;
    }
  }

  if (best_match_score >= 4 && best_match_index >= 0) {
    return os_signatures[best_match_index].name;
  }

  return "Unknown OS";
}
