
#include "../includes/scanner.h"

void retrieve_source_ip_address(t_context *ctx)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    // int dns_port = 53;

    struct sockaddr_in serv;

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    // serv.sin_port = htons(dns_port);
    // dummy conection with google server (DNS) to get local ip address
    if (connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) != 0)
    {
        printf("Failed to get local IP\n");
        cleanup_program(ctx->config, ctx);
	      exit (2);
    }


    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);

    if (getsockname(sock, (struct sockaddr*)&name, &namelen) != 0){
        printf("Failed to get local IP");
        cleanup_program(ctx->config, ctx);
        exit (2);
	}

    inet_ntop(AF_INET, &name.sin_addr, ctx->source_ip, INET_ADDRSTRLEN);
    // printf("The local port number is: %d\n", ntohs(name.sin_port));
    // printf("The local port number is: %s\n", ctx->source_ip);
    close(sock);
    // exit (2);
}

char *retrieve_network_interface(const char *ip_address)
{
    struct ifaddrs *ifaddr, *ifa;
    char addr[INET_ADDRSTRLEN];
    char *interface_name = NULL;

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL) 
          continue;
        if (ifa->ifa_addr->sa_family == AF_INET) 
        {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), addr, INET_ADDRSTRLEN);
            if (strcmp(addr, ip_address) == 0)
            {
                interface_name = strdup(ifa->ifa_name);
                freeifaddrs(ifaddr);
                return interface_name;
            }
        }
    }
    freeifaddrs(ifaddr);
    return NULL;
}
