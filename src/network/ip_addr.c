
#include "../includes/scanner.h"

void retrieve_local_ip_address(t_context *ctx)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(dns_port);

    if (connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) != 0){
        printf("Failed to get local IP\n");
	exit (2);
    }


    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);

    if (getsockname(sock, (struct sockaddr*)&name, &namelen) != 0){
        printf("Failed to get local IP");
    	exit (2);
	}

    inet_ntop(AF_INET, &name.sin_addr, ctx->local_ip, INET6_ADDRSTRLEN);

    close(sock);
}

