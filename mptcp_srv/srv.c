#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/tcp.h>     // TCP_IS_MPTCP (from UAPI)
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TCP_IS_MPTCP 43
#define SOL_TCP		6


int main(void){
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    if (s < 0) { perror("socket(IPPROTO_MPTCP)"); return 1; }

    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family=AF_INET, .sin_port=htons(8080), .sin_addr={htonl(INADDR_ANY)} };
    if (bind(s,(struct sockaddr*)&a,sizeof(a))<0 || listen(s,16)<0){ perror("bind/listen"); return 1; }

    for(;;){
        int c = accept(s, NULL, NULL);
        if (c < 0) { perror("accept"); return 1; }
        const char *msg = "hello\n"; send(c, msg, strlen(msg), 0);
        close(c);
    }
}


