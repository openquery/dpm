/* ME MAN PLAY WITH STUFF! */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <event.h>

static int l_socket = 0;

int main (int argc, char **argv)
{
    struct event ev;
    struct sockaddr_in addr;
    int flags;

    if ( (l_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    if ( (flags = fcntl(l_socket, l_socket, F_GETFL, 0)) < 0 ||
        fcntl(l_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("couldn't set O_NONBLOCK");
        close(l_socket);
        return -1;
    }

    flags = 1;
    setsockopt(l_socket, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
    setsockopt(l_socket, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(5500);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(l_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("binding server socket");
        close(l_socket);
        return -1;
    }

    if (listen(l_socket, 1024) == -1) {
        perror("setting listen on server socket");
        close(l_socket);
        return -1;
    }

    return 0;
}
