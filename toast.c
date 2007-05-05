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

int set_sock_nonblock(int fd)
{
    int flags = 1;

    if ( (flags = fcntl(fd, F_GETFL, 0)) < 0 ||
        fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("Could not set O_NONBLOCK");
        close(fd);
        return -1;
    }

    return 0;
}

void handle_event(int fd, short event, void *arg)
{
    struct event *ev = arg;
    struct sockaddr_in addr;
    socklen_t addrlen;
    int newfd;

    fprintf(stdout, "WHEEE!! %i\n", event);

    // if we're the server socket, it's a new conn.
    if (fd == l_socket) {
        if ( (newfd = accept(fd, (struct sockaddr *)&addr, &addrlen)) == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "interesting error blocking on accept. ignore?\n");
            } else if (errno == EMFILE) {
                fprintf(stderr, "Holy crap out of FDs!\n");
            } else {
                perror("Died on accept");
            }
        }
        fprintf(stdout, "Got new client sock %d\n", newfd);
        set_sock_nonblock(newfd);

        event_set(ev, newfd, EV_READ | EV_PERSIST, handle_event, ev);
        event_add(ev, NULL);
    }
}

int main (int argc, char **argv)
{
    struct event ev;
    struct sockaddr_in addr;
    int flags = 1;

    // Initialize the server socket. Nonblock/reuse/etc.

    if ( (l_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    set_sock_nonblock(l_socket);

    setsockopt(l_socket, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
    setsockopt(l_socket, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(5500);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(l_socket, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("binding server socket");
        close(l_socket);
        return -1;
    }

    if (listen(l_socket, 1024) == -1) {
        perror("setting listen on server socket");
        close(l_socket);
        return -1;
    }

    // Initialize the event system.
    event_init();

    event_set(&ev, l_socket, EV_READ | EV_PERSIST, handle_event, &ev);
    event_add(&ev, NULL);

    event_dispatch();

    return 0;
}
