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

static int l_socket = 0; // server socket. duh :P

typedef struct {
    int    fd;
    struct event ev;
    short  ev_flags; /* only way to be able to read current flags? */

    /* FIXME : Dynamic buffers. */
    char   rbuf[500];
    int    read; /* bytes of buffer used */
    char   wbuf[500];
    int    write; /* bytes of buffer used */
} conn;

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

int handle_accept(int fd)
{
    struct sockaddr_in addr;
    socklen_t addrlen;
    int newfd;

    if ( (newfd = accept(fd, (struct sockaddr *)&addr, &addrlen)) == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "interesting error blocking on accept. ignore?\n");
        } else if (errno == EMFILE) {
            fprintf(stderr, "Holy crap out of FDs!\n");
        } else {
            perror("Died on accept");
        }
    }

    return newfd;
}

void handle_event(int fd, short event, void *arg)
{
    conn *c = arg;
    conn *newc;
    int newfd;

    // if we're the server socket, it's a new conn.
    if (fd == l_socket) {
        newfd = handle_accept(fd); /* error handling */
        fprintf(stdout, "Got new client sock %d\n", newfd);
        set_sock_nonblock(newfd);

        /* client typedef init should be its own function */
        newc = (conn *)malloc( sizeof(conn) ); /* error handling */
        newc->fd = newfd;
        newc->ev_flags = EV_READ | EV_PERSIST;
        event_set(&newc->ev, newfd, newc->ev_flags, handle_event, (void *)newc);
        event_add(&newc->ev, NULL); /* error handling */

    } else {
        /* Client socket. */
        fprintf(stdout, "Got new client event on %d\n", fd);
        /* TESTING: Junk read */
        read(fd, c->rbuf, 512);
        fprintf(stdout, "Read from client: %s", c->rbuf);
    }
}

int main (int argc, char **argv)
{
    struct sockaddr_in addr;
    conn *listener;
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

    listener = (conn *)malloc( sizeof(conn) ); /* error handling */

    listener->ev_flags = EV_READ | EV_PERSIST;

    // Initialize the event system.
    event_init();

    event_set(&listener->ev, l_socket, listener->ev_flags, handle_event, (void *)listener);
    event_add(&listener->ev, NULL);

    event_dispatch();

    return 0;
}
