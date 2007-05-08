/* Plaything C event server with scripting support */

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

/* libevent specifics */
#include <event.h>

/* Lua specifics */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define BUF_SIZE 1024

static int l_socket = 0; // server socket. duh :P
static struct lua_State *L; // global lua state.

typedef struct {
    int    fd;
    struct event ev;
    short  ev_flags; /* only way to be able to read current flags? */

    /* Dynamic boofers */
    char   *rbuf;
    int    rbufsize;
    int    read; /* bytes of buffer used */
    char   *wbuf;
    int    wbufsize;
    int    written; /* bytes of buffer used */
} conn;

/* MySQL protocol handler...
 * everything starts with 3 byte len, 1 byte seq.
 * can assume read at least 4 bytes before parsing. discover len once have 4
 * bytes. read until len is satisfied.
 * mind special case of > 16MB packets.
 * conn needs states enum for mysql protocol
 * need state machine for dealing with packet once buffered.
 */

/* Stub function. In the future, should set a flag to reload or dump stuff */
static void sig_hup(const int sig) {
    fprintf(stdout, "Got reload request.\n");
}

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

static int handle_accept(int fd)
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

static void handle_close(conn *c)
{
    event_del(&c->ev);
    close(c->fd);

    fprintf(stdout, "Closed connection for %d\n", c->fd);
    if (c->rbuf) free(c->rbuf);
    if (c->wbuf) free(c->wbuf);
    free(c);
}

/*static int handle_read(conn c*)
{
    for(;;) {
        // while bytes from read, pack into buffer. return when would block
    }
}*/

static void handle_event(int fd, short event, void *arg)
{
    conn *c = arg;
    conn *newc;
    int newfd, rbytes;
    char *resp = "Helllllllllooooooooo, nurse!\n";

    // if we're the server socket, it's a new conn.
    if (fd == l_socket) {
        /* FIXME : Move the rest of this shit to another function. */
        newfd = handle_accept(fd); /* error handling */
        fprintf(stdout, "Got new client sock %d\n", newfd);
        set_sock_nonblock(newfd);

        /* client typedef init should be its own function */
        newc = (conn *)malloc( sizeof(conn) ); /* error handling */
        newc->fd = newfd;
        newc->ev_flags = EV_READ | EV_PERSIST;
   
        /* Set up the buffers. */
        newc->rbuf     = 0;
        newc->wbuf     = 0;
        newc->rbufsize = BUF_SIZE;
        newc->wbufsize = BUF_SIZE;
        newc->read     = 0;
        newc->written  = 0;

        newc->rbuf = (char *)malloc( (size_t)newc->rbufsize );
        newc->wbuf = (char *)malloc( (size_t)newc->wbufsize );

        /* Cleaner way to do this? I guess not with C */
        if (newc->rbuf == 0 || newc->wbuf == 0) {
            if (newc->rbuf != 0) free(newc->rbuf);
            if (newc->wbuf != 0) free(newc->wbuf);
            free(newc);
            perror("Could not malloc()");
            return;
        }

        event_set(&newc->ev, newfd, newc->ev_flags, handle_event, (void *)newc);
        event_add(&newc->ev, NULL); /* error handling */
    } else {
        /* Client socket. */
        fprintf(stdout, "Got new client event on %d\n", fd);
        /* TESTING: Junk read */
        rbytes = read(fd, c->rbuf, 511);

        /* If signaled for reading and got zero bytes, close it up */
        if (rbytes == 0) {
            handle_close(c);
            return;
        } else if (rbytes == -1) {
            /* Why do these happen? :\ Don't fully understand. */
            /* FIXME : This is part of handle read. read until no more data */
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        }

        c->rbuf[rbytes] = '\0';
        fprintf(stdout, "Read from client: %s", c->rbuf);
        // memset(c->rbuf, 0, 512); /* clear buffer after read */

        write(fd, resp, strlen(resp));
    }
}

int main (int argc, char **argv)
{
    struct sockaddr_in addr;
    conn *listener;
    struct sigaction sa;
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

    /* Lets ignore SIGPIPE... sorry, just about yanking this from memcached.
     * I tried to use the manpages but it came out exactly the same :P
     */

    sa.sa_handler = SIG_IGN;
    sa.sa_flags   = 0;
    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(SIGPIPE, &sa, 0) == -1) {
        perror("Could not ignore SIGPIPE: sigaction");
        exit(-1);
    }

    signal(SIGHUP, sig_hup);

    /* Fire up LUA */

    L = lua_open();

    if (L == NULL) {
        fprintf(stderr, "Could not create lua state\n");
        exit(-1);
    }

    event_dispatch();

    return 0;
}
