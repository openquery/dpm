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

#define BUF_SIZE 2048

/* Test pass-through variables. */
#define MY_SERVER "127.0.0.1"
#define MY_PORT 3306

/* MySQL protocol states */
enum myproto_states {
    my_waiting, /* Waiting for a new request to start */
    my_reading, /* Reading into a packet */
    my_proxy,   /* Write while reading, through end of packet */
    my_process, /* Processing a loaded packet */
    my_connect, /* Attempting to connect to a remote socket */
};

/* Structs...
 * FIXME: Header file? */
typedef struct {
    int    fd;

    struct event ev;
    short  ev_flags; /* only way to be able to read current flags? */

    /* Dynamic boofers */
    unsigned char   *rbuf;
    int    rbufsize;
    int    read; /* bytes of buffer used */
    int    readto; /* Bytes consumed */
    unsigned char   *wbuf;
    int    wbufsize;
    int    written; /* bytes of buffer used */
    int    towrite; /* end bytelength of write buffer. */

    /* mysql protocol specific junk */ 
    int    mystate;
    int packetsize;

    /* Proxy references. */
    struct conn *remote;
} conn;

/* Declarations */
static void sig_hup(const int sig);
int set_sock_nonblock(int fd);
static int handle_accept(int fd);
static void handle_close(conn *c);
static int handle_read(conn *c);
static conn *init_conn(int newfd);
static void handle_event(int fd, short event, void *arg);
static int add_conn_event(conn *c, const int new_flags);
static int del_conn_event(conn *c, const int new_flags);
static int update_conn_event(conn *c, const int new_flags);
static void run_protocol(conn *c, int read, int written);
static int my_next_packet_start(conn *c);
static void my_consume_header(conn *c);
static int grow_write_buffer(conn *c, int newsize);

/* Icky ewwy global vars. */

static int l_socket = 0; // server socket. duh :P
static struct lua_State *L; // global lua state.

/* Test outbound connection function */
static conn *test_outbound()
{
    int outsock;
    conn *c;
    struct sockaddr_in dest_addr;
    int flags = 1;

    fprintf(stdout, "Attempting outbound socket request\n");

    outsock = socket(AF_INET, SOCK_STREAM, 0); /* check errors */

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(MY_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(MY_SERVER);

    set_sock_nonblock(outsock); /* check errors */

    memset(&(dest_addr.sin_zero), '\0', 8);

    setsockopt(outsock, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

    /* Lets try a nonblocking connect... */
    if (connect(outsock, (const struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
        if (errno != EINPROGRESS) {
            perror("Outbound socket goofup");
            exit(-1);
        }
    }

    c = init_conn(outsock);

    /* Special state for outbound requests. */
    c->mystate = my_connect;

    /* We watch for a write to this guy to see if it succeeds */
    add_conn_event(c, EV_WRITE);

    fprintf(stdout, "Good so far. Outbound sock is init'ed and waiting\n");

    return c;
}

/* Stub function. In the future, should set a flag to reload or dump stuff */
static void sig_hup(const int sig)
{
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

static int add_conn_event(conn *c, const int new_flags)
{
    int ret;
    ret = update_conn_event(c, c->ev_flags | new_flags);
    return ret;
}

/* FIXME: Logic is wrong */
static int del_conn_event(conn *c, const int new_flags)
{
    int ret;
    ret = update_conn_event(c, c->ev_flags & new_flags);
    return ret;
}

static int update_conn_event(conn *c, const int new_flags)
{
    if (c->ev_flags == new_flags) return 1;
    if (event_del(&c->ev) == -1) return 0;

    c->ev_flags = new_flags;
    event_set(&c->ev, c->fd, new_flags, handle_event, (void *)c);

    if (event_add(&c->ev, 0) == -1) return 0;
    return 1;
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
    c = NULL;
}

/* Generic "Grow my write buffer" function. */
static int grow_write_buffer(conn *c, int newsize)
{
    unsigned char *new_wbuf;
    if (c->wbufsize < newsize) {
        fprintf(stdout, "Reallocating write buffer from %d to %d\n", c->wbufsize, c->wbufsize * 2);
        new_wbuf = realloc(c->wbuf, c->wbufsize * 2);

        if (new_wbuf == NULL) {
            perror("Realloc output buffer");
            return -1;
        }

        c->wbuf = new_wbuf;
        c->wbufsize *= 2;
    }

    return 0;
}

/* handle buffering writes... we're looking for EAGAIN until we stop
 * transmitting.
 * We're assuming the write data was pre-populated.
 * NOTE: Need to support changes in written between calls
 */
static int handle_write(conn *c)
{
    int wbytes;
    int written = 0;

    /* Short circuit for outbound connections. */
    if (c->towrite < 1) {
        return written;
    }

    for(;;) {
        /* FIXME: Should we clear the EV_WRITE flag? */
        if (c->written >= c->towrite) {
            fprintf(stdout, "Finished writing out (%d) bytes to %d\n", c->written, c->fd);
            c->mystate = my_waiting;
            c->written = 0;
            c->towrite = 0;
            update_conn_event(c, EV_READ | EV_PERSIST);
            break;
        }

        wbytes = send(c->fd, c->wbuf + c->written, c->towrite - c->written, 0);

        if (wbytes == 0) {
            handle_close(c);
            return -1;
        } else if (wbytes == -1 ) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (add_conn_event(c, EV_WRITE) == 0) {
                    fprintf(stderr, "Couldn't add write watch to %d", c->fd);
                    handle_close(c);
                }
            } else {
                handle_close(c);
                return -1;
            }
        }

        c->written += wbytes;
        written    += wbytes;
    }

    return written;
}

/* Handle buffered read events. Read into the buffer until we would block.
 * returns the total number of bytes read in the session. */
static int handle_read(conn *c)
{
    int rbytes;
    int newdata = 0;
    unsigned char *new_rbuf;

    for(;;) {
        /* We're in trouble if read is larger than rbufsize, right? ;) 
         * Anyhoo, if so, we want to realloc up the buffer.
         * TODO: Share buffers so we don't realloc so often... */
        if (c->read >= c->rbufsize) {
            /* I'd prefer 1.5... */
            fprintf(stdout, "Reallocing input buffer from %d to %d\n",
                    c->rbufsize, c->rbufsize * 2);
            new_rbuf = realloc(c->rbuf, c->rbufsize * 2);

            if (new_rbuf == NULL) {
                perror("Realloc input buffer");
                /* FIXME: Should tell user we're abanonding ship. */
                handle_close(c);
                return -1;
            }

            /* The start of the new buffer might've changed: realloc(2) */
            c->rbuf = new_rbuf;
            c->rbufsize *= 2;
        }

        // while bytes from read, pack into buffer. return when would block
        rbytes = read(c->fd, c->rbuf + c->read, c->rbufsize - c->read);

        /* If signaled for reading and got zero bytes, close it up 
         * FIXME : Should we flush the command? */
        if (rbytes == 0) {
            handle_close(c);
            return -1;
        } else if (rbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                handle_close(c);
                return -1;
            }
        }

        /* Successfuly read. Mark our progress */
        c->read += rbytes;
        newdata += rbytes;
    }

    /* Allows caller to arbitrarily measure progress, since we use a binary
     * protocol. "Did we get enough bytes to satisfy len? No? Yawn. Nap."
     */
    return newdata;
}

static conn *init_conn(int newfd)
{
    conn *newc;

    /* client typedef init should be its own function */
    newc = (conn *)malloc( sizeof(conn) ); /* error handling */
    newc->fd = newfd;
    newc->ev_flags = EV_READ | EV_PERSIST;
    newc->mystate = my_waiting;  

    /* Set up the buffers. */
    newc->rbuf     = 0;
    newc->wbuf     = 0;
    newc->rbufsize = BUF_SIZE;
    newc->wbufsize = BUF_SIZE;
    newc->read     = 0;
    newc->written  = 0;

    newc->rbuf = (unsigned char *)malloc( (size_t)newc->rbufsize );
    newc->wbuf = (unsigned char *)malloc( (size_t)newc->wbufsize );

    /* Cleaner way to do this? I guess not with C */
    if (newc->rbuf == 0 || newc->wbuf == 0) {
        if (newc->rbuf != 0) free(newc->rbuf);
        if (newc->wbuf != 0) free(newc->wbuf);
        free(newc);
        perror("Could not malloc()");
        return NULL;
    }

    newc->remote  = NULL;

    event_set(&newc->ev, newfd, newc->ev_flags, handle_event, (void *)newc);
    event_add(&newc->ev, NULL); /* error handling */

    fprintf(stdout, "Made new conn structure for %d\n", newfd);

    return newc;
}

static void handle_event(int fd, short event, void *arg)
{
    conn *c = arg;
    conn *newc = NULL;
    conn *newback = NULL;
    int newfd, rbytes, wbytes;
    int flags = 1;

    /* if we're the server socket, it's a new conn */
    if (fd == l_socket) {
        newfd = handle_accept(fd); /* error handling */
        fprintf(stdout, "Got new client sock %d\n", newfd);

        set_sock_nonblock(newfd); /* error handling on this and below */
        setsockopt(newfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
        newc = init_conn(newfd);

        if (newc == NULL) {
            return;
        }

        /* For every incoming socket, lets create a backend sock. */
        newback = test_outbound();

        /* If we couldn't get a backend, we must close the client. */
        if (newback == NULL) {
            handle_close(newc);
            return;
        }

        newc->remote = newback;

        /* Weird association. Makes sure the backend can get back to us
         * clients.
         * FIXME: This'll need cleaning up code.
         */
        newback->remote = newc;
        return;
   }
   
   if (event & EV_READ) {
        /* Client socket. */
        fprintf(stdout, "Got new read event on %d\n", fd);

        rbytes = handle_read(c);
        /* FIXME : Should we do the error handling at this level? Or lower? */
        if (rbytes < 0) return;

        fprintf(stdout, "Read (%d) from sock\n", rbytes);

        /*c->written = 0;
        memcpy(c->wbuf, resp, strlen(resp));
        c->towrite = strlen(resp);
        wbytes = handle_write(c);*/
    }

    if (event & EV_WRITE) {
        fprintf(stdout, "Got new write event on %d\n", fd);
     
        wbytes = handle_write(c);
    }

    /* Socket might be dead by this point... Don't even bother. */
    if (c) {
        run_protocol(c, rbytes, wbytes);
    }
}

/* MySQL protocol handler...
 * everything starts with 3 byte len, 1 byte seq.
 * can assume read at least 4 bytes before parsing. discover len once have 4
 * bytes. read until len is satisfied.
 * mind special case of > 16MB packets.
 * conn needs states enum for mysql protocol
 * need state machine for dealing with packet once buffered.
 */

/* Consume the next mysql protocol length + seq header out of the buffer. */
static void my_consume_header(conn *c)
{
    int base = 0;
    base = c->readto;
    c->packetsize = (c->rbuf[base]) | (c->rbuf[base + 1] << 8) | (c->rbuf[base + 2] << 16);
    c->packetsize += 4; /* Add in the original header len */
}

/* If we're ready to send the next packet along, prep the header and
 * return the starting position. */
static int my_next_packet_start(conn *c)
{
    if (c->readto == c->read) {
        return -1;
    }
    my_consume_header(c);
    if (c->read >= c->packetsize) {
        return c->readto;
    }
    return -1;
}

/* Run the "MySQL" protocol on a socket. Generic state machine logic.
 * Would've loved to use Ragel, but it doesn't make sense here.
 */
static void run_protocol(conn *c, int read, int written)
{
    int finished = 0;
    int err = 0;
    int next_packet;
    socklen_t errsize = sizeof(err);
    conn *remote = NULL;

    fprintf(stdout, "Running protocol state machine\n");

    while (!finished) {
        switch(c->mystate) {
        case my_connect:
            /* Socket was connecting. Lets see if it's good now. */
            if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &errsize) < 0) {
                perror("Running getsockopt on outbound connect");
                handle_close(c);
                break;
            }
            if (err != 0) {
                fprintf(stderr, "Error in connecting outbound socket\n");
                handle_close(c);
                break;
            }

            /* Neat. we're all good. */
            fprintf(stdout, "Successfully connected outbound socket %d\n", c->fd);
            update_conn_event(c, EV_READ | EV_PERSIST);
            c->mystate = my_waiting;
        case my_waiting:
            /* When in a waiting state, we need to read four bytes to get
             * the packet length and packet number. */
            if (c->read > 3) {
                fprintf(stdout, "Looks like we have a packet. Start reading\n");
                c->mystate = my_reading;
            } else if (c->packetsize == 0) {
                break;
            }
            /* Fall through if we're expecting a packet. */
        case my_reading:
            /* If we've read the full packet size, we can write it to the
             * other guy
             * FIXME: Making assumptions about remote, duh :P
             */
            remote = (conn *)c->remote;

            while ( (next_packet = my_next_packet_start(c)) != -1 ) {
                fprintf(stdout, "Set to read from %d packet size %u.\n", c->fd, c->packetsize);
                /* Buffered up all pending packet reads. Write out to remote */
                if (grow_write_buffer(remote, remote->towrite + c->packetsize) == -1) {
                    handle_close(remote);
                    handle_close(c);
                    break;
                }
                memcpy(remote->wbuf + remote->towrite, c->rbuf + next_packet, c->packetsize);
                remote->towrite += c->packetsize;

                /* Copied in the packet; advance to next packet. */
                c->readto += c->packetsize;
            }
            if (c == NULL) {
                break;
            }
            handle_write(remote);

            /* Any pending packet reads? If so, reset boofer. */
            if (c->readto == c->read) {
                fprintf(stdout, "Resetting read buffer\n");
                c->read    = 0;
                c->readto  = 0;
                c->mystate = my_waiting;
            }
            break;
        }
        finished++;
    }
}

int main (int argc, char **argv)
{
    struct sockaddr_in addr;
    conn *listener;
    struct sigaction sa;
    int flags = 1;

    fprintf(stdout, "Starting up...\n");
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

    fprintf(stdout, "Initializing Lua...\n");

    /* Fire up LUA */

    L = lua_open();

    if (L == NULL) {
        fprintf(stderr, "Could not create lua state\n");
        exit(-1);
    }

    fprintf(stdout, "Starting event dispatcher...\n");

    event_dispatch();

    return 0;
}
