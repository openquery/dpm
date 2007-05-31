/* Plaything C event server with scripting support */

/* Internal headers */
#include "proxy.h"
#include "sha1.h"
#include "luaobj.h"

/* Internal defines */

#undef DBUG_STATE

#define BUF_SIZE 2048

/* Test pass-through variables. */
#define MY_SERVER "127.0.0.1"
#define MY_PORT 3306

const char *my_state_name[]={
    "Server connect", "Client connect", "Server sent handshake", "Client wait ha ndshake", "Client waiting", "Server Waiting", "Client sent command", "Server sen ding fields", "Server sending rows", "Server waiting auth", "Server sending OK", "Server waiting command", "Server sending resultset", "Client waiting auth", "S erver sending handshake",
};

struct lua_State *L;

/* Declarations */
static void sig_hup(const int sig);
int set_sock_nonblock(int fd);
static int handle_accept(int fd);
static void handle_close(conn *c);
static int handle_read(conn *c);
static int handle_write(conn *c);
static conn *init_conn(int newfd);
static void handle_event(int fd, short event, void *arg);
static int add_conn_event(conn *c, const int new_flags);
//static int del_conn_event(conn *c, const int new_flags);
static int update_conn_event(conn *c, const int new_flags);
static int run_protocol(conn *c, int read, int written);

static int my_next_packet_start(conn *c);
static void my_consume_header(conn *c);
static int grow_write_buffer(conn *c, int newsize);
static int sent_packet(conn *c, void **p, int ptype, int field_count);
static int received_packet(conn *c, void **p, int *ptype, int field_count);

static my_handshake_packet *my_consume_handshake_packet(conn *c);
static my_auth_packet *my_consume_auth_packet(conn *c);
static my_ok_packet *my_consume_ok_packet(conn *c);
static my_err_packet *my_consume_err_packet(conn *c);
static my_cmd_packet *my_consume_cmd_packet(conn *c);
static my_rset_packet *my_consume_rset_packet(conn *c);
static my_field_packet *my_consume_field_packet(conn *c);
static int my_consume_row_packet(conn *c);
static my_eof_packet *my_consume_eof_packet(conn *c);
static uint64_t my_read_binary_field(unsigned char *buf, int *base);
static uint8_t my_char_val(uint8_t X);
static void my_hex2octet(uint8_t *dst, const char *src, unsigned int len);
static void my_crypt(char *dst, const unsigned char *s1, const unsigned char *s2, uint len);
static void my_scramble(unsigned char *dst, const unsigned char *random, const char *pass);
static int my_check_scramble(const unsigned char *remote_scram, const unsigned char *random, const char *stored_hash);

/* Lua related forward declarations. */
static int new_listener(lua_State *L);
static int run_lua_callback(conn *c, int nargs);

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
/*static int del_conn_event(conn *c, const int new_flags)
{
    int ret;
    ret = update_conn_event(c, c->ev_flags & ~new_flags);
    return ret;
}*/

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
    conn *remote;
    assert(c != 0);
    event_del(&c->ev);

    if (c->remote) {
        remote = (conn *)c->remote;
        remote->remote = NULL;
        handle_close(remote);
    }

    close(c->fd);
    fprintf(stdout, "Closed connection for %u\n", c->fd);
    if (c->rbuf) free(c->rbuf);
    if (c->wbuf) free(c->wbuf);
    free(c);
    c = 0;
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
        if (c->written >= c->towrite) {
            //fprintf(stdout, "Finished writing out (%d) bytes to %d\n", c->written, c->fd);
            c->mystate = my_waiting;
            c->written = 0;
            c->towrite = 0;
            update_conn_event(c, EV_READ | EV_PERSIST);
            break;
        }

        wbytes = send(c->fd, c->wbuf + c->written, c->towrite - c->written, 0);

        if (wbytes == 0) {
            return -1;
        } else if (wbytes == -1 ) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (add_conn_event(c, EV_WRITE) == 0) {
                    fprintf(stderr, "Couldn't add write watch to %d", c->fd);
                    return -1;
                }
            } else {
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
            return -1;
        } else if (rbytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
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
    static int my_connection_counter = 1; /* NOTE: Not positive if this should be global or not */

    /* client typedef init should be its own function */
    newc = (conn *)malloc( sizeof(conn) ); /* error handling */
    newc->fd = newfd;
    newc->id = my_connection_counter++;
    newc->ev_flags = EV_READ | EV_PERSIST;
    newc->mystate = my_waiting;
    newc->mypstate = my_waiting;
    newc->my_type = 0;

    /* Set up the buffers. */
    newc->rbuf     = 0;
    newc->wbuf     = 0;
    newc->rbufsize = BUF_SIZE;
    newc->wbufsize = BUF_SIZE;
    newc->read     = 0;
    newc->written  = 0;
    newc->readto   = 0;
    newc->towrite  = 0;
    newc->listener = 0;

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
    int err   = 0;

    /* if we're the server socket, it's a new conn */
    if (c->listener) {
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

        newc->remote = (struct conn *)newback;

        /* Weird association. Makes sure the backend can get back to us
         * clients.
         * FIXME: This'll need cleaning up code.
         */
        newback->remote = (struct conn *)newc;

        newc->mypstate  = myc_wait_handshake;
        newc->my_type   = my_client;
        
        /* Pass the object up into lua for later inspection. */
        new_obj(L, newc, "myp.conn");

        c->mypstate = myc_connect;
        run_lua_callback(c, 1);
        return;
   }
   
   if (event & EV_READ) {
        /* Client socket. */
        fprintf(stdout, "Got new read event on %d\n", fd);

        rbytes = handle_read(c);
        /* FIXME : Should we do the error handling at this level? Or lower? */
        if (rbytes < 0) {
            handle_close(c);
            return;
        }

        //fprintf(stdout, "Read (%d) from sock\n", rbytes);
    }

    if (event & EV_WRITE) {
        fprintf(stdout, "Got new write event on %d\n", fd);
        if (c->mystate != my_connect) {
          wbytes = handle_write(c);

          if (wbytes < 0) {
              handle_close(c);
              return;
          }
        }
    }

    err = run_protocol(c, rbytes, wbytes);
    if (err == -1) {
        handle_close(c);
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

/* Read a length encoded binary field into a uint64_t */
static uint64_t my_read_binary_field(unsigned char *buf, int *base)
{
    uint64_t ret = 0;

    if (buf[*base] < 251) {
        (*base)++;
        return (uint64_t) buf[*base - 1];
    }

    (*base)++;
    switch (buf[*base]) {
        case 251:
            /* FIXME: Handling NULL case correctly? */
            (*base)++;
            return (uint64_t) ~0;
        case 252:
            memcpy(&ret, &buf[*base], 2);
            (*base) += 2;
            break;
        case 253:
            /* NOTE: Docs say this is 32-bit. libmysqlnd says 24-bit? */
            memcpy(&ret, &buf[*base], 4);
            (*base) += 4;
            break;
        case 254:
            memcpy(&ret, &buf[*base], 8);
            (*base) += 8;
    }

    return ret;
}

/* Mostly from sql/password.c in mysqld */
static uint8_t my_char_val(uint8_t X)
{
  return (unsigned int) (X >= '0' && X <= '9' ? X-'0' :
      X >= 'A' && X <= 'Z' ? X-'A'+10 : X-'a'+10);
}

static void my_hex2octet(uint8_t *dst, const char *src, unsigned int len)
{   
  const char *str_end= src + len;
  while (src < str_end) {
      char tmp = my_char_val(*src++);
      *dst++ = (tmp << 4) | my_char_val(*src++);
  }
}

static void my_crypt(char *dst, const unsigned char *s1, const unsigned char *s2, uint len)
{
  const uint8_t *s1_end= s1 + len;
  while (s1 < s1_end)
    *dst++= *s1++ ^ *s2++;
}
/* End. */

/* Client scramble
 * random is 20 byte random scramble from the server.
 * pass is plaintext password supplied from client
 * dst is a 20 byte buffer to receive the jumbled mess. */
static void my_scramble(unsigned char *dst, const unsigned char *random, const char *pass)
{
    struct sha1_ctx context;
    uint8_t hash1[SHA1_DIGEST_SIZE];
    uint8_t hash2[SHA1_DIGEST_SIZE];

    /* First hash the password. */
    sha1_init(&context);
    sha1_update(&context, strlen(pass), (const uint8_t *) pass);
    sha1_final(&context);
    sha1_digest(&context, SHA1_DIGEST_SIZE, hash1);

    /* Second, hash the hash. */
    sha1_init(&context);
    sha1_update(&context, SHA1_DIGEST_SIZE, hash1);
    sha1_final(&context);
    sha1_digest(&context, SHA1_DIGEST_SIZE, hash2);

    /* Now we have the equivalent of SELECT PASSWORD('whatever') */
    /* Now SHA1 the random message against hash2, then xor it against hash1 */
    sha1_init(&context);
    sha1_update(&context, SHA1_DIGEST_SIZE, (const uint8_t *) random);
    sha1_update(&context, SHA1_DIGEST_SIZE, hash2);
    sha1_final(&context);
    sha1_digest(&context, SHA1_DIGEST_SIZE, (uint8_t *) dst);

    my_crypt((char *)dst, (const unsigned char *) dst, hash1, SHA1_DIGEST_SIZE);

    /* The sha1 context has temporary data that needs to disappear. */
    memset(&context, 0, sizeof(struct sha1_ctx));
}

/* Server side check. */
static int my_check_scramble(const unsigned char *remote_scram, const unsigned char *random, const char *stored_hash)
{
    uint8_t pass_hash[SHA1_DIGEST_SIZE];
    uint8_t rand_hash[SHA1_DIGEST_SIZE];
    uint8_t pass_orig[SHA1_DIGEST_SIZE];
    uint8_t pass_check[SHA1_DIGEST_SIZE];
    struct sha1_ctx context;

    /* Parse string into bytes... */
    my_hex2octet(pass_hash, stored_hash, strlen(stored_hash));

    /* Muck up our view of the password against our original random num */
    sha1_init(&context);
    sha1_update(&context, SHA1_DIGEST_SIZE, (const uint8_t *) random);
    sha1_update(&context, SHA1_DIGEST_SIZE, pass_hash);
    sha1_final(&context);
    sha1_digest(&context, SHA1_DIGEST_SIZE, rand_hash);

    /* Pull out the client sha1 */
    my_crypt((char *) pass_orig, (const unsigned char *) rand_hash, (const unsigned char *) remote_scram, SHA1_DIGEST_SIZE);

    /* Update it to be more like our own */
    sha1_init(&context);
    sha1_update(&context, SHA1_DIGEST_SIZE, pass_orig);
    sha1_final(&context);
    sha1_digest(&context, SHA1_DIGEST_SIZE, pass_check);
    memset(&context, 0, sizeof(struct sha1_ctx));

    /* Compare */
    return memcmp(pass_hash, pass_check, SHA1_DIGEST_SIZE);
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

/* Consume the next mysql protocol length + seq header out of the buffer. */
static void my_consume_header(conn *c)
{
    int base = 0;
    base = c->readto;
    c->packetsize = (c->rbuf[base]) | (c->rbuf[base + 1] << 8) | (c->rbuf[base + 2] << 16);
    c->packetsize += 4; /* Add in the original header len */
}

/* FIXME: If we have the second scramblebuff, it needs to be assembled
 * into a single line for processing.
 */
static my_handshake_packet *my_consume_handshake_packet(conn *c)
{
    my_handshake_packet *p;
    int base = c->readto + 4;
    size_t my_size = 0;

    /* Clear out the struct. */
    p = (my_handshake_packet *)malloc( sizeof(my_handshake_packet) );
    if (p == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(p, 0, sizeof(my_handshake_packet));

    p->h.ptype = myp_handshake;
    /* FIXME: add free and store handlers */

    /* We only support protocol 10 right now... */
    p->protocol_version = c->rbuf[base];
    if (p->protocol_version != 10) {
        fprintf(stderr, "We only support protocol version 10! Closing.\n");
        return NULL;
    }

    base++;

    /* Server version string. Crappy malloc. */
    my_size = strlen((const char *)&c->rbuf[base]);
    p->server_version = (char *)malloc( my_size );

    if (p->server_version == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memcpy(p->server_version, &c->rbuf[base], my_size);
    /* +1 to account for the \0 */
    base += my_size + 1;

    /* TODO: I think technically I can do this with one memcpy. */

    /* 4 byte thread id */
    memcpy(&p->thread_id, &c->rbuf[base], 4);
    base += 4;

    /* First 8 bytes of scramble_buff. Sandwich with 12 more + \0 later */
    memcpy(&p->scramble_buff, &c->rbuf[base], 8);
    base += 8;

    /* Should be 0 */
    p->filler1 = c->rbuf[base];
    base++;

    /* Set of flags for server caps. */
    /* TODO: Need to explicitly disable compression, ssl, other features we
     * don't support. */
    memcpy(&p->server_capabilities, &c->rbuf[base], 2);
    base += 2;

    /* Language setting. Pass-through and/or ignore. */
    p->server_language = c->rbuf[base];
    base++;

    /* Server status flags. AUTOCOMMIT flags and such? */
    memcpy(&p->server_status, &c->rbuf[base], 2);
    base += 2;

    /* More zeroes? */
    memcpy(&p->filler2, &c->rbuf[base], 13);
    base += 13;

    /* Rest of random number "string" */
    memcpy(&p->scramble_buff[8], &c->rbuf[base], 13);
    base += 13;

    fprintf(stdout, "***PACKET*** Handshake packet: %x\n%s\n%x\n%x\n%x\n", p->protocol_version, p->server_version, p->thread_id, p->filler1, p->server_capabilities);

    return p;
}

/* FIXME: Two stupid optional params. if no scramble buf, and no database
 * name, is that the end of the packet? Should test, instead of strlen'ing
 * random memory.
 */
static my_auth_packet *my_consume_auth_packet(conn *c)
{
    my_auth_packet *p;
    int base = c->readto + 4;
    size_t my_size = 0;

    /* Clear out the struct. */
    p = (my_auth_packet *)malloc( sizeof(my_auth_packet) );
    if (p == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(p, 0, sizeof(my_auth_packet));

    p->h.ptype = myp_auth;
    /* FIXME: add free and store handlers */

    /* Client flags. Same as server_flags with some crap added/removed.
     * at this point in packet processing we should take out unsupported
     * options.
     */
    memcpy(&p->client_flags, &c->rbuf[base], 4);
    base += 4;

    /* Should we short circuit this to something more reasonable for latency?
     */
    memcpy(&p->max_packet_size, &c->rbuf[base], 4);
    base += 4;

    p->charset_number = c->rbuf[base];
    base++;

    /* Skip the filler crap. */
    base += 23;

    /* Supplied username. */
    /* FIXME: This string reading crap should be a helper function. */
    my_size = strlen((const char *)&c->rbuf[base]);
    p->user = (char *)malloc( my_size );

    if (p->user == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memcpy(p->user, &c->rbuf[base], my_size + 1);
    /* +1 to account for the \0 */
    base += my_size + 1;

    /* "Length coded binary" my ass. */
    /* If we don't have one, leave it all zeroes. */
    if (c->rbuf[base] > 0) {
        memcpy(&p->scramble_buff, &c->rbuf[base + 1], 21);
        base += 21;
    } else {
        /* I guess this "filler" is only here if there's no scramble. */
        base++;
    }

    if (c->packetsize > base) {
        my_size = strlen((const char *)&c->rbuf[base]);
        p->databasename = (char *)malloc( my_size );

        if (p->databasename == 0) {
            perror("Could not malloc()");
            return NULL;
        }
        memcpy(p->databasename, &c->rbuf[base], my_size + 1);
        /* +1 to account for the \0 */
        base += my_size + 1;
    }

    fprintf(stdout, "***PACKET*** Client auth packet: %x\n%u\n%x\n%s\n%s\n", p->client_flags, p->max_packet_size, p->charset_number, p->user, p->databasename);

    return p;
}

static my_ok_packet *my_consume_ok_packet(conn *c)
{
    my_ok_packet *p;
    int base = c->readto + 4;
    uint64_t my_size = 0;

    /* Clear out the struct. */
    p = (my_ok_packet *)malloc( sizeof(my_ok_packet) );
    if (p == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(p, 0, sizeof(my_ok_packet));

    p->h.ptype = myp_ok;
    /* FIXME: add free and store handlers */

    p->affected_rows = my_read_binary_field(c->rbuf, &base);

    p->insert_id = my_read_binary_field(c->rbuf, &base);

    memcpy(&p->server_status, &c->rbuf[base], 2);
    base += 2;

    memcpy(&p->warning_count, &c->rbuf[base], 2);
    base += 2;

    if (c->packetsize > base - c->readto && (my_size = my_read_binary_field(c->rbuf, &base))) {
        p->message = (char *)malloc( my_size );
        if (p->message == 0) {
            perror("Could not malloc()");
            return NULL;
        }
        p->message_len = my_size;
        memcpy(p->message, &c->rbuf[base], my_size);
    } else {
        p->message = NULL;
    }

    fprintf(stdout, "***PACKET*** Server OK packet: %x\n%llu\n%llu\n%u\n%u\n%s\n", p->field_count, (unsigned long long)p->affected_rows, (unsigned long long)p->insert_id, p->server_status, p->warning_count, p->message_len ? p->message : '\0');

    return p;
}

/* FIXME: There might be an "unknown error" state which changes the packet
 * payload.
 */
static my_err_packet *my_consume_err_packet(conn *c)
{
    my_err_packet *p;
    int base = c->readto + 4;
    size_t my_size = 0;

    /* Clear out the struct. */
    p = (my_err_packet *)malloc( sizeof(my_err_packet) );
    if (p == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(p, 0, sizeof(my_err_packet));

    p->h.ptype = myp_err;
    /* FIXME: add free and store handlers */

    p->field_count = c->rbuf[base];
    base++;

    memcpy(&p->errnum, &c->rbuf[base], 2);
    base += 2;

    p->marker = c->rbuf[base];
    base++;

    memcpy(&p->sqlstate, &c->rbuf[base], 5);
    base += 5;

    /* Have to add our own null termination... */
    p->sqlstate[6] = '\0';

    /* Why couldn't they just use a packed string? Or a null terminated
     * string? Was it really worth saving one byte when it should be numeric
     * anyway?
     */
    my_size = c->packetsize - (base - c->readto);

    p->message = (char *)malloc( my_size + 1 );
    if (p->message == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memcpy(p->message, &c->rbuf[base], my_size);
    p->message[my_size] = '\0';

    fprintf(stdout, "***PACKET*** Server Error Packet: %d\n%d\n%c\n%s\n%s\n", p->field_count, p->errnum, p->marker, p->sqlstate, p->message);

    return p;
}

static my_cmd_packet *my_consume_cmd_packet(conn *c)
{
    my_cmd_packet *p;
    int base = c->readto + 4;
    size_t my_size = 0;

    /* Clear out the struct. */
    p = (my_cmd_packet *)malloc( sizeof(my_cmd_packet) );
    if (p == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(p, 0, sizeof(my_cmd_packet));

    p->h.ptype = myp_cmd;
    /* FIXME: add free and store handlers */

    p->command = c->rbuf[base];
    base++;

    my_size = c->packetsize - (base - c->readto);

    p->arg = (unsigned char *)malloc( my_size + 1 );
    if (p->arg == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memcpy(p->arg, &c->rbuf[base], my_size);
    p->arg[my_size] = '\0';

    fprintf(stdout, "***PACKET*** Client Command Packet: %d\n%s\n", p->command, p->arg);

    return p;
}

static my_rset_packet *my_consume_rset_packet(conn *c)
{
    my_rset_packet *p;
    int base = c->readto + 4;

    /* Clear out the struct. */
    p = (my_rset_packet *)malloc( sizeof(my_rset_packet) );
    if (p == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(p, 0, sizeof(my_rset_packet));

    p->h.ptype = myp_rset;
    /* FIXME: add free and store handlers */

    p->field_count = my_read_binary_field(c->rbuf, &base);
    c->field_count = p->field_count;

    if (c->packetsize > (base - c->readto)) {
        p->extra = my_read_binary_field(c->rbuf, &base);
    }

    fprintf(stdout, "***PACKET*** Client Resultset Packet: %llx\n%llx\n", (unsigned long long)p->field_count, (unsigned long long)p->extra);

    return p;
}

static my_field_packet *my_consume_field_packet(conn *c)
{
    my_field_packet *p;
    int base = c->readto + 4;
    size_t my_size = 0;
    unsigned char *start_ptr;

    /* Clear out the struct. */
    p = (my_field_packet *)malloc( sizeof(my_field_packet) );
    if (p == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(p, 0, sizeof(my_field_packet));

    p->h.ptype = myp_field;
    /* FIXME: add free and store handlers */

    /* This packet type has a ton of dynamic length fields.
     * What we're going to do instead of 6 mallocs is use an offset table
     * and a bunch of pointers into one fat malloc.
     */

    my_size = c->packetsize - 4; /* Remove a few bytes for now. */

    p->fields = (unsigned char *)malloc( my_size );
    if (p->fields == 0) {
        perror("Malloc()");
        return NULL;
    }
    start_ptr = p->fields;

    /* This is the basic repetition here.
     * The protocol docs say there might be \0's here, but lets add them
     * anyway... Many of the clients do.
     */
    p->catalog_len = my_read_binary_field(c->rbuf, &base);
    p->catalog = start_ptr;
    memcpy(p->catalog, &c->rbuf[base], p->catalog_len);
    base += p->catalog_len;
    *(start_ptr += p->catalog_len) = '\0';

    p->db_len = my_read_binary_field(c->rbuf, &base);
    p->db = start_ptr + 1;
    memcpy(p->db, &c->rbuf[base], p->db_len);
    base += p->db_len;
    *(start_ptr += p->db_len + 1) = '\0';

    p->table_len = my_read_binary_field(c->rbuf, &base);
    p->table = start_ptr + 1;
    memcpy(p->table, &c->rbuf[base], p->table_len);
    base += p->table_len;
    *(start_ptr += p->table_len + 1) = '\0';

    p->org_table_len = my_read_binary_field(c->rbuf, &base);
    p->org_table = start_ptr + 1;
    memcpy(p->org_table, &c->rbuf[base], p->org_table_len);
    base += p->org_table_len;
    *(start_ptr += p->org_table_len + 1) = '\0';

    p->name_len = my_read_binary_field(c->rbuf, &base);
    p->name = start_ptr + 1;
    memcpy(p->name, &c->rbuf[base], p->name_len);
    base += p->name_len;
    *(start_ptr += p->name_len + 1) = '\0';

    p->org_name_len = my_read_binary_field(c->rbuf, &base);
    p->org_name = start_ptr + 1;
    memcpy(p->org_name, &c->rbuf[base], p->org_name_len);
    base += p->org_name_len;
    *(start_ptr += p->org_name_len + 1) = '\0';

    /* Rest of this packet is straightforward. */

    /* Skip filler field */
    base++;

    memcpy(&p->charsetnr, &c->rbuf[base], 2);
    base += 2;

    memcpy(&p->length, &c->rbuf[base], 4);
    base += 4;

    p->type = c->rbuf[base];
    base++;

    memcpy(&p->flags, &c->rbuf[base], 2);
    base += 2;

    p->decimals = c->rbuf[base];
    base++;

    /* Skip second filler field */
    base += 2;

    /* Default is optional? */
    /* FIXME: I might be confusing this as a length encoded number, when it's
     * a length encoded string of binary data. */
    if (c->packetsize > (base - c->readto)) {
        p->my_default = my_read_binary_field(c->rbuf, &base);
    }

    fprintf(stdout, "***PACKET*** parsed field packet.\n");
    return p;
}

/* Placeholder */
static int my_consume_row_packet(conn *c)
{
    //int base = c->readto + 4;
    int i = 0;

    for (i = 4; i < c->packetsize; i++) {
        fprintf(stdout, "%x ", c->rbuf[c->readto + i]);
    }
    fprintf(stdout, "\n");
    for (i = 4; i < c->packetsize; i++) {
        fprintf(stdout, "%c ", c->rbuf[c->readto + i]);
    }
    
    fprintf(stdout, "\n");

    fprintf(stdout, "***PACKET*** parsed row packet.\n");
    return 0;
}

/* Placeholder */
static my_eof_packet *my_consume_eof_packet(conn *c)
{
    my_eof_packet *p;
    int base = c->readto + 4;
 
    /* Clear out the struct. */
    p = (my_eof_packet *)malloc( sizeof(my_eof_packet) );
    if (p == 0) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(p, 0, sizeof(my_eof_packet));

    p->h.ptype = myp_eof;
    /* FIXME: add free and store handlers */

    /* Skip field_count, is always 0xFE */
    base++;

    memcpy(&p->warning_count, &c->rbuf[base], 2);
    base += 2;

    memcpy(&p->status_flags, &c->rbuf[base], 2);
    base += 2;

    fprintf(stdout, "***PACKET*** parsed EOF packet.\n");
    return 0;
}

/* Can't send a packet unless we know what it is.
 * So *p and ptype must be defined.
 */
 /* NOTE: This means the packet was sent _TO_ the wire on this conn */
static int sent_packet(conn *c, void **p, int ptype, int field_count)
{
    int ret = 0;

    #ifdef DBUG_STATE
    fprintf(stdout, "START State: %s\n", my_state_name[c->mypstate]);
    #endif
    switch (c->my_type) {
    case my_client:
        /* Doesn't matter what we send to the client right now.
         * The clients maintain their own state based on what command they
         * just sent. We can add state tracking in the future so you can write
         * clients from lua without going crazy and pulling out all your hair.
         */
        switch (c->mypstate) {
        case myc_wait_handshake:
            assert(ptype == myp_handshake);
            c->mypstate = myc_wait_auth;
        }
        break;
    case my_server:
        switch (c->mypstate) {
        case mys_wait_auth:
            assert(ptype == myp_auth);
            c->mypstate = mys_sending_ok;
            break;
        case mys_wait_cmd:
            assert(ptype == myp_cmd);
            {
            my_cmd_packet *cmd = (my_cmd_packet *)*p;
            c->last_cmd = cmd->command;
            switch (c->last_cmd) {
            case COM_QUERY:
                c->mypstate = mys_sending_rset;
                break;
            case COM_FIELD_LIST:
                c->mypstate = mys_sending_fields;
                break;
            case COM_INIT_DB:
            case COM_QUIT:
                c->mypstate = mys_sending_ok;
                break;
            default:
                fprintf(stdout, "***WARNING*** UNKNOWN PACKET RESULT SET FOR PACKET TYPE %d\n", c->last_cmd);
                assert(1 == 0);
            }
            }
            break;
        }
    }

    #ifdef DBUG_STATE
    fprintf(stdout, "END State: %s\n", my_state_name[c->mypstate]);
    #endif
    run_lua_callback(c, 0);
    return ret;
}

/* If we received a packet, we don't necessarily know what it is.
 * So *p can be NULL and ptype can be 0 (myp_unknown).
 */
 /* NOTE: This means the packet was received _ON_ the wire for this conn */
static int received_packet(conn *c, void **p, int *ptype, int field_count)
{
    int ret = 0;
    #ifdef DBUG_STATE
    fprintf(stdout, "START State: %s\n", my_state_name[c->mypstate]);
    #endif
    switch (c->my_type) {
    case my_client:
        switch (c->mypstate) {
        case myc_wait_auth:
            *p = my_consume_auth_packet(c);
            *ptype = myp_auth;
            c->mypstate = myc_waiting;
            break;
        case myc_waiting:
            *p = my_consume_cmd_packet(c);
            *ptype = myp_cmd;
            break;
        }
        break;
    case my_server:
        switch (c->mypstate) {
        case mys_connect:
            *p = my_consume_handshake_packet(c);
            *ptype = myp_handshake;
            c->mypstate = mys_wait_auth;
            break;
        case mys_sending_ok:
            switch (field_count) {
            case 0:
                *p = my_consume_ok_packet(c);
                *ptype = myp_ok;
                c->mypstate = mys_wait_cmd;
                break;
            case 255:
                *ptype = myp_err;
                break;
            default:
                /* Should never get here. */
                assert(field_count == 0 || field_count == 255);
            }
            break;
        case mys_sending_rset:
            switch (field_count) {
            case 255:
                *ptype = myp_err;
                break;
            default:
                *p = my_consume_rset_packet(c);
                *ptype = myp_rset;
                c->mypstate = mys_sending_fields;
            }
            break;
        case mys_sending_fields:
            switch (field_count) {
            case 254:
                /* Grr. impossible to tell an EOF apart from a ROW or FIELD
                 * unless it's the right size to be an EOF as well */
                if (c->packetsize < 10) {
                my_consume_eof_packet(c);
                *ptype = myp_eof;
                /* Can change this to another switch, or cuddle a flag under
                 * case 'mys_wait_cmd', if it's really more complex than this.
                 */
                if (c->last_cmd == COM_QUERY) {
                    c->mypstate = mys_sending_rows;
                } else {
                    c->mypstate = mys_wait_cmd;
                }
                break;
                }
            case 255:
                *ptype = myp_err;
                break;
            default:
                my_consume_field_packet(c);
                *ptype = myp_field;
            }
            break;
        case mys_sending_rows:
            switch (field_count) {
            case 254:
                if (c->packetsize < 10) {
                my_consume_eof_packet(c);
                *ptype = myp_eof;
                c->mypstate = mys_wait_cmd;
                break;
                }
            case 255:
                *ptype = myp_err;
                break;
            default:
                my_consume_row_packet(c);
                *ptype = myp_row;
                break;
            }
            break;
        }

        /* Read errors if we detected an error packet. */
        if (*ptype == myp_err) {
            *p = my_consume_err_packet(c);
            c->mypstate = mys_wait_cmd;
        }
    }

    #ifdef DBUG_STATE
    fprintf(stdout, "END State: %s\n", my_state_name[c->mypstate]);
    #endif
    run_lua_callback(c, 0);
    return ret;
}

/* Run the "MySQL" protocol on a socket. Generic state machine logic.
 * Would've loved to use Ragel, but it doesn't make sense here.
 */
static int run_protocol(conn *c, int read, int written)
{
    int finished = 0;
    int err = 0;
    int next_packet;
    socklen_t errsize = sizeof(err);
    conn *remote = NULL;

    //fprintf(stdout, "Running protocol state machine\n");

    while (!finished) {
        switch (c->mystate) {
        case my_connect:
            /* Socket was connecting. Lets see if it's good now. */
            if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &errsize) < 0) {
                perror("Running getsockopt on outbound connect");
                return -1;
            }
            if (err != 0) {
                fprintf(stderr, "Error in connecting outbound socket\n");
                return -1;
            }

            /* Neat. we're all good. */
            fprintf(stdout, "Successfully connected outbound socket %d\n", c->fd);
            update_conn_event(c, EV_READ | EV_PERSIST);
            c->mystate  = my_waiting;
            c->mypstate = mys_connect;
            c->my_type  = my_server;
        case my_waiting:
            /* When in a waiting state, we need to read four bytes to get
             * the packet length and packet number. */
            if (c->read > 3) {
                //fprintf(stdout, "Looks like we have a packet. Start reading\n");
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
                fprintf(stdout, "Read from %d packet size %u.\n", c->fd, c->packetsize);
                {
                int ptype = myp_none;
                void *p = NULL;
                int ret = 0;
                /* Drive the packet state machine. */
                ret = received_packet(c, &p, &ptype, c->rbuf[c->readto + 4]);
                //if (p == NULL) return -1;
                /*err = run_packet_protocol(c);
                if (err == -1) return -1;*/
                /* Buffered up all pending packet reads. Write out to remote */
                if (grow_write_buffer(remote, remote->towrite + c->packetsize) == -1) {
                    return -1;
                }

                /* Drive other half of state machine. */
                ret = sent_packet(remote, &p, ptype, c->field_count);

                memcpy(remote->wbuf + remote->towrite, c->rbuf + next_packet, c->packetsize);
                remote->towrite += c->packetsize;

                /* Copied in the packet; advance to next packet. */
                c->readto += c->packetsize;
                }
            }
            if (c == NULL) {
                break;
            }
            err = handle_write(remote);
            if (err == -1) return -1;

            /* Any pending packet reads? If so, reset boofer. */
            if (c->readto == c->read) {
                //fprintf(stdout, "Resetting read buffer\n");
                c->read    = 0;
                c->readto  = 0;
                c->mystate = my_waiting;
            }
            break;
        }
        finished++;
    }

    return 0;
}

/* Take present state value and attempt a lua callback.
 * callbacks[conn->id][statename]->() in lua's own terms.
 * if there is a "wait for state" value named, short circuit unless that state
 * is matched.
 */
static int run_lua_callback(conn *c, int nargs)
{
    int top = lua_gettop(L); /* Save so we may saw off the top later */

    fprintf(stdout, "Running callback [%s] on conn id %llu\n", my_state_name[c->mypstate], (unsigned long long) c->id);

    lua_getglobal(L, "callback");
    if (!lua_istable(L, -1)) {
        lua_settop(L, top);
        return 0;
    }

    /* First stage is to find the table of callbacks for this connection id */
    lua_pushnumber(L, c->id);
    lua_gettable(L, -2);
    if (!lua_istable(L, -1)) {
        lua_settop(L, top);
        return 0;
    }

    /* Now the top of the stack should be another table... */
    lua_getfield(L, -1, my_state_name[c->mypstate]);

    /* Now the top o' the stack ought to be a function. */
    if (!lua_isfunction(L, -1)) {
        lua_settop(L, top);
        return 0;
    }

    /* Do the argument shuffle! */
    lua_insert(L, 1);
    /* Function's on the bottom, but two levels of callback table are above.
     * so pop them out and we should have the right order. */
    lua_pop(L, 2);

    /* Finally, call the function? We should push some args too */
    if (lua_pcall(L, nargs, 0, 0) != 0) {
        luaL_error(L, "Error running callback function: %s", lua_tostring(L, -1));
    }
    lua_settop(L, top - nargs);

    return 0;
}

static int new_listener(lua_State *L)
{
    struct sockaddr_in addr;
    conn *listener;
    int flags = 1;
    int l_socket = 0;
    const char *ip_addr = luaL_checkstring(L, 1);
    double port_num = luaL_checknumber(L, 2);

    if ( (l_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    set_sock_nonblock(l_socket);

    setsockopt(l_socket, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
    setsockopt(l_socket, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_num);
    addr.sin_addr.s_addr = inet_addr(ip_addr);

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

    listener = init_conn(l_socket);

    listener->ev_flags = EV_READ | EV_PERSIST;

    listener->listener++;

    event_set(&listener->ev, l_socket, listener->ev_flags, handle_event, (void *)listener);
    event_add(&listener->ev, NULL);

    new_obj(L, listener, "myp.conn");

    return 1;
}

int main (int argc, char **argv)
{
    struct sigaction sa;
    static const struct luaL_Reg myp [] = {
        {"listener", new_listener},
        {NULL, NULL},
    };

    fprintf(stdout, "Starting up...\n");

    /* Initialize the event system. */
    event_init();

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

    L = lua_open();

    if (L == NULL) {
        fprintf(stderr, "Could not create lua state\n");
        return -1;
    }
    luaL_openlibs(L);

    luaL_register(L, "myp", myp);
    register_obj_types(L); /* Internal call to fill all custom metatables */

    if (luaL_dofile(L, "toast.lua")) {
        fprintf(stdout, "Could not run lua initializer: %s\n", lua_tostring(L, -1));
        lua_pop(L, 1);
        return -1;
    }
    lua_pop(L, 1); /* Don't need to leave the table at the top of the stack */

    fprintf(stdout, "Starting event dispatcher...\n");

    event_dispatch();

    return 0;
}
