/*
 *  Copyright 2008 Dormando (dormando@rydia.net).  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
*/

/* Main proxy defines. */

#ifndef PROXY_H
#define PROXY_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h> /* sockaddr_in BSD */
#include <sys/un.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <signal.h> /* BSD */
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <getopt.h>
#include <assert.h>

/* libevent specifics */
#include <event.h>

/* Lua specifics */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* Public domain MySQL defines from mysqlnd's portability.h */
#include "portability.h"

#define SERVER_STATUS_IN_TRANS     1    /* Transaction has started */
#define SERVER_STATUS_AUTOCOMMIT   2    /* Server in auto_commit mode */
#define SERVER_MORE_RESULTS_EXISTS 8    /* Multi query - next query exists */

#define SERVER_QUERY_NO_GOOD_INDEX_USED 16
#define SERVER_QUERY_NO_INDEX_USED      32

/* Client packet flags */
#define CLIENT_LONG_PASSWORD    1   /* new more secure passwords */
#define CLIENT_FOUND_ROWS   2   /* Found instead of affected rows */
#define CLIENT_LONG_FLAG    4   /* Get all column flags */
#define CLIENT_CONNECT_WITH_DB  8   /* One can specify db on connect */
#define CLIENT_NO_SCHEMA    16  /* Don't allow database.table.column */
#define CLIENT_COMPRESS     32  /* Can use compression protocol */
#define CLIENT_ODBC     64  /* Odbc client */
#define CLIENT_LOCAL_FILES  128 /* Can use LOAD DATA LOCAL */
#define CLIENT_IGNORE_SPACE 256 /* Ignore spaces before '(' */
#define CLIENT_PROTOCOL_41  512 /* New 4.1 protocol */
#define CLIENT_INTERACTIVE  1024    /* This is an interactive client */
#define CLIENT_SSL              2048    /* Switch to SSL after handshake */
#define CLIENT_IGNORE_SIGPIPE   4096    /* IGNORE sigpipes */
#define CLIENT_TRANSACTIONS 8192    /* Client knows about transactions */
#define CLIENT_RESERVED         16384   /* Old flag for 4.1 protocol  */
#define CLIENT_SECURE_CONNECTION 32768  /* New 4.1 authentication */
#define CLIENT_MULTI_STATEMENTS 65536 /* Enable/disable multi-stmt support */
#define CLIENT_MULTI_RESULTS    131072 /* Enable/disable multi-results */

/*
  This flag is sent when a read-only cursor is exhausted, in reply to
  COM_STMT_FETCH command.
*/
#define SERVER_STATUS_LAST_ROW_SENT 128
#define SERVER_STATUS_DB_DROPPED        256 /* A database was dropped */
#define SERVER_STATUS_NO_BACKSLASH_ESCAPES 512

#define MYSQL_ERRMSG_SIZE   512

#define NAME_LEN    64      /* Field/table name length */
#define HOSTNAME_LENGTH 60
#define USERNAME_LENGTH 16
#define SERVER_VERSION_LENGTH 60
#define SQLSTATE_LENGTH 5

#define NOT_NULL_FLAG   1       /* Field can't be NULL */
#define PRI_KEY_FLAG    2       /* Field is part of a primary key */
#define UNIQUE_KEY_FLAG 4       /* Field is part of a unique key */
#define MULTIPLE_KEY_FLAG 8     /* Field is part of a key */
#define BLOB_FLAG   16      /* Field is a blob */
#define UNSIGNED_FLAG   32      /* Field is unsigned */
#define ZEROFILL_FLAG   64      /* Field is zerofill */
#define BINARY_FLAG 128     /* Field is binary   */

/* The following are only sent to new clients */
#define ENUM_FLAG   256     /* field is an enum */
#define AUTO_INCREMENT_FLAG 512     /* field is a autoincrement field */
#define TIMESTAMP_FLAG  1024        /* Field is a timestamp */
#define SET_FLAG    2048        /* field is a set */
#define NO_DEFAULT_VALUE_FLAG 4096  /* Field doesn't have default value */
#define NUM_FLAG    32768       /* Field is num (for clients) */

/* Integer values for commands */
enum my_proto_commands {
    COM_SLEEP = 0,
    COM_QUIT,
    COM_INIT_DB,
    COM_QUERY,
    COM_FIELD_LIST,
    COM_CREATE_DB,
    COM_DROP_DB,
    COM_REFRESH,
    COM_SHUTDOWN,
    COM_STATISTICS,
    COM_PROCESS_INFO,
    COM_CONNECT,
    COM_PROCESS_KILL,
    COM_DEBUG,
    COM_PING,
    COM_TIME,
    COM_DELAYED_INSERT,
    COM_CHANGE_USER,
    COM_BINLOG_DUMP,
    COM_TABLE_DUMP,
    COM_CONNECT_OUT,
    COM_REGISTER_SLAVE,
    COM_STMT_PREPARE,
    COM_STMT_EXECUTE,
    COM_STMT_SEND_LONG_DATA,
    COM_STMT_CLOSE,
    COM_STMT_RESET,
    COM_SET_OPTION,
    COM_STMT_FETCH,
    COM_DAEMON,
    COM_END,
};

/* Integer values for mysql types. */
enum my_field_types {
    MYSQL_TYPE_DECIMAL = 0,
    MYSQL_TYPE_TINY,
    MYSQL_TYPE_SHORT,
    MYSQL_TYPE_LONG,
    MYSQL_TYPE_FLOAT,
    MYSQL_TYPE_DOUBLE,
    MYSQL_TYPE_NULL,
    MYSQL_TYPE_TIMESTAMP,
    MYSQL_TYPE_LONGLONG,
    MYSQL_TYPE_INT24,
    MYSQL_TYPE_DATE,
    MYSQL_TYPE_TIME,
    MYSQL_TYPE_DATETIME,
    MYSQL_TYPE_YEAR,
    MYSQL_TYPE_NEWDATE,
    MYSQL_TYPE_VARCHAR,
    MYSQL_TYPE_BIT,
    MYSQL_TYPE_NEWDECIMAL=246,
    MYSQL_TYPE_ENUM=247,
    MYSQL_TYPE_SET=248,
    MYSQL_TYPE_TINY_BLOB=249,
    MYSQL_TYPE_MEDIUM_BLOB=250,
    MYSQL_TYPE_LONG_BLOB=251,
    MYSQL_TYPE_BLOB=252,
    MYSQL_TYPE_VAR_STRING=253,
    MYSQL_TYPE_STRING=254,
    MYSQL_TYPE_GEOMETRY=255
};

/* Defines which were not yanked. */
#define MYSQL_NULL (uint64_t) ~0

/* MySQL protocol states */
enum myconn_states {
    my_waiting, /* Waiting for a new request to start */
    my_reading, /* Reading into a packet */
    my_connect, /* Attempting to connect to a remote socket */
};

enum dpm_packet_types {
    dpm_none, /* No packet/error */
    dpm_handshake,
    dpm_auth,
    dpm_ok,
    dpm_cmd,
    dpm_err,
    dpm_rset,
    dpm_field,
    dpm_row,
    dpm_eof,
    dpm_stats,
};

/* This enum is to help transition off of the lowercase style.
 * Lets define both for now, update everything over a few commits, then remove
 * the old one.
 */
enum dpm_proto_states {
    MYS_CONNECT,
    MYC_CONNECT,
    MYS_SENT_HANDSHAKE,
    MYC_WAIT_HANDSHAKE,
    MYC_WAITING, /* Waiting to send a command. */
    MYS_WAITING, /* Waiting to receive a command. */
    MYC_SENT_CMD,
    MYS_SENDING_FIELDS,
    MYS_SENDING_ROWS,
    MYS_WAIT_AUTH,
    MYS_SENDING_OK,
    MYS_WAIT_CMD,
    MYS_SENDING_RSET,
    MYC_WAIT_AUTH,
    MYS_SENDING_HANDSHAKE,
    MYS_RECV_ERR,
    MY_CLOSING,
    MYS_SENDING_STATS,
    MYS_GOT_CMD, /* Server received command */
    MYS_SENDING_EOF, /* The "data marker" at end of fields or end of rows. */
    MYS_SENT_RSET,
    MYS_SENT_FIELDS,
};

/* It's a lie. */
#define TOTAL_STATES 25

enum my_types {
    MY_SERVER, /* Conn is a server connection */
    MY_CLIENT, /* Conn is a client connection */
};

enum dpm_listeners {
    DPM_TCP  = 1,
    DPM_UNIX,
};

#define DPM_OK 0
#define DPM_NOPROXY 1
#define DPM_FLUSH_DISCONNECT 2

#define CALLBACK_AVAILABLE(c) \
( (c->package_callback != NULL && c->package_callback[c->dpmstate] != 0) \
? c->package_callback[c->dpmstate] : c->main_callback[c->dpmstate] )

/* Structs... */
typedef struct {
    int    fd;
    uint64_t id; /* Unique id for struct. */

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
    int    mystate;  /* Connection state */
    int    dpmstate; /* Packet state */
    uint8_t my_type; /* Type of *remote* end of this connection */
    int    packetsize;
    uint64_t field_count; /* Number of field packets expected. */
    uint8_t last_cmd; /* Last command ran through this connection. */
    unsigned char packet_seq; /* Packet sequence */

    int listener;

    /* Proxy references. */
    struct conn *remote;
    uint64_t remote_id; /* Cached value for the remote conn id. */
    uint8_t alive; /* Whether or not we're alive. */

    /* Callback information. */
    int main_callback[25]; /* Each connection can be different. */
    int *package_callback; /* ... and packages may take over.   */
    int package_callback_ref; /* Reference to the callback object. */

    /* Allow connections to be chained into linked lists. */
    struct conn *nextconn;
} conn;

/* This fits into connection object. */
typedef struct {
    int callback[25];
} my_callback_obj;

/* Periodic (or onetime) timed event callbacks. */
typedef struct {
    struct event evtimer;
    struct timeval interval;
    int    self; /* lua reference to our own object. */
    int    callback; /* lua reference to the callback function. */
    int    arg; /* lua reference of object to return. */
} my_timer_obj;

typedef struct {
    int ptype;
    void    (*free_me) (void *p);
    int     (*to_buf) (conn *c, void *p);
} my_packet_header;

typedef struct {
    my_packet_header h;
} my_packet_fuzz;

typedef struct {
    my_packet_header h;
    uint8_t        protocol_version;
    char           server_version[SERVER_VERSION_LENGTH];
    uint32_t       thread_id;
    char           scramble_buff[21]; /* NULL terminated, for some reason. */
    uint8_t        filler1; /* Should always be 0x00 */
    uint16_t       server_capabilities;
    uint8_t        server_language;
    uint16_t       server_status;
    unsigned char  filler2[13]; /* Should always be 0x00 */
} my_handshake_packet;

typedef struct {
    my_packet_header h;
    uint32_t       client_flags;
    uint32_t       max_packet_size;
    uint8_t        charset_number;
    unsigned char  filler[23];
    char           user[USERNAME_LENGTH];
    char           scramble_buff[21]; /* NULL terminated. */
    uint8_t        filler2;
    char          *databasename;
} my_auth_packet;

typedef struct {
    my_packet_header h;
    uint8_t        field_count; /* Always zero to identify packet. */
    uint64_t       affected_rows; /* 1-9 byte encoded length. */
    uint64_t       insert_id; /* 1-9 byte encoded insert id. */
    uint16_t       server_status; /* 16 bit flags I think? */
    uint16_t       warning_count; /* 16 bit numeric for number of warnings? */
    char          *message; /* length encoded string of warnings. */
    uint64_t       message_len; /* Length of the above string. */
} my_ok_packet;

typedef struct {
    my_packet_header h;
    uint8_t        field_count; /* Always 0xFF. */
    uint16_t       errnum;
    char           marker; /* Always '#' */
    char           sqlstate[6]; /* Length is actually 5. +1 for \0 */
    char           message[MYSQL_ERRMSG_SIZE]; /* Should be null terminated? */
} my_err_packet;

typedef struct {
    my_packet_header h;
    uint8_t        command; /* Flags describe this. */
    char *argument;     /* Non-null-terminated string that was the cmd */
} my_cmd_packet;

/* NOTE: Do we need to store the length of 'fields' anywhere? */
typedef struct {
    my_packet_header h;
    unsigned char          *fields; /* Should be length of packet - 14 or so, I guess. */
    unsigned char          *catalog; /* below are pointers into *fields */
    unsigned char          *db;
    unsigned char          *table;
    unsigned char          *org_table;
    unsigned char          *name;
    unsigned char          *org_name;
    uint64_t       catalog_len;
    uint64_t       db_len;
    uint64_t       table_len;
    uint64_t       org_table_len;
    uint64_t       name_len;
    uint64_t       org_name_len;
    uint8_t        filler1;
    uint16_t       charsetnr;
    uint32_t       length;
    uint8_t        type;
    uint16_t       flags;
    uint8_t        decimals;
    uint16_t       filler2;
    uint64_t       my_default;
    uint8_t        has_default;
} my_field_packet;

typedef struct {
    my_packet_header h;
    uint16_t    warning_count;
    uint16_t    server_status;
} my_eof_packet;

typedef struct {
    my_field_packet *f; /* Pointer to a field packet struct. */
    int ref; /* Int reference for luaL_ref and unref, points to field obj */
} my_rset_field_header;

typedef struct {
    my_packet_header h;
    uint64_t       field_count; /* Actually a field count this time. */
    uint64_t       extra; /* Optional random junk. */
    uint64_t       fields_total; /* Number of fields actually associated. */
    my_rset_field_header *fields; /* Pointer array to field structures. */
} my_rset_packet;

typedef struct {
    my_packet_header h;
    int     packed_row_lref; /* Lua reference to the packed row. */
} my_row_packet;

typedef struct {
    size_t  len;
    char    data[1];
} cbuffer_t;

/* Icky ewwy global vars. */

extern struct lua_State *L;

/* Global forward declarations */
void *my_new_handshake_packet();
void *my_new_auth_packet();
void *my_new_ok_packet();
void *my_new_err_packet();
void *my_new_cmd_packet();
void *my_new_rset_packet();
void *my_new_field_packet();
void *my_new_row_packet();
void *my_new_eof_packet();

/* MySQL protocol handlers other parts of the code needs. */
uint64_t my_read_binary_field(unsigned char *buf, int *base);
int my_size_binary_field(uint64_t length);
void my_write_binary_field(unsigned char *buf, int *base, uint64_t length);

void handle_close(conn *c);

/* Basic string buffering functions, which I can expand on later.
 */
cbuffer_t *cbuffer_new(size_t len, const char *src);
void cbuffer_free(cbuffer_t *buf);
inline size_t cbuffer_size(cbuffer_t *buf);
inline const char *cbuffer_data(cbuffer_t *data);

typedef void *(*pkt_func) (conn *c);

#endif /* PROXY_H */
