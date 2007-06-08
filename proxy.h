/* Main proxy defines. */

#ifndef PROXY_H
#define PROXY_H

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
#include <stdint.h>
/* Help find stupid bugs */
#include <assert.h>

/* libevent specifics */
#include <event.h>

/* Lua specifics */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/* Public domain MySQL defines from mysqlnd's portability.h */
#include "portability.h"

/* MySQL defines from mysql_com.h - It's GPL! */
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

/* End defines from mysql_com.h */

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

/* MySQL protocol states */
enum myconn_states {
    my_waiting, /* Waiting for a new request to start */
    my_reading, /* Reading into a packet */
    my_connect, /* Attempting to connect to a remote socket */
};

enum mypacket_types {
    myp_none, /* No packet/error */
    myp_handshake,
    myp_auth,
    myp_ok,
    myp_cmd,
    myp_err,
    myp_rset,
    myp_field,
    myp_row,
    myp_eof,
};

enum myproto_states {
    mys_connect,
    myc_connect,
    mys_sent_handshake,
    myc_wait_handshake,
    myc_waiting, /* Waiting to send a command. */
    mys_waiting, /* Waiting to receive a command. */
    myc_sent_cmd,
    mys_sending_fields,
    mys_sending_rows,
    mys_wait_auth,
    mys_sending_ok,
    mys_wait_cmd,
    mys_sending_rset,
    myc_wait_auth,
    mys_sending_handshake,
    mys_recv_err,
};

enum my_types {
    my_server, /* This conn is a server connection */
    my_client, /* This conn is a client connection */
};

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
    int    mypstate; /* Packet state */
    uint8_t my_type; /* Type of *remote* end of this connection */
    int    packetsize;
    uint64_t field_count; /* Number of field packets expected. */
    uint8_t last_cmd; /* Last command ran through this connection. */
    unsigned char packet_seq; /* Packet sequence */

    int listener;

    /* Proxy references. */
    struct conn *remote;
} conn;

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
    unsigned char  scramble_buff[21]; /* NULL terminated, for some reason. */
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
    unsigned char  scramble_buff[21]; /* NULL terminated. */
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
    unsigned char *arg;     /* Non-null-terminated string that was the cmd */
} my_cmd_packet;

typedef struct {
    my_packet_header h;
    uint64_t       field_count; /* Actually a field count this time. */
    uint64_t       extra; /* Optional random junk. */
} my_rset_packet;

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
} my_field_packet;

typedef struct {
    my_packet_header h;
    uint16_t    warning_count;
    uint16_t    status_flags;
} my_eof_packet;

/* Icky ewwy global vars. */

extern struct lua_State *L;

/* Global forward declarations */
void *my_new_handshake_packet();
void *my_new_auth_packet();
void *my_new_ok_packet();
void *my_new_err_packet();

#endif /* PROXY_H */
