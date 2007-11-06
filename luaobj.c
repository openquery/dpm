/* Copyright 2007 Dormando (dormando@rydia.net)
 *     This file is part of dpm.
 *
 *  dpm is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  dpm is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* Lua C object binding C code... */

#include "proxy.h"
#include "luaobj.h"

/* Forward declarations */
static int conn_gc(lua_State *L);
static int callback_gc(lua_State *L);
static int packet_gc(lua_State *L);

static int  obj_index(lua_State *L);
static void obj_add(lua_State *L, obj_reg *r);
static int  new_lua_obj(lua_State *L);

/* Accessors */
static int obj_int(lua_State *L, void *var, void *var2);
static int obj_enum(lua_State *L, void *var, void *var2);
static int obj_flags(lua_State *L, void *var, void *var2);
static int obj_string(lua_State *L, void *var, void *var2);
static int obj_pstring(lua_State *L, void *var, void *var2);
static int obj_lstring(lua_State *L, void *var, void *var2);
static int obj_uint64_t(lua_State *L, void *var, void *var2);
static int obj_uint32_t(lua_State *L, void *var, void *var2);
static int obj_uint16_t(lua_State *L, void *var, void *var2);
static int obj_uint8_t(lua_State *L, void *var, void *var2);

void *my_new_callback_object();
/* Package callback accessors. */
static int obj_callback_register(lua_State *L, void *var, void *var2);

/* Special connection accessors. */
static int obj_conn_package_register(lua_State *L, void *var, void *var2);

/* Resultset accessors. */
static int obj_rset_field_count(lua_State *L, void *var, void *var2);
static int obj_rset_add_field(lua_State *L, void *var, void *var2);
static int obj_rset_remove_field(lua_State *L, void *var, void *var2);
static int obj_rset_pack_row(lua_State *L, void *var, void *var2);
static int obj_rset_parse_row_array(lua_State *L, void *var, void *var2);
static int obj_rset_parse_row_table(lua_State *L, void *var, void *var2);

/* Special field accessor. */
static int obj_field_full(lua_State *L, void *var, void *var2);
static int obj_field_name(lua_State *L, void *var, void *var2);

static const obj_reg conn_regs [] = {
    {"id", obj_uint64_t, LO_READONLY, offsetof(conn, id), 0},
    {"remote_id", obj_uint64_t, LO_READONLY, offsetof(conn, remote_id), 0},
    {"listener", obj_int, LO_READONLY, offsetof(conn, listener), 0},
    {"my_type", obj_uint8_t, LO_READONLY, offsetof(conn, my_type), 0},
    {"register", obj_callback_register, LO_READWRITE, offsetof(conn, main_callback), 0},
    {"package_register", obj_conn_package_register, LO_READWRITE, offsetof(conn, package_callback), 0},
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg handshake_regs [] = {
    {"protocol_version", obj_uint8_t, LO_READWRITE, offsetof(my_handshake_packet, protocol_version), 0},
    {"server_version", obj_string, LO_READONLY, offsetof(my_handshake_packet, server_version), 0},
    {"thread_id", obj_uint32_t, LO_READWRITE, offsetof(my_handshake_packet, thread_id), 0},
    {"scramble_buff", obj_string, LO_READONLY, offsetof(my_handshake_packet, scramble_buff), 20},
    {"server_capabilities", obj_flags, LO_READWRITE, offsetof(my_handshake_packet, server_capabilities), 0},
    {"server_language", obj_uint8_t, LO_READWRITE, offsetof(my_handshake_packet, server_language), 0},
    {"server_status", obj_flags, LO_READWRITE, offsetof(my_handshake_packet, server_status), 0},
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg auth_regs [] = {
    {"client_flags", obj_flags, LO_READWRITE, offsetof(my_auth_packet, client_flags), 0},
    {"max_packet_size", obj_uint32_t, LO_READWRITE, offsetof(my_auth_packet, max_packet_size), 0},
    {"charset_number", obj_uint8_t, LO_READWRITE, offsetof(my_auth_packet, charset_number), 0},
    {"user", obj_string, LO_READWRITE, offsetof(my_auth_packet, user), 15},
    {"databasename", obj_string, LO_READWRITE, offsetof(my_auth_packet, databasename), 0},
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg ok_regs [] = {
    {"field_count", obj_uint8_t, LO_READONLY, offsetof(my_ok_packet, field_count), 0},
    {"affected_rows", obj_uint64_t, LO_READWRITE, offsetof(my_ok_packet, affected_rows), 0},
    {"insert_id", obj_uint64_t, LO_READWRITE, offsetof(my_ok_packet, insert_id), 0},
    {"server_status", obj_flags, LO_READWRITE, offsetof(my_ok_packet, server_status), 0},
    {"warning_count", obj_uint16_t, LO_READWRITE, offsetof(my_ok_packet, warning_count), 0},
    {"message", obj_lstring, LO_READONLY, offsetof(my_ok_packet, message), offsetof(my_ok_packet, message_len)},
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg err_regs [] = {
    {"field_count", obj_uint8_t, LO_READONLY, offsetof(my_err_packet, field_count), 0},
    {"errnum", obj_uint16_t, LO_READWRITE, offsetof(my_err_packet, errnum), 0},
    {"sqlstate", obj_string, LO_READWRITE, offsetof(my_err_packet, sqlstate), 5},
    {"message", obj_string, LO_READWRITE, offsetof(my_err_packet, message), 511},
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg cmd_regs [] = {
    {"command", obj_uint8_t, LO_READWRITE, offsetof(my_cmd_packet, command), 0},
    {"argument", obj_pstring, LO_READWRITE, offsetof(my_cmd_packet, argument), 0},
    {NULL, NULL, 0, 0, 0},
};

/* A resultset is a magic object, see below. */
/* The 'field_count' is handled specially because we need memory for the
 * field packet storage.
 */
static const obj_reg rset_regs [] = {
    {"field_count", obj_rset_field_count, LO_READWRITE, offsetof(my_rset_packet, field_count), 0},
    {"add_field", obj_rset_add_field, LO_READWRITE, offsetof(my_rset_packet, fields), 0},
    {"remove_field", obj_rset_remove_field, LO_READWRITE, offsetof(my_rset_packet, fields), 0},
    {"pack_row", obj_rset_pack_row, LO_READWRITE, offsetof(my_rset_packet, fields), 0},
    {"parse_row_array", obj_rset_parse_row_array, LO_READWRITE, offsetof(my_rset_packet, fields), 0},
    {"parse_row_table", obj_rset_parse_row_table, LO_READWRITE, offsetof(my_rset_packet, fields), 0},
    {NULL, NULL, 0, 0, 0},
};

/* Field packets are not magic, but different. For consistency
 * we should have one accessor for every field, but desiring a tiny bit
 * of efficiency (for now) the dynamic part of the packet is only rewriteable.
 */
static const obj_reg field_regs [] = {
    {"name", obj_field_name, LO_READWRITE, 0, 0},
    {"full", obj_field_full, LO_READWRITE, 0, 0},
    {NULL, NULL, 0, 0, 0},
};

/* Row packets are dumb, operated on by resultset objects. */
/* FIXME: accessor for the raw packet data? For the insane. */
static const obj_reg row_regs [] = {
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg eof_regs [] = {
    {"warning_count", obj_uint16_t, LO_READWRITE, offsetof(my_eof_packet, warning_count), 0},
    {"server_status", obj_flags, LO_READWRITE, offsetof(my_eof_packet, server_status), 0},
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg callback_regs [] = {
    {"register", obj_callback_register, LO_READWRITE, offsetof(my_callback_obj, callback), 0},
    {NULL, NULL, 0, 0, 0},
};

static const luaL_Reg generic_m [] = {
    {"__gc", packet_gc},
    {NULL, NULL},
};

static const luaL_Reg conn_m [] = {
    {"__gc", conn_gc},
    {NULL, NULL},
};

static const luaL_Reg callback_m [] = {
    {"__gc", callback_gc},
    {NULL, NULL},
};

static const obj_toreg regs [] = {
    {"dpm.conn", conn_regs, conn_m, NULL, NULL},
    {"dpm.handshake", handshake_regs, generic_m, my_new_handshake_packet, "new_handshake_pkt"},
    {"dpm.auth", auth_regs, generic_m, my_new_auth_packet, "new_auth_pkt"},
    {"dpm.ok", ok_regs, generic_m, my_new_ok_packet, "new_ok_pkt"},
    {"dpm.err", err_regs, generic_m, my_new_err_packet, "new_err_pkt"},
    {"dpm.cmd", cmd_regs, generic_m, my_new_cmd_packet, "new_cmd_pkt"},
    {"dpm.rset", rset_regs, generic_m, my_new_rset_packet, "new_rset_pkt"},
    {"dpm.field", field_regs, generic_m, my_new_field_packet, "new_field_pkt"},
    {"dpm.row", row_regs, generic_m, my_new_row_packet, "new_row_pkt"},
    {"dpm.eof", eof_regs, generic_m, my_new_eof_packet, "new_eof_pkt"},
    {"dpm.callback", callback_regs, callback_m, my_new_callback_object, "new_callback"},
    {NULL, NULL, NULL, NULL, NULL},
};

void *my_new_callback_object()
{
    my_callback_obj *o;

    o = malloc( sizeof(my_callback_obj) );
    if (o == NULL) {
        perror("Could not malloc()");
        return NULL;
    }
    memset(o, 0, sizeof(my_callback_obj));

    return o;
}

/* Nothing special for now. This ensures we don't segfault when calling the
 * packet gc on a connection obj.
 * TODO: Should check if conn is alive, and handle_close it if so.
 */
static int conn_gc(lua_State *L)
{
    int i;
    conn **c;
    c = lua_touserdata(L, 1);

    for (i = 0; i < TOTAL_STATES; i++) {
        if ((*c)->main_callback[i] != 0)
            luaL_unref(L, LUA_REGISTRYINDEX, (*c)->main_callback[i]);
    }

    free(*c);

    return 0;
}

/* Flat gc for callback objects. */
static int callback_gc(lua_State *L)
{
    int i;
    my_callback_obj **o;
    o = lua_touserdata(L, 1);

    for (i = 0; i < TOTAL_STATES; i++) {
        if ((*o)->callback[i] != 0)
            luaL_unref(L, LUA_REGISTRYINDEX, (*o)->callback[i]);
    }

    free(*o);

    return 0;
}

static int packet_gc(lua_State *L)
{
    my_packet_fuzz **p;
    p = lua_touserdata(L, 1);

    /* This frees itself. Ensure there are no leaks with valgrind! */
    if ((*p)->h.free_me)
        (*p)->h.free_me(*p);

    return 0;
}

void dump_stack()
{
    int top = lua_gettop(L);
    int i = 1;
    printf("TOP OF STACK [%d]\n", top);
    for (; i < top + 1; i++) {
        printf("STACK IS [%s]\n", lua_typename(L, lua_type(L, i)));
    }
}

/* Accessor functions */

static int obj_conn_package_register(lua_State *L, void *var, void *var2)
{
    conn *c = var2;
    my_callback_obj **o;

    if (lua_gettop(L) != 2)
        return luaL_error(L, "Wrong number of arguments");

    if (lua_isnil(L, 2)) {
        c->package_callback = NULL;
        if (c->package_callback_ref != 0)
            luaL_unref(L, LUA_REGISTRYINDEX, c->package_callback_ref);
        c->package_callback_ref = 0;
        return 0;
    }

    o = luaL_checkudata(L, 2, "dpm.callback");
    c->package_callback = (*o)->callback;
    c->package_callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

/* Registers a single callback into a connection or callback object. 
 * Argument should be a number + function */
static int obj_callback_register(lua_State *L, void *var, void *var2)
{
    int *callback = var;
    int state_number;
    int t;

    if (lua_gettop(L) < 3) {
        lua_pushnil(L);
        return 1;
    }

    state_number = luaL_checkinteger(L, 2);

    /* TODO: Should this "max" be defined near the enum? */
    if (state_number > TOTAL_STATES - 1)
        luaL_error(L, "Invalid callback state number %d!", state_number);

    t = lua_type(L, 3);
    if (t == LUA_TFUNCTION) {
        /* Toss a copy of the function to the top of the stack. */
        lua_pushvalue(L, 3);

        /* ... and collapse it into a reference. */
        callback[state_number] = luaL_ref(L, LUA_REGISTRYINDEX);
    } else if (t == LUA_TNIL) {
        if (callback[state_number] != 0)
            luaL_unref(L, LUA_REGISTRYINDEX, callback[state_number]);

        callback[state_number] = 0;
    } else {
        luaL_error(L, "Argument for callback must be a function or nil");
    }

    return 0;
}

/* Stub for field full (re)write accessor. */
static int obj_field_full(lua_State *L, void *var, void *var2)
{
    return 0;
}

/* Poorly named minimal accessor for field sets. Set the name and type fields.
 */
static int obj_field_name(lua_State *L, void *var, void *var2)
{
    my_field_packet *p = var2;
    const char *fname;
    size_t len;

    if (lua_gettop(L) < 2 && p->fields) {
        lua_pushlstring(L, (const char *) p->name, p->name_len);
        lua_pushinteger(L, p->type);
        return 2;
    }

    /* Pull in a string field, then an integer field if there're enough args.
     * size p->fields to the length of the 'name' field plus enough space to
     * null out the rest of the fields.
     * I guess only 'type' needs to be changed, otherwise.
     */

    fname = lua_tolstring(L, 2, &len);

    /* Of course, we have to completely wipe what's there. */
    if (p->fields)
        free(p->fields);

    p->fields = malloc( len + 16 ); /* Too lazy to count it out. */
    if (p->fields == NULL)
        luaL_error(L, "Failed to allocate memory for field packet");

    p->catalog_len = 3;
    p->catalog     = p->fields;
    strcpy((char *) p->catalog, "def");

    p->db_len        = 0;
    p->table_len     = 0;
    p->org_table_len = 0;
    p->org_name_len  = 0;

    p->name_len      = len;
    p->name          = p->fields + 3;
    memcpy(p->name, fname, len);

    if (lua_type(L, 3) != LUA_TNONE) {
        p->type = lua_tointeger(L, 3);
    } else {
        p->type = MYSQL_TYPE_STRING;
    }

    return 0;
}

/* These are magic accessors for the resultset object.
 * The resultset must hold references to valid field objects in order for
 * there to be a "low level" mechanism for packing and parsing row packets.
 *
 * Fields are added or removed one at a time to build up the object, then rows
 * are packed or parsed as fast as we can. using local pointers.
 * This means it's important that the resultset destructor remember to
 * remove the lua reference on any field objects so they may be garbage
 * collected.
 */

/* It will be faster if you pre-allocate the field storage by specifying the
 * final field_count ahead of time. The 'add_field' function will also expand
 * memory as needed to make it easier to use in obscure ways.
 */
static int obj_rset_field_count(lua_State *L, void *var, void *var2)
{
    my_rset_packet *p = var2;
    my_rset_field_header *new_fields;

    if (lua_gettop(L) < 2) {
        lua_pushinteger(L, *(int*)var);
        return 1;
    }
    uint64_t new_count = (uint64_t)luaL_checkinteger(L, 2);

    /* This number can "technically" be anything, but lets be
     * reasonable and try to avoid memory implosion. */
    /* FIXME: Should also ensure it's positive and return error to lua. */
    if (new_count > 32768)
        new_count = 32768;

    if (p->fields && new_count > p->field_count) {
        /* Only have to resize if the new value is bigger. */
        /* FIXME: I hate this line. */
        new_fields = realloc(p->fields, 
                     ( sizeof (my_rset_field_header) * p->field_count ) +
                     ( sizeof (my_rset_field_header) * 
                     ( new_count - p->field_count ) ) );

        /* FIXME: Bubble error to lua. */
        if (new_fields == NULL) {
            perror("Realloc fields array");
            return 0;
        }

        p->fields = new_fields;
    } else if (!p->fields) {
        p->fields = malloc( sizeof(my_rset_field_header) * new_count );
        /* FIXME: Propagate error to lua. */
        if (p->fields == NULL) {
            perror("Could not malloc()");
            return 0;
        }
    }

    p->field_count = new_count;

    return 0;
}

/* TODO: Should this allow injecting/removing to/from any point? */

/* Add to end of field header array. Store lua obj reference and cache
 * its internal pointer for later use.
 */
static int obj_rset_add_field(lua_State *L, void *var, void *var2)
{
    my_field_packet **f = luaL_checkudata(L, 2, "dpm.field");
    my_rset_packet *p   = var2;
    my_rset_field_header *new_fields;

    if (!(*f)->fields)
        luaL_error(L, "Must use initialized field object");

    /* field_count describes the size of the fields array... */
    if (p->field_count < p->fields_total + 1) {
        new_fields = realloc(p->fields, ( sizeof (my_rset_field_header) *
                             ( p->field_count + 1 ) ) );

        /* FIXME: Bubble errors to lua. */
        if (new_fields == NULL) {
            perror("Growing fields array");
            return 0;
        }

        p->fields = new_fields;
        p->field_count = p->fields_total + 1;
    }

    p->fields[p->fields_total].f   = *f;
    p->fields[p->fields_total].ref = luaL_ref(L, LUA_REGISTRYINDEX);
    p->fields_total++;

    return 0;
}

/* Pop field off of the end. Dereference the object and return it to lua? */
/* TODO: Collapse from index? Remove specific field? */
static int obj_rset_remove_field(lua_State *L, void *var, void *var2)
{
    my_rset_packet *p   = var2;

    if (p->fields_total == 0)
        return 0;

    if (p->fields[p->fields_total].f)
        luaL_unref(L, LUA_REGISTRYINDEX, p->fields[p->fields_total].ref);

    p->fields_total--;

    return 0;
}

/* Iterate over a table of columns passed in and store them as mysql length
 * encoded strings into a buffer. Can use lua's string buffer, or our own.
 */
static int obj_rset_pack_row(lua_State *L, void *var, void *var2)
{
    my_rset_packet *p = var2;
    luaL_Buffer b;
    unsigned int nargs = lua_gettop(L);
    unsigned int x;
    int base;
    char *tolua;
    size_t len;

    /* The top of the stack should be a row object to stuff data into. */
    my_row_packet **row = luaL_checkudata(L, 2, "dpm.row");

    /* The rest should be the fields in the row. Make sure the number of args
     * left == the fields_total.
     */
    if (p->field_count != nargs - 2)
        return luaL_error(L, "Number of provided columns does not match the field number: %d", (int) p->field_count);

    /* It doesn't matter what the fields were right now. They all end up as
     * strings for the moment. We could handle floats or timestamps or blah
     * specially, but not right now.
     */
    luaL_buffinit(L, &b);
    nargs++;

    for (x = 3; x != nargs; x++) {
        /* Find how long a value is, and convert numerics to strings. */
        lua_tolstring(L, x, &len);

        /* func takes uchar */
        /* Pack in the length of the data segment. */
        tolua = luaL_prepbuffer(&b);
        base = 0;

        my_write_binary_field((unsigned char *) tolua, &base, (uint64_t) len);
        luaL_addsize(&b, base);

        /* Then we pull one of the arguments to the _top_ and pack that in. */
        lua_pushvalue(L, x);
        /* Appends string, pops value. */
        luaL_addvalue(&b);
    }

    /* Complete the buffer, then store a reference to the final value. */
    luaL_pushresult(&b);

    if ((*row)->packed_row_lref)
        luaL_unref(L, LUA_REGISTRYINDEX, (*row)->packed_row_lref);

    (*row)->packed_row_lref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

/* Iterate over the associated fields to pull length encoded values out of a
 * row packet and into a lua table, return the table. Should attempt to store
 * numerics as numeric, strings as strings.
 * Folks should use parse_as_array for speed. parse_as_table for convenience.
 */

/* Should we define the magic value here? Boring. 0 is array, 1 is table. */
static int _rset_parse_data(my_rset_packet *rset, int type)
{
    my_row_packet **row   = luaL_checkudata(L, 2, "dpm.row");
    unsigned int i;
    int base = 0;
    const char *rdata, *end;
    uint64_t len;

    lua_rawgeti(L, LUA_REGISTRYINDEX, (*row)->packed_row_lref);
    rdata = lua_tolstring(L, -1, &len);
    end = rdata + len;

    /* We can pre-allocate the table. */
    if (type == 0) {
        lua_createtable(L, rset->field_count, 0);
    } else {
        lua_createtable(L, 0, rset->field_count);
    }

    for (i = 0; i < rset->fields_total; i++) {
        if (rdata >= end)
            return luaL_error(L, "There are more fields defined than row data!");

        len = (size_t) my_read_binary_field((unsigned char *) rdata, &base);
        rdata += base;
        base   = 0;

        /* Push the index for the next value. */
        if (type == 0) {
            lua_pushinteger(L, i);
        } else {
            lua_pushlstring(L, (char *) rset->fields[i].f->name,
                               (size_t) rset->fields[i].f->name_len);
        }

        if (len == MYSQL_NULL) {
            lua_pushnil(L);
        } else { 
            /* Leaves the next value at the top of the stack. */
            lua_pushlstring(L, (char *) rdata, len);
            rdata += len;
        }

        /* Now collapse savely into the table. */
        lua_settable(L, -3);
    }

    /* Return just the table to lua. */
    return 1;
}

static int obj_rset_parse_row_array(lua_State *L, void *var, void *var2)
{
    return _rset_parse_data(var2, 0);
}

static int obj_rset_parse_row_table(lua_State *L, void *var, void *var2)
{
    return _rset_parse_data(var2, 1);
}

/* Storage of MySQL "dynamic length" variables */
/* FIXME: All of these malloc'ing string functions need to bubble errors
 * up to lua.
 */
static int obj_lstring(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushlstring(L, (char *)var, *(uint64_t *)var2);
    } else {
        size_t len = 0;
        void **lstring = var;

        const char *str = luaL_checklstring(L, 2, &len);
        free(*lstring);
        len++;
        *lstring = (char *)malloc(len);

        if (*lstring == NULL) {
            perror("malloc");
            return 0;
        }

        memcpy(*lstring, str, len);
        return 0;
    }

    return 1;
}

/* Store fixed length \0 terminated strings to to/from lua */
static int obj_string(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushstring(L, var);
    } else {
        size_t len = 0;
        unsigned int *maxlen = var2;
        const char *str = luaL_checklstring(L, 2, &len);
        len++;

        /* FIXME: Everything should have a maximum. Remove this! */
        if (*maxlen != 0 && len > *maxlen) {
            return luaL_error(L, "Argument too long to store. Max [%d]", *maxlen);
        }

        strncpy((char *)var, str, len);
        return 0;
    }

    return 1;
}

/* Store \0 terminated strings to to/from lua.
 * There's an extra indirection if the string was a malloc case
 * FIXME: What would be a good upper bounds here?
 */
static int obj_pstring(lua_State *L, void *var, void *var2)
{

    void **pstring = var;
    if (lua_gettop(L) < 2) {
        lua_pushstring(L, (char *)*pstring);
    } else {
        size_t len = 0;
        const char *str = luaL_checklstring(L, 2, &len);
        free(*pstring);
        len++;
        *pstring = (char *)malloc(len);

        if (*pstring == NULL) {
            perror("malloc");
            return 0;
        }

        memcpy(*pstring, str, len);
        return 0;
    }

    return 1;
}

/* Sets/returns bit flags within a value. 
 * If one arg, returns flag val. If two arg, sets flag to a boolean of second
 * arg.
 * FIXME: Untested
 * Arguments are all 16-bit, but tihs uses 'int'!
 */
static int obj_flags(lua_State *L, void *var, void *var2)
{
    int flag = 0;
    int top = lua_gettop(L);
    if (top < 2) {
        luaL_error(L, "Must specify a flag to retrieve or set");
    } else if (top == 2) {
        /* This should be a flag fetch. */
        flag = luaL_checkint(L, 2);
        lua_pushboolean(L, *(int *)var & flag);
    } else if (top == 3) {
        /* This should be a flag set. */
        flag = luaL_checkint(L, 2);

        if (lua_toboolean(L, 3)) {
            *(int *)var |= flag;
        } else {
            *(int *)var &= ~flag;
        }

        return 0;
    } else {
        luaL_error(L, "Flags need only FLAG, BOOLEAN as arguments");
    }

    return 1;
}

/* It's just an int... we can do bounds checking sometime. */
static int obj_enum(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushinteger(L, *(int*)var);
    } else {
        *(int *)var = luaL_checkint(L, 2);
        return 0;
    }

    return 1;
}

static int obj_int(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushinteger(L, *(int*)var);
    } else {
        *(int *)var = luaL_checkint(L, 2);
        return 0;
    }

    return 1;
}

static int obj_uint64_t(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushinteger(L, *(uint64_t*)var);
    } else {
        /* FIXME: Casting a signed int to an unsigned with no checks is insane
         */
        *(uint64_t *)var = (uint64_t)luaL_checkinteger(L, 2);
        return 0;
    }

    return 1;
}

static int obj_uint32_t(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushinteger(L, *(uint32_t*)var);
    } else {
        /* FIXME: Casting a signed int to an unsigned with no checks is insane
         */
        *(uint32_t *)var = (uint32_t)luaL_checkinteger(L, 2);
        return 0;
    }

    return 1;
}

static int obj_uint16_t(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushinteger(L, *(uint16_t*)var);
    } else {
        /* FIXME: Casting a signed int to an unsigned with no checks is insane
         */
        *(uint16_t *)var = (uint16_t)luaL_checkinteger(L, 2);
        return 0;
    }

    return 1;
}

static int obj_uint8_t(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushinteger(L, *(uint8_t*)var);
    } else {
        /* FIXME: Casting a signed int to an unsigned with no checks is insane
         */
        *(uint8_t *)var = (uint8_t)luaL_checkinteger(L, 2);
        return 0;
    }

    return 1;
}

/* Object construction functions... */

/* Here we add specific object accessors into a metatable. Using C closures to
 * easily pull the struct back in on callback. */
static void obj_add(lua_State *L, obj_reg *r)
{
    for (; r->name; r++) {
        lua_pushstring(L, r->name);
        lua_pushlightuserdata(L, (void *)r);
        lua_pushcclosure(L, obj_index, 1);
        lua_rawset(L, -3);
    }
}

/* _non_ lua centric object creatorabobble. */
int new_obj(lua_State *L, void *p, const char *type)
{
    void **u = (void **)lua_newuserdata(L, sizeof(void **));
    *u = p;
    luaL_getmetatable(L, type);
    lua_setmetatable(L, -2);
    /* The userdata's on the stack. Call up to lua... */
    return 1;
}

/* Lua-centric automated object builder. */
static int new_lua_obj(lua_State *L)
{
    void *o;
    void **u; 
    lua_pushvalue(L, lua_upvalueindex(1)); /* Registration struct. */

    if (lua_islightuserdata(L, -1)) {
        obj_toreg *oreg = (obj_toreg *)lua_touserdata(L, -1);
        lua_pop(L, 1);
        o = oreg->obj_new_func();
        if (o) {
            u = (void **)lua_newuserdata(L, sizeof(void **));
            *u = o;
            luaL_getmetatable(L, oreg->name);
            lua_setmetatable(L, -2);
        } else {
            luaL_error(L, "Unable to create object!");
        }
    } else {
        luaL_error(L, "Not a light user data object... [%s]", lua_typename(L, lua_type(L, lua_upvalueindex(1))));
    }
    return 1;
}

/* Pseudo index function called on every access. This guy parses out the
 * accessor struct, handles read/write protectiveness, and makes the official
 * accessor call. */
static int obj_index(lua_State *L)
{
    void **p;
    if (!lua_isuserdata(L, 1)) {
        luaL_error(L, "Expected userdata, got [%s]", lua_typename(L, lua_type(L,
 1)));
    }

    lua_pushvalue(L, lua_upvalueindex(1)); /* Accessor struct */

    if (lua_islightuserdata(L, -1)) {
        obj_reg *f = (obj_reg *)lua_touserdata(L, -1);
        lua_pop(L, 1);
        /* We must test for rw perms here */
        if (f->type == LO_READONLY && lua_gettop(L) > 1) {
            luaL_error(L, "Value is read only");
        }
        p = lua_touserdata(L, 1);
        return f->func(L, *p + f->offset1, f->offset2 ? *p + f->offset2 : *p);
    } else {
        luaL_error(L, "Not a light user data object... [%s]", lua_typename(L, lua_type(L, lua_upvalueindex(1))));
    }

    return 0;
}

/* This is "heavily inspired" by proxy_lua_init_global_fenv in MySQL Proxy.
 * I say inspired by, even though this is a close copy, because it inspired me
 * to stop trying to find a way to build it off of proxy.h and just do it.
 * Really wish there was a way to only write these once.
 */
int register_obj_defines(lua_State *L)
{

#define DPM_D(x) \
    lua_pushinteger(L, x); \
    lua_setfield(L, -2, #x);

    /* Proxy internal defines. */

    DPM_D(MY_SERVER);
    DPM_D(MY_CLIENT);

    DPM_D(DPM_OK);
    DPM_D(DPM_NOPROXY);
    DPM_D(DPM_FLUSH_DISCONNECT);

    /* State fields. */
    DPM_D(MYS_CONNECT)
    DPM_D(MYC_CONNECT)
    DPM_D(MYS_SENT_HANDSHAKE)
    DPM_D(MYC_WAIT_HANDSHAKE)
    DPM_D(MYC_WAITING)
    DPM_D(MYS_WAITING)
    DPM_D(MYC_SENT_CMD)
    DPM_D(MYS_SENDING_FIELDS)
    DPM_D(MYS_SENDING_ROWS)
    DPM_D(MYS_WAIT_AUTH)
    DPM_D(MYS_SENDING_OK)
    DPM_D(MYS_WAIT_CMD)
    DPM_D(MYS_SENDING_RSET)
    DPM_D(MYC_WAIT_AUTH)
    DPM_D(MYS_SENDING_HANDSHAKE)
    DPM_D(MYS_RECV_ERR)
    DPM_D(MY_CLOSING)
    DPM_D(MYS_SENDING_STATS)
    DPM_D(MYS_GOT_CMD)
    DPM_D(MYS_SENDING_EOF)
    DPM_D(MYS_SENT_RSET)
    DPM_D(MYS_SENT_FIELDS)

    /* MySQL Protocol layer defines. */

    DPM_D(COM_SLEEP);
    DPM_D(COM_QUIT);
    DPM_D(COM_INIT_DB);
    DPM_D(COM_QUERY);
    DPM_D(COM_FIELD_LIST);
    DPM_D(COM_CREATE_DB);
    DPM_D(COM_DROP_DB);
    DPM_D(COM_REFRESH);
    DPM_D(COM_SHUTDOWN);
    DPM_D(COM_STATISTICS);
    DPM_D(COM_PROCESS_INFO);
    DPM_D(COM_CONNECT);
    DPM_D(COM_PROCESS_KILL);
    DPM_D(COM_DEBUG);
    DPM_D(COM_PING);
    DPM_D(COM_TIME);
    DPM_D(COM_DELAYED_INSERT);
    DPM_D(COM_CHANGE_USER);
    DPM_D(COM_BINLOG_DUMP);
    DPM_D(COM_TABLE_DUMP);
    DPM_D(COM_CONNECT_OUT);
    DPM_D(COM_REGISTER_SLAVE);
    DPM_D(COM_STMT_PREPARE);
    DPM_D(COM_STMT_EXECUTE);
    DPM_D(COM_STMT_SEND_LONG_DATA);
    DPM_D(COM_STMT_CLOSE);
    DPM_D(COM_STMT_RESET);
    DPM_D(COM_SET_OPTION);
    DPM_D(COM_STMT_FETCH);
    DPM_D(COM_DAEMON);

    DPM_D(MYSQL_TYPE_DECIMAL);
    DPM_D(MYSQL_TYPE_NEWDECIMAL);
    DPM_D(MYSQL_TYPE_TINY);
    DPM_D(MYSQL_TYPE_SHORT);
    DPM_D(MYSQL_TYPE_LONG);
    DPM_D(MYSQL_TYPE_FLOAT);
    DPM_D(MYSQL_TYPE_DOUBLE);
    DPM_D(MYSQL_TYPE_NULL);
    DPM_D(MYSQL_TYPE_TIMESTAMP);
    DPM_D(MYSQL_TYPE_LONGLONG);
    DPM_D(MYSQL_TYPE_INT24);
    DPM_D(MYSQL_TYPE_DATE);
    DPM_D(MYSQL_TYPE_TIME);
    DPM_D(MYSQL_TYPE_DATETIME);
    DPM_D(MYSQL_TYPE_YEAR);
    DPM_D(MYSQL_TYPE_NEWDATE);
    DPM_D(MYSQL_TYPE_ENUM);
    DPM_D(MYSQL_TYPE_SET);
    DPM_D(MYSQL_TYPE_TINY_BLOB);
    DPM_D(MYSQL_TYPE_MEDIUM_BLOB);
    DPM_D(MYSQL_TYPE_LONG_BLOB);
    DPM_D(MYSQL_TYPE_BLOB);
    DPM_D(MYSQL_TYPE_VAR_STRING);
    DPM_D(MYSQL_TYPE_STRING);
    DPM_D(MYSQL_TYPE_GEOMETRY);
    DPM_D(MYSQL_TYPE_BIT);

    return 1;
}

/* Registers connection object + methods, defined at top, into lua */
int register_obj_types(lua_State *L)
{
    obj_toreg *r = regs;

    /* Call a separate function for filtering MYSQL_BLAH and related defines
     * into the lua namespace.
     */
    register_obj_defines(L);

    /* We need to iterate twice... Since the main function table _must_
     * be at the top of the stack at the time we're being called.
     */
    for (; r->name; r++) {
        if (!r->obj_new_name)
            continue;
        lua_pushstring(L, r->obj_new_name);
        lua_pushlightuserdata(L, (void *)r);
        lua_pushcclosure(L, new_lua_obj, 1);
        lua_settable(L, -3);
    }
    lua_pop(L, 1);
    r = regs;
    for (; r->name; r++) {
        luaL_newmetatable(L, r->name);
        luaL_register(L, NULL, r->methods);
        obj_add(L, r->accessors); /* Push it, push it real good. */
        /* metatable.__index = metatable */
        lua_pushvalue(L, -1); /* Create a copy to fold into the metamethod */
        lua_setfield(L, -2, "__index");
        lua_pop(L, 1);
    }

    return 1;
}
