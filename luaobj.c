/* Lua C object binding C code... */

#include "proxy.h"
#include "luaobj.h"

/* Forward declarations */
static int tmp_gc(lua_State *L);

static int  obj_index(lua_State *L);
static void obj_add(lua_State *L, obj_reg *r);
static int  new_lua_obj(lua_State *L);

/* Accessors */
static int obj_int(lua_State *L, void *var, void *var2);
static int obj_enum(lua_State *L, void *var, void *var2);
static int obj_flags(lua_State *L, void *var, void *var2);
static int obj_string(lua_State *L, void *var, void *var2);
static int obj_lstring(lua_State *L, void *var, void *var2);
static int obj_uint64_t(lua_State *L, void *var, void *var2);
static int obj_uint32_t(lua_State *L, void *var, void *var2);
static int obj_uint16_t(lua_State *L, void *var, void *var2);
static int obj_uint8_t(lua_State *L, void *var, void *var2);

static const obj_reg conn_regs [] = {
    {"id", obj_uint64_t, LO_READONLY, offsetof(conn, id), 0},
    {"listener", obj_int, LO_READONLY, offsetof(conn, listener), 0},
    {"my_type", obj_uint8_t, LO_READONLY, offsetof(conn, my_type), 0},
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg handshake_regs [] = {
    {"protocol_version", obj_uint8_t, LO_READWRITE, offsetof(my_handshake_packet, protocol_version), 0},
    {"server_version", obj_string, LO_READONLY, offsetof(my_handshake_packet, server_version), 0},
    {"thread_id", obj_uint32_t, LO_READWRITE, offsetof(my_handshake_packet, thread_id), 0},
    {"scramble_buff", obj_string, LO_READONLY, offsetof(my_handshake_packet, scramble_buff), 0},
    {"server_capabilities", obj_flags, LO_READWRITE, offsetof(my_handshake_packet, server_capabilities), 0},
    {"server_language", obj_uint8_t, LO_READWRITE, offsetof(my_handshake_packet, server_language), 0},
    {"server_status", obj_flags, LO_READWRITE, offsetof(my_handshake_packet, server_status), 0},
    {NULL, NULL, 0, 0, 0},
};

static const obj_reg auth_regs [] = {
    {"client_flags", obj_flags, LO_READWRITE, offsetof(my_auth_packet, client_flags), 0},
    {"max_packet_size", obj_uint32_t, LO_READWRITE, offsetof(my_auth_packet, max_packet_size), 0},
    {"charset_number", obj_uint8_t, LO_READWRITE, offsetof(my_auth_packet, charset_number), 0},
    {"user", obj_string, LO_READWRITE, offsetof(my_auth_packet, user), 0},
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
    {"sqlstate", obj_string, LO_READWRITE, offsetof(my_err_packet, sqlstate), 0},
    {"message", obj_string, LO_READWRITE, offsetof(my_err_packet, message), 0},
    {NULL, NULL, 0, 0, 0},
};

static const luaL_Reg generic_m [] = {
    {"__gc", tmp_gc},
    {NULL, NULL},
};

static const obj_toreg regs [] = {
    {"myp.conn", conn_regs, generic_m, NULL, NULL},
    {"myp.handshake", handshake_regs, generic_m, my_new_handshake_packet, "new_handshake_pkt"},
    {"myp.auth", auth_regs, generic_m, my_new_auth_packet, "new_auth_pkt"},
    {"myp.ok", ok_regs, generic_m, my_new_ok_packet, "new_ok_pkt"},
    {"myp.err", err_regs, generic_m, my_new_err_packet, "new_err_pkt"},
    {NULL, NULL, NULL, NULL, NULL},
};

static int tmp_gc(lua_State *L)
{
    fprintf(stdout, "Tried to garbage collect something.\n");
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
static int obj_lstring(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushlstring(L, (char *)var, *(uint64_t *)var2);
    } else {
        luaL_error(L, "Dynamic length variables are presently read-only");
    }

    return 1;
}

/* Sends \0 terminated strings to to/from lua */
static int obj_string(lua_State *L, void *var, void *var2)
{
    if (lua_gettop(L) < 2) {
        lua_pushstring(L, (char *)var);
    } else {
        luaL_error(L, "String functions are presently read-only");
    }

    return 1;
}

/* Sets/returns bit flags within a value. 
 * If one arg, returns flag val. If two arg, sets flag to a boolean of second
 * arg.
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
        return f->func(L, *p + f->offset1, f->offset2 ? *p + f->offset2 : 0);
    } else {
        luaL_error(L, "Not a light user data object... [%s]", lua_typename(L, lua_type(L, lua_upvalueindex(1))));
    }

    return 0;
}

/* Registers connection object + methods, defined at top, into lua */
int register_obj_types(lua_State *L)
{
    obj_toreg *r = regs;
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

