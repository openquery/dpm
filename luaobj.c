/* Lua C object binding C code... */

#include "proxy.h"
#include "luaobj.h"

/* Forward declarations */
static void dump_stack();
static int tmp_gc(lua_State *L);

static int  obj_index(lua_State *L);
static void obj_add(lua_State *L, obj_reg *r);

/* Accessors */
static int obj_int(lua_State *L, void *var);
static int obj_uint64_t(lua_State *L, void *var);
static int obj_uint32_t(lua_State *L, void *var);
static int obj_uint16_t(lua_State *L, void *var);
static int obj_uint8_t(lua_State *L, void *var);

static const obj_reg conn_regs [] = {
    {"id", obj_uint64_t, LO_READONLY, offsetof(conn, id)},
    {"listener", obj_int, LO_READONLY, offsetof(conn, listener)},
    {NULL, NULL, 0, 0},
};

static const luaL_Reg conn_m [] = {
    {"__gc", tmp_gc},
    {NULL, NULL}
};

static const obj_toreg regs [] = {
    {"myp.conn", conn_regs, conn_m},
    {NULL, NULL, NULL},
};

static int tmp_gc(lua_State *L)
{
    fprintf(stdout, "Tried to garbage collect something.\n");
    return 0;
}

static void dump_stack()
{
    int top = lua_gettop(L);
    int i = 1;
    printf("TOP OF STACK [%d]\n", top);
    for (; i < top + 1; i++) {
        printf("STACK IS [%s]\n", lua_typename(L, lua_type(L, i)));
    }
}

/* Accessor functions */

static int obj_int(lua_State *L, void *var)
{
    if (lua_gettop(L) < 2) {
        lua_pushinteger(L, *(int*)var);
    } else {
        *(int *)var = luaL_checkint(L, 2);
        return 0;
    }

    return 1;
}

static int obj_uint64_t(lua_State *L, void *var)
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

static int obj_uint32_t(lua_State *L, void *var)
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

static int obj_uint16_t(lua_State *L, void *var)
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

static int obj_uint8_t(lua_State *L, void *var)
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

/* _non_ lua centric connection object creatorabobble. */
int new_conn_obj(lua_State *L, conn *c)
{
    lua_pushlightuserdata(L, (void *)c);

    luaL_getmetatable(L, "myp.conn");
    lua_setmetatable(L, -2);

    /* The userdata's on the stack. Call up to lua... */
    return 1;
}

/* Pseudo index function called on every access. This guy parses out the
 * accessor struct, handles read/write protectiveness, and makes the official
 * accessor call. */
static int obj_index(lua_State *L)
{
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
        return f->func(L, lua_touserdata(L, 1) + f->offset1);
    } else {
        luaL_error(L, "Not a light user data object... [%s]", lua_typename(L, lua_type(L, lua_upvalueindex(1))));
    }

    return 0;
}

/* Registers connection object + methods, defined at top, into lua */
int register_obj_types(lua_State *L)
{
    obj_toreg *r = regs;
    for (; r->name; r++) {
        luaL_newmetatable(L, r->name);
        luaL_register(L, NULL, r->methods);
        obj_add(L, r->accessors); /* Push it, push it real good. */
        /* metatable.__index = metatable */
        lua_pushvalue(L, -1); /* Create a copy to fold into the metamethod */
        lua_setfield(L, -1, "__index");

        lua_pop(L, 1);
    }

    return 1;
}

