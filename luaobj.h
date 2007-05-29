/* Lua C object definitions. */

#ifndef LUAOBJ_H
#define LUAOBJ_H

typedef int (*obj_func) (lua_State *L, void *var);

#define LO_READONLY 0
#define LO_READWRITE 1

typedef const struct {
    const char *name; /* table index name */
    obj_func    func; /* Crazy object function type */
    int         type; /* 0 ro 1 rwr */
    size_t      offset1; /* Offset of the first variable */
} obj_reg;

typedef const struct {
    const char *name; /* metatable name (object type) */
    obj_reg    *accessors; /* array of accessors. */
} obj_toreg;

int register_obj_types(lua_State *L);
int new_conn_obj(lua_State *L, conn *c);

#endif /* LUAOBJ_H */
