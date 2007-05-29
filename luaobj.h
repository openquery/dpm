/* Lua C object definitions. */

#ifndef LUAOBJ_H
#define LUAOBJ_H

typedef int (*obj_func) (lua_State *L, void *var, void *var2);

#define LO_READONLY 0
#define LO_READWRITE 1

typedef const struct {
    const char *name; /* table index name */
    obj_func    func; /* crazy object function type */
    int         type; /* r/w flags */
    size_t      offset1; /* offset of the first variable */
    size_t      offset2; /* optional second offset (variable len) */
} obj_reg;

typedef const struct {
    const char *name; /* metatable name (object type) */
    const obj_reg    *accessors; /* array of indirect accessors. */
    const luaL_Reg   *methods; /* array of direct methods. */
} obj_toreg;

int register_obj_types(lua_State *L);
int new_conn_obj(lua_State *L, conn *c);

#endif /* LUAOBJ_H */
