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

/* Lua C object definitions. */

#ifndef LUAOBJ_H
#define LUAOBJ_H

typedef int (*obj_func) (lua_State *L, void *var, void *var2);
typedef void *(*obj_new) ();

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
    const obj_new     obj_new_func; /* make new object function */
    const char       *obj_new_name; /* Name of function for making new packet */
} obj_toreg;

void dump_stack();
int register_obj_types(lua_State *L);
int new_obj(lua_State *L, void *p, const char *type);

#endif /* LUAOBJ_H */
