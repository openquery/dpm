project(dpm C)
include(UsePkgConfig)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -Wextra -Wno-unused-parameter")

#
# locate lua via pkgconfig. debian uses versioned lua${ver}.pc files.
#
pkgconfig("lua5.1" LUA_INCLUDE_DIR LUA_LINK_DIR LUA_LDFLAGS LUA_CFLAGS)
if(NOT LUA_INCLUDE_DIR)
  pkgconfig("lua" LUA_INCLUDE_DIR LUA_LINK_DIR LUA_LDFLAGS LUA_CFLAGS)
  if(NOT LUA_INCLUDE_DIR)
    message(SEND_ERROR "lua 5.1 was not found (via pkgconfig)")
  endif(NOT LUA_INCLUDE_DIR)
endif(NOT LUA_INCLUDE_DIR)

message("${LUA_INCLUDE_DIR} ${LUA_LINK_DIR} ${LUA_LDFLAGS} ${LUA_CFLAGS}")

#
# libevent doesn't have a pkgconfig file,
# so we have to make some assumptions (user can override)
#
if(NOT LIBEVENT_PREFIX)
set(LIBEVENT_PREFIX "/usr")
endif(NOT LIBEVENT_PREFIX)

set(LIBEVENT_INCLUDE_DIR "${LIBEVENT_PREFIX}/include")
set(LIBEVENT_LINK_DIR "${LIBEVENT_PREFIX}/lib")
set(LIBEVENT_LDFLAGS "-levent")

#
# all files compiled in this directory get these additional paths
#
set_directory_properties(PROPERTIES
    INCLUDE_DIRECTORIES "${LUA_INCLUDE_DIR} ${LIBEVENT_INCLUDE_DIR}"
    LINK_DIRECTORIES "${LUA_LINK_DIR} ${LIBEVENT_LINK_DIR}")

#
# compile to 'dpm'
#
add_executable(dpm sha1.c luaobj.c dpm.c)
set_target_properties(dpm PROPERTIES
    COMPILE_FLAGS "${LUA_CFLAGS} ${LIBEVENT_CFLAGS}"
    LINK_FLAGS "${LUA_LDFLAGS} ${LIBEVENT_LDFLAGS}")
