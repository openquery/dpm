project(dpm C)
include(UsePkgConfig)
# Cmake < 2.4.6 does not have FindPkgConfig
include(FindPkgConfig OPTIONAL)
cmake_minimum_required(VERSION 2.4.5)

option(DEBUG "Compile DPM in DEBUG mode")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-unused-parameter")

#
# TODO: Also make this pass -DDEBUG to the compilation phase.
#
if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
    message("Compiling in debug mode")
else(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
    message("Compiling in optimized mode")
endif(DEBUG)

#
# locate pkgconfig - only verify if pkgconfig exists
# This is an extra verification step if FindPkgConfig exists.
# We use the variables exposed by UsePkgConfig instead.
#
if(PKG_CONFIG_FOUND)
    message(STATUS "Using pkg-config")
    pkg_check_modules(LUA lua>=5.1)

    if(NOT LUA_VERSION)
        pkg_check_modules(LUA lua51>=5.1)
        if (NOT LUA_VERSION)
            message(SEND_ERROR "lua 5.1 was not found (via find pkgconfig)")
        endif(NOT LUA_VERSION)
    endif(NOT LUA_VERSION)
endif(PKG_CONFIG_FOUND)

#
# locate lua via pkgconfig. debian uses versioned lua${ver}.pc files.
#
if(PKGCONFIG_EXECUTABLE)
    pkgconfig("lua5.1" LUA_INCLUDE_DIR LUA_LINK_DIR LUA_LDFLAGS LUA_CFLAGS)
    if(NOT LUA_INCLUDE_DIR)
      pkgconfig("lua" LUA_INCLUDE_DIR LUA_LINK_DIR LUA_LDFLAGS LUA_CFLAGS)
      if(NOT LUA_INCLUDE_DIR)
        message(SEND_ERROR "lua 5.1 was not found (via use pkgconfig)")
      endif(NOT LUA_INCLUDE_DIR)
    endif(NOT LUA_INCLUDE_DIR)
endif(PKGCONFIG_EXECUTABLE)

#
# If there is no pkg-config, emulate FIND_PACKAGE behavior to locate lua.
#
if(NOT LUA_INCLUDE_DIR)
    find_path(LUA_INCLUDE_DIR NAMES lua.h PATHS /usr/local/include PATH_SUFFIXES lua51)
    find_library(LUA_LIBRARY NAMES lua PATHS /usr/local/lib PATH_SUFFIXES lua51)

    if(LUA_INCLUDE_DIR AND LUA_LIBRARY)
        set(LUA_MANUALLY_FOUND TRUE)
        # Lua's always bound to -lm so far as I know...
	set(LUA_LDFLAGS "-lm")
    endif(LUA_INCLUDE_DIR AND LUA_LIBRARY)

    if(NOT LUA_MANUALLY_FOUND)
        message(FATAL_ERROR "Lua 5.1 was not found (via scanning)")
    endif(NOT LUA_MANUALLY_FOUND)
endif(NOT LUA_INCLUDE_DIR)

if(VERBOSE)
    message("${LUA_INCLUDE_DIR} ${LUA_LINK_DIR} ${LUA_LDFLAGS} ${LUA_CFLAGS}")
endif(VERBOSE)

#
# libevent doesn't have a pkgconfig file,
# so we have to make some assumptions (user can override)
#
if(NOT LIBEVENT_PREFIX)
    find_path(LIBEVENT_INCLUDE_DIR NAMES event.h)
    find_library(LIBEVENT_LIBRARY NAMES event)

    if(LIBEVENT_INCLUDE_DIR AND LIBEVENT_LIBRARY)
        set(LIBEVENT_FOUND TRUE)
    endif(LIBEVENT_INCLUDE_DIR AND LIBEVENT_LIBRARY)

    if(NOT LIBEVENT_FOUND AND NOT LIBEVENT_PREFIX)
        message(FATAL_ERROR "libevent library or header not found. Retry with -DLIBEVENT_PREFIX='/path/to/your/libevent'")
    endif(NOT LIBEVENT_FOUND AND NOT LIBEVENT_PREFIX)
endif(NOT LIBEVENT_PREFIX)

if(LIBEVENT_PREFIX)
    set(LIBEVENT_INCLUDE_DIR "${LIBEVENT_PREFIX}/include")
    set(LIBEVENT_LINK_DIR "${LIBEVENT_PREFIX}/lib")
    set(LIBEVENT_LDFLAGS "-levent")
    if(NOT EXISTS "${LIBEVENT_INCLUDE_DIR}/event.h")
        message(FATAL_ERROR "libevent's event.h header not found. Retry with -DLIBEVENT_PREFIX='/path/to/your/libevent'")
    endif(NOT EXISTS "${LIBEVENT_INCLUDE_DIR}/event.h")
endif(LIBEVENT_PREFIX)

#
# all files compiled in this directory get these additional paths
#
include_directories(${LUA_INCLUDE_DIR} ${LIBEVENT_INCLUDE_DIR})
link_directories(${LUA_LINK_DIR} ${LIBEVENT_LINK_DIR})

#
# compile to 'dpm'
#
add_executable(dpm sha1.c luaobj.c dpm.c)
set_target_properties(dpm PROPERTIES
    COMPILE_FLAGS "${LUA_CFLAGS} ${LIBEVENT_CFLAGS}"
    LINK_FLAGS "${LUA_LDFLAGS} ${LIBEVENT_LDFLAGS}")

add_definitions(-DDPMLIBDIR="\\"${CMAKE_INSTALL_PREFIX}/dpm\\"")

if(LUA_MANUALLY_FOUND)
    message(STATUS "Linking with manually detected lua")
    target_link_libraries(dpm ${LUA_LIBRARY})
endif(LUA_MANUALLY_FOUND)

if(LIBEVENT_FOUND)
    message(STATUS "Linking with manually detected libevent")
    target_link_libraries(dpm ${LIBEVENT_LIBRARY})
endif(LIBEVENT_FOUND)

#
# install phase - we have the proxy binary and lua libraries.
#
install(TARGETS dpm RUNTIME DESTINATION bin)
install(DIRECTORY lua DESTINATION dpm)
