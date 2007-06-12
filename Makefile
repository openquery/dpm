#
# DPM Makefile
#

CFLAGS = -g -Wall -Wextra -Wno-unused-parameter

#
# Lua might be prefixed to a non-/usr location
#
LUAPKG  = $(shell pkg-config --list-all | grep lua | cut -d\  -f1)
CFLAGS += $(shell pkg-config --cflags ${LUAPKG})
LIBS   += $(shell pkg-config --libs ${LUAPKG})

#
# Hack, assume libevent1 is in /usr
#
LIBS += -levent

#
# Et al.
#
objs = sha1.o luaobj.o dpm.o
target = dpm

all: ${objs}
	${CC} ${CFLAGS} ${objs} -o ${target} -levent ${LIBS}

clean:
	rm -f ${objs} ${target}

%.o: %.c
	${CC} ${CFLAGS} -c $< -o $@
