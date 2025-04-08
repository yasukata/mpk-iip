PROGS = libisolate-iip-mpk.so

CFLAGS += -O3 -pipe -g
CFLAGS += -rdynamic
CFLAGS += -Werror -Wextra -Wall
CFLAGS += -mpku
CFLAGS += -nostartfiles -nodefaultlibs -nostdlib -nostdinc
CFLAGS += -fPIC

LDFLAGS += -shared

C_OBJS = side-iip.o

OBJS += $(C_OBJS)

CLEANFILES = $(PROGS) $(OBJS)

.PHONY: all
all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
