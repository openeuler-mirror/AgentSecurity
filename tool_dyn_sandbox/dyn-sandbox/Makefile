CC := gcc
CFLAGS := -Wall -Wextra -O2

ifdef CONFIG_LANDLOCK_ENABLE
CFLAGS += -DCONFIG_LANDLOCK_ENABLE
endif

LDFLAGS :=
LDLIBS := -lyaml

SRCS := dyn-sandbox.c landlock.c seccomp_profiles.c policy_parser.c
OBJS := dyn-sandbox.o param_parse.o landlock.o seccomp_profiles.o policy_parser.o

TARGET := dyn-sandbox

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(TARGET)
