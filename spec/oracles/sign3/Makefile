PROGRAM = sign3
PROGRAM_FILES = sign3.c


CC=gcc
CFLAGS += -Iinclude
CFLAGS	+= $(shell xmlsec1-config --cflags)
LDFLAGS	+=
LIBS 	+= $(shell xmlsec1-config --libs)

all: $(PROGRAM)

%: %.c
		$(CC) $(PROGRAM_FILES) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(LIBS)

clean:
		@rm -rf $(PROGRAM)

