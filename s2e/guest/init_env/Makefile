MYCFLAGS = $(CFLAGS) -m32 -Wall -g -O0 -I../include -std=c99
MYCXXFLAGS = $(CXX_FLAGS) -m32 -Wall -g -O0 -I../include
LDLIBS = -ldl
CC = gcc
CXX = g++

BINARIES=init_env.so

%.so: %.c
	$(CC) $(MYCFLAGS) -fPIC -shared -o $@ $^ $(LDLIBS)

.PHONY: all
all: $(BINARIES)

.PHONY: clean
clean:
	rm -f $(BINARIES)

install: $(BINARIES)
	cp $(BINARIES) $(BUILD_DIR)
