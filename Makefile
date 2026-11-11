
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g

all: server client

server: src/server.c
	$(CC) $(CFLAGS) src/server.c -o server

client: src/client.c
	$(CC) $(CFLAGS) src/client.c -o client

clean:
	rm -f server client
	rm -f run/peercred.sock

.PHONY: all clean
