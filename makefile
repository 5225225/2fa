CC=clang
CFLAGS=-Wall -Wextra -Werror -g
LINK=-l pthread -l dl -l crypto

CCMD=$(CC) $(CFLAGS) $(LINK)
LCMD=$(CC) $(CFLAGS) -c

all: totp

totp: totp.o sqlite3.o
	$(CCMD) totp.o sqlite3.o -o totp

sqlite3.o: sqlite3.c
	$(LCMD) sqlite3.c
