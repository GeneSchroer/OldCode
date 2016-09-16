# Makefile - S/KEY v1.1b
#
# Neil M. Haller <nmh@thumper.bellcore.com>
# Philip R. Karn <karn@chicago.qualcomm.com>
# John S. Walden <jsw@thumper.bellcore.com>
# Scott Chasin <chasin@crimelab.com>

MANDIR  =  /usr/local/man/man8
DESTDIR =  /usr/local/bin

CFLAGS	=  -g -DUSE_ECHO# -Wall -Werror

LIB     =  libskey.a
LIBOBJS =  skeylogin.o skeysubr.o md4.o put.o
LIBSRCS =  skeylogin.c skeysubr.c md4.c put.c

what:
	@echo ""
	@echo "Please specify the type of system you are compiling on:"
	@echo ""
	@echo "Example: make sunos4"
	@echo ""

all:	$(LIB) key keyinit keysh done

setuid:
	chmod u+s keyinit keysh

install:
	chmod u+s keyinit keysh
	mv key $(BIN)
	mv keyinit $(BIN)
	mv keysh $(BIN)
centos:
	make all  RANLIB="echo" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS) /usr/lib/libcrypt.a"

key:    skey.c
	$(CC) -o $@ $(CFLAGS) skey.c $(LIB) $(SYSLIBS)

keyinit: skeyinit.c
	$(CC) -o $@ $(CFLAGS) skeyinit.c $(LIB) $(SYSLIBS) $(LDFLAGS)

keysh:  skeysh.c
	$(CC) -o $@ $(CFLAGS) skeysh.c $(LIB) $(SYSLIBS)

$(LIB): $(LIBOBJS)
	ar -rv $(LIB) $(LIBOBJS)
	$(RANLIB) $(LIB)

done:
	@echo "Make completed."

clean:
	rm -f key keyinit keysh *.o libskey.a *.bak *.BAK *.s tags
#LDFLAGS= /usr/lib/libcrypt.a
