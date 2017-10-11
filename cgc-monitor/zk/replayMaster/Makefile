PACKAGE_NAME    = cgc-monitor-replay-master
BINARY              = replay_master
FINAL              = finalSetup.sh
DTD              = replay_master.dtd
MAN                             = $(BINARY).1.gz $(FINAL).1.gz 
BIN                     = $(DESTDIR)/usr/bin
MANDIR                  = $(DESTDIR)/usr/share/man/man1
DTDDIR                  = $(DESTDIR)/usr/share/cgc-monitoring
OBJS                = src/replayMaster.o src/log.o src/config.o src/package.o src/xmlutil.o ../serviceMaster/src/repoUtils.o
UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
#CC                  = g++
#LD                  = g++
CC                  = gcc
LD                  = gcc
INC = -I/usr/local/include/zookeeper -I../serviceMaster/src -I../replayMaster/src -I/usr/include/libxml2
LIBS += /usr/local/lib/libzookeeper_mt.a
LIBS += -lxml2 -lz -lm
endif
ifeq ($(UNAME), FreeBSD)
CC                  = clang
LD                  = clang

LIBS += /usr/local/lib/libzookeeper_mt.a
LIBS += -lpmc  -lxml2 -lz -llzma -lm
#LIBS += -lm /usr/local/lib/libxml2.a /usr/lib/libm.a
INC += -I/usr/local/include -I/usr/local/include/zookeeper -I../serviceMaster/src -I../replayMaster/src -I/usr/local/include/libxml2
#OTHER_LIBS = -lm /usr/local/lib/libxml2.a /usr/lib/libm.a

LDFLAGS += -static
endif

#MY_LIBS = /usr/local/lib/libzookeeper_mt.a $(OTHER_LIBS)

LDFLAGS += -Wl,-z,relro -Wl,-z,now -pthread -L/usr/local/lib

#CFLAGS += -O3 -g -D_FORTIFY_SOURCE=2 -fstack-protector -fPIE
#CFLAGS += -O3 -g 
#CFLAGS += -Werror -Wno-variadic-macros
#CFLAGS += -DRANDOM_UID -DHAVE_SETRESGID
#CFLAGS += -m32
# CFLAGS += -fsanitize=undefined-trap -fsanitize-undefined-trap-on-error -Wno-disabled-macro-expansion
#CFLAGS += -O3 -g -D_FORTIFY_SOURCE=2 -fstack-protector -fpic
CFLAGS += -O3 -g -D_FORTIFY_SOURCE=2 -fpic
CFLAGS += -Werror -Wno-variadic-macros
CFLAGS += -DRANDOM_UID -DHAVE_SETRESGID

#LDFLAGS += -m32

all: $(BINARY) $(FINAL) man

$(BINARY): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

%.1.gz: %.md
	pandoc -s -t man $< -o $<.tmp
	gzip -9 < $<.tmp > $@

man: $(MAN)
install: $(BINARY) $(MAN)
	ls -la $(MAN)
	install -d $(BIN)
	install $(BINARY) $(BIN)
	install $(FINAL) $(BIN)
	install -d $(DTDDIR)
	install $(DTD) $(DTDDIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f src/*.o $(BINARY) $(MAN) *.tmp

distclean: clean
