PACKAGE_NAME    = cgc-monitor-service-master
BINARY              = service_master
DTD              = service_master.dtd
MAN                             = $(BINARY).1.gz 
BIN                     = $(DESTDIR)/usr/bin
MANDIR                  = $(DESTDIR)/usr/share/man/man1
DTDDIR                  = $(DESTDIR)/usr/share/cgc-monitoring
OBJS                = src/serviceMaster.o src/config.o ../replayMaster/src/package.o ../replayMaster/src/xmlutil.o src/repoUtils.o ../replayMaster/src/log.o
INC = -I/usr/local/include/zookeeper -I../replayMaster/src -I/usr/include/libxml2
MY_LIBS = /usr/local/lib/libzookeeper_mt.a
OTHER_LIBS = -lm -lxml2

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
#CC                  = g++
#LD                  = g++
CC                  = gcc
LD                  = gcc
INC = -I/usr/local/include/zookeeper -I../replayMaster/src -I/usr/include/libxml2
LIBS += /usr/local/lib/libzookeeper_mt.a
LIBS += -lxml2 -lz -lm
endif
ifeq ($(UNAME), FreeBSD)
CC                  = clang
LD                  = clang

LIBS += /usr/local/lib/libzookeeper_mt.a
LIBS += -lpmc  -lxml2 -lz -llzma -lm
INC = -I/usr/local/include/zookeeper -I../replayMaster/src -I../replayMaster/src -I/usr/local/include/libxml2
INC += -I/usr/local/include
LDFLAGS += -static
#OTHER_LIBS = -lm /usr/local/lib/libxml2.a /usr/lib/libm.a

endif

#MY_LIBS = /usr/local/lib/libzookeeper_mt.a $(OTHER_LIBS)

CFLAGS += -O3 -ggdb -D_FORTIFY_SOURCE=2 -fstack-protector -fPIE
CFLAGS += -Werror -Wno-variadic-macros
CFLAGS += -DRANDOM_UID -DHAVE_SETRESGID

LDFLAGS += -Wl,-z,relro -Wl,-z,now -pthread -L/usr/local/lib

all: $(BINARY) man

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
	install -d $(DTDDIR)
	install $(DTD) $(DTDDIR)
	install -d $(MANDIR)
	install $(MAN) $(MANDIR)

clean:
	-@rm -f src/*.o $(BINARY) $(MAN) *.tmp

distclean: clean
