PACKAGE_NAME = cgc-monitor-game-notify
GN_BINARY = game_notify 
GL_BINARY = game_listener
GN_OBJS = game_notify.o 
GL_OBJS = game_listener.o
#MAN                             = $(GN_BINARY).1.gz
BIN                     = $(DESTDIR)/usr/bin
#MANDIR                  = $(DESTDIR)/usr/share/man/man1

CC                  = gcc
LD                  = gcc
CFLAGS += -O3 -ggdb -D_FORTIFY_SOURCE=2 -fstack-protector -fPIE
CFLAGS += -Werror -Wno-variadic-macros
CFLAGS += -DRANDOM_UID -DHAVE_SETRESGID

LDFLAGS += -Wl,-z,relro -Wl,-z,now -L/usr/local/lib

#all: $(GN_BINARY) $(GL_BINARY) man
all: $(GN_BINARY) $(GL_BINARY) 

$(GN_BINARY): $(GN_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(GN_OBJS) $(LIBS)
$(GL_BINARY): $(GL_OBJS)
	$(LD) $(LDFLAGS) -o $@ $(GL_OBJS) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

#%.1.gz: %.md
#	pandoc -s -t man $< -o $<.tmp
#	gzip -9 < $<.tmp > $@

#man: $(MAN)
install: $(BINARY) $(MAN)
	ls -la $(MAN)
	install -d $(BIN)
	install $(GN_BINARY) $(GL_BINARY) $(BIN)
	#install -d $(MANDIR)
	#install $(MAN) $(MANDIR)

clean:
	-@rm -f src/*.o $(GL_BINARY) $(GN_BINARY) $(MAN) *.tmp

                                                                 
