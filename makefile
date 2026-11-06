CC = gcc
CFLAGS = -DOPENSSL_API_3_0 -fsanitize=address,undefined -g -O0 -fno-omit-frame-pointer
CFLAGS += -Iext/civetweb/include -pthread
CFLAGS += $(shell pkg-config --cflags glib-2.0)

LDLIBS = -lcjson -lcurl -lsqlite3 -lcrypto -lssl
LDLIBS += $(shell pkg-config --libs glib-2.0)

SOURCES = main.c network.c request.c handlers.c globals.c helpers.c http.c hmap/*.c ext/civetweb/src/civetweb.c

yampd: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(LDLIBS) -o yampd

clean:
	rm -f yampd