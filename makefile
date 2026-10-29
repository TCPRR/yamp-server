CFLAGS = -DOPENSSL_API_3_0
yampd: main.c request.c handlers.c globals.c
	gcc -g -O0 $(CFLAGS) -fno-omit-frame-pointer -fsanitize=address,undefined -Iext/civetweb/include -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I/usr/include/sysprof-6 -pthread *.c hmap/*.c ext/civetweb/src/civetweb.c -lcjson -lcurl -lsqlite3 -lcrypto -lssl -lglib-2.0 -o yampd