YAMPServer:
	gcc -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include -I/usr/include/sysprof-6 -pthread main.c -lcjson -lsqlite3 -lcrypto -lssl -lglib-2.0