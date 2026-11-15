#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <poll.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <glib.h>
#include "helpers.h"
#include "hmap/hashmap.h"
#include "globals.h"
#include "network.h"
#include "request.h"
#include "config.h"
#include "handlers.h"
#include "types.h"
#include "http.h"
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>

#define PORT 5224
#define SSLPORT 5225

Connection** client_sockets;
int nClients;
int* IPCSockets;
int nIPCClients;
sqlite3* DB;

void InsertMainRespOverride(char* key, char* value) {
	MainRespOverride override;
	override.key = strdup(key);
	override.val = strdup(value);
	respoverrides =
		realloc(respoverrides, sizeof(MainRespOverride) * (nrespoverrides + 1));
	respoverrides[nrespoverrides++] = override;
}

int epfd = -1;

void DisconnectClient(Connection* c) {
	int sd = c->fd;

	YampUser* usr = FindUserByFD(sd);
	if (usr) {
		int cnt;
		UserSession* ses = FindSessionByFD(sd);
		if (!ses) {
			return;
		}
		if (ses->prev)
			ses->prev->next = ses->next;
		else
			usr->sessions = ses->next;
		if (ses->next)
			ses->next->prev = ses->prev;
		free(ses->device);
		free(ses->token);

		if (!usr->sessions) { // last device gone
			char** relatedpeople = CollectRelatedUserIDs(usr->id, 0, &cnt);
			YampStatus* offline_stat = CreateOfflineStatus();
			for (int j = 0; j < cnt; j++) {
				PushStatusUpdate(relatedpeople[j], usr->id, offline_stat);
			}
			FreeStatusObject(offline_stat);
			FreeStrList(relatedpeople, cnt);

			hashmap_delete(UsersByID, usr);
			hashmap_delete(UsersByName, usr);
			FreeUserObject(usr);
		}
		hashmap_delete(UserSessionsByFD, ses);
	}

	epoll_ctl(epfd, EPOLL_CTL_DEL, sd, NULL);
	if (c->encrypt && c->ssl) {
		SSL_free(c->ssl);
		c->ssl = NULL;
	}
	close(sd);
	int i = c->idx;
	free(c);
	client_sockets[i] = client_sockets[--nClients];
	client_sockets[i]->idx = i;
}

int main() {
	UsersByName = hashmap_new(sizeof(YampUser), 256, 0, 0, hmap_username_hash,
							  hmap_username_compare, hmap_username_free, NULL);
	UsersByID = hashmap_new(sizeof(YampUser), 256, 0, 0, hmap_userid_hash,
							hmap_userid_compare, hmap_userid_free, NULL);
	UserSessionsByFD =
		hashmap_new(sizeof(UserSession), 256, 0, 0, hmap_session_hash,
					hmap_session_compare, hmap_session_free, NULL);

	sqlite3_open("yamp.db", &DB);
	int db_init_fd = open("yamp.db.sql", O_RDONLY);
	if (db_init_fd == -1) {
		perror("open yamp.db.sql");
		return -1;
	}

	struct stat init_stat;
	if (fstat(db_init_fd, &init_stat) == -1 || init_stat.st_size < 0) {
		perror("fstat yamp.db.sql");
		close(db_init_fd);
		return -1;
	}

	char* db_init_sql = malloc((size_t)init_stat.st_size + 1);
	if (!db_init_sql) {
		close(db_init_fd);
		return -1;
	}

	size_t total = 0;
	while (total < (size_t)init_stat.st_size) {
		ssize_t n = read(db_init_fd, db_init_sql + total,
						 (size_t)init_stat.st_size - total);
		if (n <= 0) {
			perror("read yamp.db.sql");
			free(db_init_sql);
			close(db_init_fd);
			return -1;
		}
		total += (size_t)n;
	}

	db_init_sql[total] = '\0';
	close(db_init_fd);
	char* err = NULL;

	if (sqlite3_exec(DB, db_init_sql, NULL, NULL, &err) != SQLITE_OK) {
		fprintf(stderr, "Database initialization failed! %s\n", err);
		sqlite3_free(err);
		sqlite3_exec(DB, "ROLLBACK;", NULL, NULL, NULL);
	}

	free(db_init_sql);

	int master_socket;
	int master_tls_socket;
	int valread, sd;
	struct sockaddr_in address = {.sin_family = AF_INET,
								  .sin_addr.s_addr = INADDR_ANY,
								  .sin_port = htons(PORT)};
	struct sockaddr_in tlsaddress = {.sin_family = AF_INET,
									 .sin_addr.s_addr = INADDR_ANY,
									 .sin_port = htons(SSLPORT)};

	// create and configure master socket, the one that will receive the
	// incomings
	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	master_socket = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	master_tls_socket = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(master_tls_socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

	bind(master_socket, (struct sockaddr*)&address, sizeof(address));
	bind(master_tls_socket, (struct sockaddr*)&tlsaddress, sizeof(address));
	listen(master_socket, 3);
	listen(master_tls_socket, 3);
	if (SSL_CTX_use_certificate_chain_file(ctx, CHAINFILE_PATH) <= 0) {
		printf("Error loading the certificate chain\n");
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVKEY_PATH, SSL_FILETYPE_PEM) <= 0) {
		printf("Error loading the private key chain\n");
	}
	SSL* serverssl = SSL_new(ctx);
	SSL_set_fd(serverssl, master_tls_socket);

	printf("server listening\n");

	InitYAMPHTTP();

	epfd = epoll_create1(0);
	if (epfd < 0) {
		perror("epoll_create1");
		return -1;
	}
	struct epoll_event ev = {0};



	ev.events = EPOLLIN;
	Connection master_socket_con = {0};
	master_socket_con.connected = 1;
	master_socket_con.encrypt = 0;
	master_socket_con.fd = master_socket;
	master_socket_con.listener = 1;

	ev.data.fd = master_socket;
	ev.data.ptr = &master_socket_con; // Master listener socket


	epoll_ctl(epfd, EPOLL_CTL_ADD, master_socket, &ev);

	struct epoll_event ev_tls = {0};

	ev_tls.events = EPOLLIN;

	Connection master_tls_socket_con = {0};
	master_tls_socket_con.connected = 1;
	master_tls_socket_con.encrypt = 1;
	master_tls_socket_con.fd = master_tls_socket;
	master_tls_socket_con.listener = 1;

	ev_tls.data.fd = master_tls_socket;
	ev_tls.data.ptr = &master_tls_socket_con; // Master TLS listener socket

	epoll_ctl(epfd, EPOLL_CTL_ADD, master_tls_socket, &ev_tls);

	struct epoll_event events[64];

	while (1) {
		// process a chunk of 64 at a time, the while loop will eventually make
		// it process them all
		int n = epoll_wait(epfd, events, 64, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait");
			break;
		}

		for (int k = 0; k < n; k++) {

			int fd = events[k].data.fd;
			int type = events[k].data.u64;

			Connection* c = events[k].data.ptr;

			if (c->listener && !c->encrypt) {
				int new_socket = accept(master_socket, NULL, NULL);
				if (new_socket < 0)
					continue;
				YAMPSend(new_socket, "{\"type\":\"hello\"}", 16);

				client_sockets = realloc(client_sockets,
										 sizeof(Connection*) * (nClients + 1));
				struct epoll_event ev = {0};

				ev.events = EPOLLIN;
				ev.data.fd = new_socket;
				Connection* new_con = malloc(sizeof(*new_con));
				*new_con = (Connection){0};
				new_con->connected = 1;
				new_con->encrypt = 0;
				new_con->fd = new_socket;
				new_con->listener = 0;
				new_con->idx = nClients;


				client_sockets[nClients] = new_con;
				ev.data.ptr = client_sockets[nClients];


				epoll_ctl(epfd, EPOLL_CTL_ADD, new_socket, &ev);

				nClients++;
				continue;
			}

			if (c->listener && c->encrypt) {
				int new_socket = accept(master_tls_socket, NULL, NULL);
				if (new_socket < 0)
					continue;
				SSL* ssl = SSL_new(ctx);
				SSL_set_fd(ssl, new_socket);
				if (SSL_accept(ssl) != 1) {
					SSL_free(ssl);
					close(new_socket);
					continue;
				}
				TLSYAMPSend(ssl, "{\"type\":\"hello\"}", 16);

				client_sockets = realloc(client_sockets,
										 sizeof(Connection*) * (nClients + 1));
				struct epoll_event ev = {0};

				ev.events = EPOLLIN;
				ev.data.fd = new_socket;
				Connection* new_con = malloc(sizeof(*new_con));
				*new_con = (Connection){0};
				new_con->connected = 1;
				new_con->encrypt = 1;
				new_con->fd = new_socket;
				new_con->ssl = ssl;
				new_con->listener = 0;
				new_con->idx = nClients;


				client_sockets[nClients] = new_con;
				ev.data.ptr = client_sockets[nClients];


				epoll_ctl(epfd, EPOLL_CTL_ADD, new_socket, &ev);

				nClients++;
				continue;
			}

			if (events[k].events & EPOLLIN) {
				uint32_t len;
				char* payload;
				int ok;
				if (c->encrypt)
					ok = TLSYAMPRecv(c->ssl, &payload, &len);
				else
					ok = YAMPRecv(c->fd, &payload, &len);

				if (ok) {
					// printf("%s\n", payload);
					char* response = NULL;
					// sockid in ProcessRequest is deprecated and unused
					if (ProcessRequest(payload, &response, -1, c)) {
						if (c->encrypt)
							TLSYAMPSend(c->ssl, response, strlen(response));
						else
							YAMPSend(c->fd, response, strlen(response));
					}
					free(payload);
					free(response);
				} else {
					// disconnected or tried to abuse the server
					DisconnectClient(c);
				}
			} else if (events[k].events & (EPOLLHUP | EPOLLERR)) {
				DisconnectClient(c);
			}
		}
	}
}