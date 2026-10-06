#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
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
#define PORT 5224
#define SSLPORT 5225
#define MAX_CLIENTS 1024
Connection client_sockets[MAX_CLIENTS] = {0};
sqlite3 *DB;

int main() {
	UsersByName = hashmap_new(sizeof(user), 256, 0, 0, hmap_username_hash,
							  hmap_username_compare, hmap_username_free, NULL);
	UsersByFD = hashmap_new(sizeof(user), 256, 0, 0, hmap_userfd_hash,
							hmap_userfd_compare, hmap_userfd_free, NULL);
	sqlite3_open("yamp.db", &DB);

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
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	master_socket = socket(AF_INET, SOCK_STREAM, 0);
	master_tls_socket = socket(AF_INET, SOCK_STREAM, 0);

	bind(master_socket, (struct sockaddr *)&address, sizeof(address));
	bind(master_tls_socket, (struct sockaddr *)&tlsaddress, sizeof(address));
	listen(master_socket, 3);
	listen(master_tls_socket, 3);
	if(SSL_CTX_use_certificate_chain_file(
		ctx, CHAINFILE_PATH) <= 0){
			printf("Error loading the certificate chain\n");
	}

	if(SSL_CTX_use_PrivateKey_file(
		ctx, PRIVKEY_PATH, SSL_FILETYPE_PEM) <= 0){
			printf("Error loading the private key chain\n");
	}
	SSL *serverssl = SSL_new(ctx);
	SSL_set_fd(serverssl, master_tls_socket);

	printf("server listening\n");

	// pollfds[0] is always the master socket; the rest track clients
	struct pollfd pollfds[MAX_CLIENTS + 2];

	while (1) {
		// build the pollfd array fresh each iteration
		pollfds[0].fd = master_socket;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;
		pollfds[1].fd = master_tls_socket;
		pollfds[1].events = POLLIN;
		pollfds[1].revents = 0;

		for (int i = 0; i < MAX_CLIENTS; i++) {
			sd = client_sockets[i].fd;
			pollfds[i + 2].fd = client_sockets[i].connected
									? sd
									: -1; // -1 tells poll to ignore this slot
			pollfds[i + 2].events = POLLIN;
			pollfds[i + 2].revents = 0;
		}

		int activity = poll(pollfds, MAX_CLIENTS + 2, -1);
		if (activity < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		// handle new connection
		if (pollfds[0].revents & POLLIN) {
			int new_socket = accept(master_socket, NULL, NULL);

			if (new_socket >= 0) {
				YAMPSend(new_socket, "{\"type\":\"hello\"}", 16);

				for (int i = 0; i < MAX_CLIENTS; i++) {
					if (client_sockets[i].connected == 0) {
						client_sockets[i].fd = new_socket;
						client_sockets[i].connected = 1;
						client_sockets[i].encrypt = 0;
						break;
					}
				}
			}
		}
		if (pollfds[1].revents & POLLIN) {

			int new_socket = accept(master_tls_socket, NULL, NULL);

			SSL *ssl = SSL_new(ctx);
			SSL_set_fd(ssl, new_socket);

			int ret = SSL_accept(ssl);
			if (ret >= 0) {
				TLSYAMPSend(ssl, "{\"type\":\"hello\"}", 16);

				for (int i = 0; i < MAX_CLIENTS; i++) {
					if (client_sockets[i].connected == 0) {
						client_sockets[i].fd = new_socket;
						client_sockets[i].ssl = ssl;
						client_sockets[i].connected = 1;
						client_sockets[i].encrypt = 1;
						break;
					}
				}
			}
		}

		// handle client data
		for (int i = 0; i < MAX_CLIENTS; i++) {
			sd = client_sockets[i].fd;
			if (sd <= 0)
				continue;

			short revents = pollfds[i + 2].revents;

			if (revents & (POLLHUP | POLLERR | POLLNVAL)) {
				close(sd);
				client_sockets[i].connected = 0;
				continue;
			}

			if (revents & POLLIN) {
				if (client_sockets[i].encrypt) {
					uint32_t len;
					char *payload;
					if (TLSYAMPRecv(client_sockets[i].ssl, &payload, &len)) {
						printf("%s\n", payload);
						char *response;
						if (ProcessRequest(payload, &response, i, &client_sockets[i])) {
							TLSYAMPSend(client_sockets[i].ssl, response,
										strlen(response));
						}
						free(payload);
					} else {
						// disconnected or tried to abuse the server
						SSL_free(client_sockets[i].ssl);
						close(sd);
						client_sockets[i].connected = 0;
					}
				} else {
					uint32_t len;
					char *payload;
					if (YAMPRecv(sd, &payload, &len)) {
						printf("%s\n", payload);
						char *response;
						if (ProcessRequest(payload, &response, i, &client_sockets[i])) {
							YAMPSend(sd, response, strlen(response));
						}
						free(payload);
					} else {
						// disconnected or tried to abuse the server
						close(sd);
						client_sockets[i].connected = 0;
					}
				}
			}
		}
	}

	return 0;
}