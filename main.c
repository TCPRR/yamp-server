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
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <glib.h>
#include "helpers.h"
#include "hmap/hashmap.h"
#include "globals.h"
#include "network.h"
#include "request.h"
#define PORT 5224
#define MAX_CLIENTS 255
int client_sockets[MAX_CLIENTS] = {0};
sqlite3 *DB;

int main() { // select part of the multi-socket pooling thing is taken from a
	         // tutorial, i cleared it as much as i could
	UsersByName = hashmap_new(sizeof(user), 256, 0, 0, hmap_username_hash,
							  hmap_username_compare, hmap_username_free, NULL);
	UsersByFD = hashmap_new(sizeof(user),256,0,0,hmap_userfd_hash,hmap_userfd_compare,hmap_userfd_free,NULL);
	sqlite3_open("yamp.db", &DB);

	int master_socket;
	int max_sd, valread, sd;
	struct sockaddr_in address = {.sin_family = AF_INET,
	                              .sin_addr.s_addr = INADDR_ANY,
	                              .sin_port = htons(PORT)};
	fd_set readfds;

	// create and configure master socket, the oen that will uh receive the
	// incomings
	master_socket = socket(AF_INET, SOCK_STREAM, 0);
	int opt = 1;
	setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	bind(master_socket, (struct sockaddr *)&address, sizeof(address));
	listen(master_socket, 3);

	printf("server listening\n");

	while (1) {
		FD_ZERO(&readfds);
		FD_SET(master_socket, &readfds);
		max_sd = master_socket;

		// add active client sockets
		for (int i = 0; i < MAX_CLIENTS; i++) {
			sd = client_sockets[i];
			if (sd > 0)
				FD_SET(sd, &readfds);
			if (sd > max_sd)
				max_sd = sd;
		}

		select(max_sd + 1, &readfds, NULL, NULL, NULL);

		// haaaaandle new connection
		if (FD_ISSET(master_socket, &readfds)) {
			int new_socket = accept(master_socket, NULL, NULL);

			YAMPSend(new_socket, "{\"type\":\"hello\"}", 17);

			for (int i = 0; i < MAX_CLIENTS; i++) {
				if (client_sockets[i] == 0) {
					client_sockets[i] = new_socket;
					break;
				}
			}
		}

		// handle client data
		for (int i = 0; i < MAX_CLIENTS; i++) {
			sd = client_sockets[i];
			if (FD_ISSET(sd, &readfds)) {
				uint32_t payloadlen;

				if (read(sd, &payloadlen, 4) != 4) {
					user searchusr;
					searchusr.fd = sd;
					const user* resultusr = hashmap_get(UsersByFD,&searchusr);
					hashmap_delete(UsersByName,resultusr);
					hashmap_delete(UsersByFD,&searchusr);
					close(sd);
					client_sockets[i] = 0;
				} else {
					payloadlen = ntohl(payloadlen);
					char *payload = malloc(payloadlen);
					if(read(sd, payload, payloadlen)==payloadlen){
					char *response;
					if (ProcessRequest(payload, &response, i, sd)) {
						YAMPSend(sd, response, strlen(response) + 1);
					}
					}
				}
			}
		}
	}

	return 0;
}
