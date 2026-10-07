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
#define PORT 5224
#define SSLPORT 5225
#define MAX_CLIENTS 1024
#define MAX_IPC_CLIENTS 1024
Connection client_sockets[MAX_CLIENTS] = {0};
int IPCSockets[MAX_IPC_CLIENTS] = {0};
sqlite3* DB;

void* UnixListener(void* args) {
	int fd = (int)args;
	while (1) {
		uint32_t len;
		int r = recv(fd, &len, 4, 0);
		if(r==0){
			return NULL;
		}
		len=ntohl(len);
		char* payload = malloc(len);
		int totaln = 0;
		while (len>totaln) {
			int n = recv(fd, payload + totaln, len - totaln, 0);
			if (n <= 0) {
				free(payload);
				return NULL;
			}
			totaln += n;
		}
		cJSON* payld = cJSON_Parse(payload);
		if(!payld){
			printf("Unintelligable payload from a plugin\n");
			return NULL;
		}
		char* endpoint =
			cJSON_GetStringValue(cJSON_GetObjectItem(payld, "endpoint"));
		cJSON* response = cJSON_CreateObject();
		cJSON_AddItemToObject(response, "reqid", cJSON_Duplicate(cJSON_GetObjectItem(payld, "reqid"), 1));
		if (strcmp(endpoint, "GetSpaceFromInvite") == 0) {

		} else if (strcmp(endpoint, "GetSpaceDetails") == 0) {
			cJSON* spacejson;
			CreateSpaceObjectFromName(
				cJSON_GetStringValue(cJSON_GetObjectItem(payld, "name")),
				&spacejson);
			if (spacejson) {
				cJSON_AddItemToObject(response, "space", spacejson);
				cJSON_AddBoolToObject(response, "success", 1);
			} else {
				cJSON_AddBoolToObject(response, "success", 0);
			}
		} else if(strcmp(endpoint,"SetMainRespOverride")==0){
			MainRespOverride override;
			override.key=strdup(cJSON_GetStringValue(cJSON_GetObjectItem(payld, "key")));
			override.val=strdup(cJSON_GetStringValue(cJSON_GetObjectItem(payld, "val")));
			printf("A main-response keypair override was set, %s is now %s\n",override.key,override.val);
			respoverrides=realloc(respoverrides,sizeof(MainRespOverride)*(nrespoverrides+1));
			respoverrides[nrespoverrides++]=override;
		}
		char* respout = cJSON_PrintUnformatted(response);
		uint32_t rlen=strlen(respout)+1;
		len = strlen(respout) + 1;
		send(fd, &rlen, 4, 0);
		send(fd, respout, strlen(respout) + 1, 0);
		free(respout);
		cJSON_Delete(response);
		cJSON_Delete(payld);
	}
	return NULL;
}
void* UnixAccepter(void* args) {
	int fd = (int)args;

	while (1) {
		struct pollfd pollfds[MAX_IPC_CLIENTS + 1];

		pollfds[0].fd = fd;
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		for (int i = 0; i < MAX_IPC_CLIENTS; i++) {
			pollfds[i + 1].fd = IPCSockets[i] > 0 ? IPCSockets[i] : -1;
			pollfds[i + 1].events = POLLIN;
			pollfds[i + 1].revents = 0;
		}

		int activity = poll(pollfds, MAX_IPC_CLIENTS + 1, -1);
		if (activity < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		// new IPC client connecting
		if (pollfds[0].revents & POLLIN) {
			int new_socket = accept(fd, NULL, NULL);
			if (new_socket >= 0) {
				int placed = 0;
				for (int i = 0; i < MAX_IPC_CLIENTS; i++) {
					if (IPCSockets[i] <= 0) {
						IPCSockets[i] = new_socket;
						placed = 1;

						pthread_t clientthread;
						pthread_create(&clientthread, NULL, UnixListener,
									   (void*)new_socket);
						pthread_detach(clientthread);
						break;
					}
				}
				if (!placed) {
					close(new_socket);
				}
			}
		}

		for (int i = 0; i < MAX_IPC_CLIENTS; i++) {
			if (IPCSockets[i] <= 0)
				continue;

			short revents = pollfds[i + 1].revents;
			if (revents & (POLLHUP | POLLERR | POLLNVAL)) {
				close(IPCSockets[i]);
				IPCSockets[i] = 0;
			}
		}
	}

	return NULL;
}
int main() {
	UsersByName = hashmap_new(sizeof(user), 256, 0, 0, hmap_username_hash,
							  hmap_username_compare, hmap_username_free, NULL);
	UsersByID = hashmap_new(sizeof(user), 256, 0, 0, hmap_userid_hash,
							  hmap_userid_compare, hmap_userid_free, NULL);
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
	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	master_socket = socket(AF_INET, SOCK_STREAM, 0);
	master_tls_socket = socket(AF_INET, SOCK_STREAM, 0);

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

	struct sockaddr_un unixaddress;
	memset(&unixaddress, 0, sizeof(unixaddress));
	unlink("/tmp/yamp-server.sock");
	unixaddress.sun_family = AF_UNIX;
	strncpy(unixaddress.sun_path, "/tmp/yamp-server.sock", sizeof(unixaddress.sun_path) - 1);

	int unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	bind(unix_fd, (struct sockaddr*)&unixaddress, sizeof(unixaddress));
	listen(unix_fd, 3);
	pthread_t unixacthread;
	if (pthread_create(&unixacthread, NULL, UnixAccepter, (void*)unix_fd)==0) {
		printf("unix IPC listening\n");
	}

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

			SSL* ssl = SSL_new(ctx);
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
					char* payload;
					if (TLSYAMPRecv(client_sockets[i].ssl, &payload, &len)) {
						printf("%s\n", payload);
						char* response;
						if (ProcessRequest(payload, &response, i,
										   &client_sockets[i])) {
							TLSYAMPSend(client_sockets[i].ssl, response,
										strlen(response));
						}
						free(payload);
					} else {
						// disconnected or tried to abuse the server
						SSL_free(client_sockets[i].ssl);
						close(sd);
						user search;
						search.con=client_sockets[i];
						user* usr = hashmap_get(UsersByFD,&search);
						if(usr){
							int cnt;
							char** relatedpeople = CollectRelatedUserIDs(usr->username, NULL, &cnt);
							for(int i = 0; i<cnt; i++){
								PushStatusUpdate(relatedpeople[i], usr->id, (status){"offline","","",""});
							}
							hashmap_delete(UsersByID, usr);
							hashmap_delete(UsersByName, usr);
							hashmap_delete(UsersByFD, usr);
						}
						client_sockets[i].connected = 0;
					}
				} else {
					uint32_t len;
					char* payload;
					if (YAMPRecv(sd, &payload, &len)) {
						printf("%s\n", payload);
						char* response;
						if (ProcessRequest(payload, &response, i,
										   &client_sockets[i])) {
							YAMPSend(sd, response, strlen(response));
						}
						free(payload);
					} else {
						// disconnected or tried to abuse the server
						close(sd);
						user search;
						search.con=client_sockets[i];
						user* usr = hashmap_get(UsersByFD,&search);
						if(usr){
							int cnt;
							char** relatedpeople = CollectRelatedUserIDs(usr->username, NULL, &cnt);
							for(int i = 0; i<cnt; i++){
								PushStatusUpdate(relatedpeople[i], usr->id, (status){"offline","","",""});
							}
							hashmap_delete(UsersByID, usr);
							hashmap_delete(UsersByName, usr);
							hashmap_delete(UsersByFD, usr);
						}
						client_sockets[i].connected = 0;
					}
				}
			}
		}
	}

	return 0;
}
