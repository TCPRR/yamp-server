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

#define PORT 5224
#define MAX_CLIENTS 255
char *usersocks[MAX_CLIENTS];
sqlite3 *DB;
cJSON *CreateUserObject(char *name, char *description, char* display_name, char *status) {
	cJSON *returnObj = cJSON_CreateObject();
	cJSON_AddStringToObject(returnObj, "name", name);
	cJSON_AddStringToObject(returnObj, "display_name", display_name);
	cJSON_AddStringToObject(returnObj, "description", description);
	cJSON_AddStringToObject(returnObj, "status", status);
	return returnObj;
}
int ProcessRequest(char *payload, char **response, int sockid) {
	cJSON *responsebuild = cJSON_CreateObject();
	printf(payload);
	printf("\n");
	cJSON *PayloadParsed = cJSON_Parse(payload);
	if (!PayloadParsed) {
		printf("Failed parsing, did u fuck up smh\n");
		return 0;
	}
	char *type = cJSON_GetObjectItem(PayloadParsed, "type")->valuestring;
	if (strcmp(type, "request") == 0) {
		cJSON_AddStringToObject(responsebuild, "type", "response");
		cJSON *reqid = cJSON_GetObjectItem(PayloadParsed, "reqid");
		cJSON_AddItemToObject(responsebuild, "reqid", cJSON_Duplicate(reqid,cJSON_True));
		char *endpoint =
		    cJSON_GetObjectItem(PayloadParsed, "endpoint")->valuestring;
		if (strcmp(endpoint, "login") == 0) {
			char *username =
			    cJSON_GetObjectItem(PayloadParsed, "username")->valuestring;
			char *passwd =
			    cJSON_GetObjectItem(PayloadParsed, "password")->valuestring;
			if ((strcmp(username, "sofi") == 0) &&
			    (strcmp(passwd, "SofiMaster7373") == 0)) {

				cJSON_AddStringToObject(responsebuild, "response", "success");
				usersocks[sockid] = username;
			} else {

				cJSON_AddStringToObject(responsebuild, "response", "fail");
			}
		} else if (strcmp(endpoint, "buddylist") == 0) {
			cJSON* buddy1=CreateUserObject("lanternoric","Polish asshole tgat will NOT update ur subdomain","Lanternoric","online");
			cJSON *buddies = cJSON_CreateArray();
			cJSON_AddItemToArray(buddies,buddy1);
			cJSON_AddItemToObject(responsebuild, "response", buddies);
		}

	} else {

		printf("no req november\n");
	}
	(*response) = cJSON_Print(responsebuild);
	printf(cJSON_Print(responsebuild));
	printf("\n");
	return 1;
}
int send_framed(int fd, const char *buf, uint32_t len) {
	uint32_t netlen = htonl(len);
	if (send(fd, &netlen, sizeof(netlen), 0) != sizeof(netlen))
		return -1;
	send(fd, buf, len, 0);

	return 0;
}

int main() { //select part of the multi-socket pooling thing is taken from a tutorial, i cleared it as much as i could
	memset(usersocks, 0, MAX_CLIENTS);
	int fd = open("yamp.db", O_RDWR);
	sqlite3_open("yamp.db", &DB);

	int master_socket, client_sockets[MAX_CLIENTS] = {0};
	int max_sd, valread, sd;
	struct sockaddr_in address = {.sin_family = AF_INET,
	                              .sin_addr.s_addr = INADDR_ANY,
	                              .sin_port = htons(PORT)};
	fd_set readfds;

	// create and configure master socket, the oen that will uh receive the incomings
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

			send_framed(new_socket, "{\"type\":\"hello\"}", 17);

			for (int i = 0; i < MAX_CLIENTS; i++) {
				if (client_sockets[i] == 0) {
					client_sockets[i] = new_socket;
					break;
				}
			}
		}

		// haaandle client data
		for (int i = 0; i < MAX_CLIENTS; i++) {
			sd = client_sockets[i];
			if (FD_ISSET(sd, &readfds)) {
				uint32_t payloadlen;

				if (read(sd, &payloadlen, 4) != 4) {
					close(sd);
					usersocks[i] = 0;
					client_sockets[i] = 0;
				} else {
					payloadlen = ntohl(payloadlen);
					char *payload = malloc(payloadlen);
					read(sd, payload, payloadlen);
					char *response;
					if (ProcessRequest(payload, &response, i)) {
						send_framed(sd, response, strlen(response) + 1);
					}
				}
			}
		}
	}

	return 0;
}
