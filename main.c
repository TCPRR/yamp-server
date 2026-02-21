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
#define PORT 5224
#define MAX_CLIENTS 255
int client_sockets[MAX_CLIENTS] = {0};
GHashTable *users_by_fd;
GHashTable *users_by_name;

typedef struct {
	int fd;
	char *username;
	char *status;
} user;

sqlite3 *DB;

int send_framed(int fd, const char *buf, uint32_t len) {
	uint32_t netlen = htonl(len);
	if (send(fd, &netlen, sizeof(netlen), 0) != sizeof(netlen))
		return -1;
	send(fd, buf, len, 0);

	return 0;
}

cJSON *CreateUserObject(char *name, char *description, char *display_name,
                        char *status) {
	cJSON *returnObj = cJSON_CreateObject();
	cJSON_AddStringToObject(returnObj, "name", name);
	cJSON_AddStringToObject(returnObj, "display_name", display_name);
	cJSON_AddStringToObject(returnObj, "description", description);
	cJSON_AddStringToObject(returnObj, "status", status);
	return returnObj;
}

void sha256_hex(const char *input, char *output_hex) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char *)input, strlen(input), hash);

	// Convert to hex string
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(output_hex + (i * 2), "%02x", hash[i]);
	}
	output_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
}
int CreateUserObjectFromUsername(char *name, cJSON **output) {
	const char *sql = "SELECT display_name FROM users WHERE name "
	                  "= ?";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		*output = cJSON_CreateObject();
		cJSON_AddStringToObject(*output, "name", name);
		cJSON_AddStringToObject(*output, "display_name",
		                        sqlite3_column_text(stmt, 0));
		return 1;
	} else {
		return 0;
	}

	return 1;
}
int PushEvent(int fd, char *event, cJSON *data) {
	cJSON *payload = cJSON_CreateObject();
	cJSON_AddStringToObject(payload, "type", "event");
	cJSON_AddStringToObject(payload, "event", event);
	cJSON_AddItemToObject(payload, "data", data);
	send_framed(fd, cJSON_Print(payload), strlen(cJSON_Print(payload)) + 1);
}
int PushRecvIM(char *toWho, char* fromWho, char *content) {
	cJSON *payload = cJSON_CreateObject();
	int fd = ((user *)g_hash_table_lookup(users_by_name, toWho))->fd;
	if(fd){
	printf("Pushing a message recv event to %s at %d, that says %s", toWho, fd,
	       content);
	cJSON_AddStringToObject(payload, "content", content);
	cJSON_AddStringToObject(payload, "author", fromWho);
	PushEvent(fd, "recvim", payload);
	}
}
int CreateFriendsListFromUsername(const char *name, cJSON **output) {

	const char *sql = "SELECT friends FROM users WHERE name = ?";
	sqlite3_stmt *stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	int rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return 0;
	}

	const unsigned char *friends_text = sqlite3_column_text(stmt, 0);

	if (!friends_text) {
		sqlite3_finalize(stmt);
		return 0;
	}

	// copy cause strtok modifies string
	char *friends_copy = strdup((const char *)friends_text);
	if (!friends_copy) {
		sqlite3_finalize(stmt);
		return 0;
	}

	cJSON *array = cJSON_CreateArray();

	char *token = strtok(friends_copy, ",");
	while (token != NULL) {
		cJSON *userObj = NULL;

		if (CreateUserObjectFromUsername(token, &userObj)) {
			cJSON_AddItemToArray(array, userObj);
		}

		token = strtok(NULL, ",");
	}

	free(friends_copy);
	sqlite3_finalize(stmt);

	*output = array;
	return 1;
}
int ProcessRequest(char *payload, char **response, int sockid, int sockfd) {
	cJSON *responsebuild = cJSON_CreateObject();
	cJSON *PayloadParsed = cJSON_Parse(payload);
	if (!PayloadParsed) {
		printf("Failed parsing, did u fuck up smh\n");
		return 0;
	}
	char *type = cJSON_GetObjectItem(PayloadParsed, "type")->valuestring;
	if (strcmp(type, "request") == 0) {
		cJSON_AddStringToObject(responsebuild, "type", "response");
		cJSON *reqid = cJSON_GetObjectItem(PayloadParsed, "reqid");
		cJSON_AddItemToObject(responsebuild, "reqid",
		                      cJSON_Duplicate(reqid, cJSON_True));
		char *endpoint =
		    cJSON_GetObjectItem(PayloadParsed, "endpoint")->valuestring;
		if (strcmp(endpoint, "login") == 0) {
			char *username = strdup(
			    cJSON_GetObjectItem(PayloadParsed, "username")->valuestring);
			char *passwd =
			    cJSON_GetObjectItem(PayloadParsed, "password")->valuestring;
			char *hashedPassword = malloc(65);
			sha256_hex(passwd, hashedPassword);
			const char *sql = "SELECT name, display_name FROM users WHERE name "
			                  "= ? AND password = ?";
			sqlite3_stmt *stmt;
			sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
			sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, hashedPassword, -1, SQLITE_STATIC);
			printf("Hello there, %s!", username);
			if (sqlite3_step(stmt) == SQLITE_ROW) {
				cJSON_AddStringToObject(responsebuild, "response", "success");
				user *newUser = malloc(sizeof(user));
				newUser->username = username;
				newUser->fd = sockfd;
				newUser->status = "online";
				g_hash_table_insert(users_by_name, username, (gpointer)newUser);
				g_hash_table_insert(users_by_fd, GINT_TO_POINTER(sockfd),
				                    (gpointer)newUser);
			} else {

				cJSON_AddStringToObject(responsebuild, "response", "fail");
			}

			sqlite3_finalize(stmt);
		} else if (strcmp(endpoint, "buddylist") == 0) {
			char *username = ((user *)(g_hash_table_lookup(
			                      users_by_fd, GINT_TO_POINTER(sockfd))))
			                     ->username;
			printf("%s is asking for its buddies\n", username);
			cJSON *tmp;
			if (CreateFriendsListFromUsername(username, &tmp)) {
				cJSON_AddItemToObject(responsebuild, "response", tmp);
			}
		} else if (strcmp(endpoint, "sendim") == 0) {
			char *content =
			    cJSON_GetObjectItem(PayloadParsed, "content")->valuestring;
			char *fromWho = ((user *)g_hash_table_lookup(
			                     users_by_fd, GINT_TO_POINTER(sockfd)))
			                    ->username;
			char *toWho =
			    cJSON_GetObjectItem(PayloadParsed, "toWho")->valuestring;
			printf("Sending IM, said by %s, to %s, that says %s\n", fromWho,
			       content);
			PushRecvIM(toWho, fromWho, content);
		}

	} else {

		printf("no req november\n");
	}
	(*response) = cJSON_Print(responsebuild);
	printf(cJSON_Print(responsebuild));
	printf("\n");
	return 1;
}
int main() { // select part of the multi-socket pooling thing is taken from a
	         // tutorial, i cleared it as much as i could
	users_by_fd = g_hash_table_new(g_direct_hash, g_direct_equal);
	users_by_name = g_hash_table_new(g_str_hash, g_str_equal);
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
					client_sockets[i] = 0;
				} else {
					payloadlen = ntohl(payloadlen);
					char *payload = malloc(payloadlen);
					read(sd, payload, payloadlen);
					char *response;
					if (ProcessRequest(payload, &response, i, sd)) {
						send_framed(sd, response, strlen(response) + 1);
					}
				}
			}
		}
	}

	return 0;
}
