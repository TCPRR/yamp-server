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
#define PORT 5224
#define MAX_CLIENTS 255
int client_sockets[MAX_CLIENTS] = {0};
GHashTable *users_by_fd;
GHashTable *users_by_name;
typedef struct{
	char* status;
	char* RPCName;
	char* RPCDesc;
	char* RPCIcon;
} status;
typedef struct {
	int fd;
	char *username;
	status status;
} user;

sqlite3 *DB;

int send_framed(int fd, const char *buf, uint32_t len) {
	uint32_t netlen = htonl(len);
	if (send(fd, &netlen, sizeof(netlen), 0) != sizeof(netlen))
		return -1;
	send(fd, buf, len, 0);

	return 0;
}

cJSON *CreateUserObject(char *name, char *description, char *display_name, char* pfp,
                        status* status) {
	cJSON *returnObj = cJSON_CreateObject();
	cJSON_AddStringToObject(returnObj, "name", name);
	cJSON_AddStringToObject(returnObj, "display_name", display_name);
	cJSON_AddStringToObject(returnObj, "description", description);
	cJSON_AddStringToObject(returnObj, "pfp", pfp);
	cJSON* statusObj = cJSON_CreateObject();
	cJSON_AddStringToObject(statusObj, "RPCName", status->RPCName);
	cJSON_AddStringToObject(statusObj, "RPCDesc", status->RPCDesc);
	cJSON_AddStringToObject(statusObj, "RPCIcon", status->RPCIcon);
	cJSON_AddStringToObject(statusObj, "status", status->status);
	cJSON_AddItemToObject(returnObj, "status", statusObj);
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
int CreateSpaceObjectFromName(char *name, cJSON **output) {
	const char *sql = "SELECT display_name FROM spaces WHERE name "
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
int CreateUserObjectFromUsername(char *name, cJSON **output) {
	const char *sql = "SELECT display_name, pfp, description FROM users WHERE name "
	                  "= ?";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		user* usr = g_hash_table_lookup(users_by_name, name);
		status stat;
		if(usr && strcmp(usr->status.status, "offline") != 0){
			stat = usr->status;
		} else {
			stat.status = "offline";
			stat.RPCName = stat.RPCDesc = stat.RPCIcon = "";
		}
		*output = CreateUserObject(name,sqlite3_column_text(stmt,2),sqlite3_column_text(stmt,0),sqlite3_column_text(stmt,1),&stat);
		return 1;
	} else {
		return 0;
	}

	return 1;
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
int CreateSpacesListFromUsername(const char *name, cJSON **output) {

	const char *sql =
	    "SELECT \"space-name\" FROM \"user-space\" WHERE \"user-name\" = ?";
	sqlite3_stmt *stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);

	cJSON *array = cJSON_CreateArray();
	for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW;
	     rc = sqlite3_step(stmt)) {
		cJSON *userObj;
		if (CreateSpaceObjectFromName(sqlite3_column_text(stmt, 0), &userObj)) {
			cJSON_AddItemToArray(array, userObj);
		}
	}

	sqlite3_finalize(stmt);

	*output = array;
	return 1;
}
int CreateChannelsListFromName(const char *name, cJSON **output) {

	const char *sql = "SELECT channels FROM spaces WHERE name = ?";
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
		cJSON *channel = cJSON_CreateObject();
		cJSON_AddStringToObject(channel, "name", token);
		cJSON_AddItemToArray(array, channel);
		token = strtok(NULL, ",");
	}

	free(friends_copy);
	sqlite3_finalize(stmt);

	*output = array;
	return 1;
}

int CreateUsersOwnObjectFromUsername(char *name, cJSON **output) {
	const char *sql = "SELECT display_name FROM users WHERE name "
	                  "= ?";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		CreateUserObjectFromUsername(name,output);
		cJSON *spaces;
		CreateSpacesListFromUsername(name, &spaces);
		cJSON_AddItemToObject(*output, "spaces", spaces);
		return 1;
	} else {
		return 0;
	}
	sqlite3_finalize(stmt);

	return 1;
}
char **ListSpaceMembersNames(char *name, int *outputlen) {
    const char *sql =
        "SELECT \"user-name\" FROM \"user-space\" WHERE \"space-name\" = ?";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

    int i = 0;
    int capacity = 128;
    char **ret = malloc(capacity * sizeof(char *));

    for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW; rc = sqlite3_step(stmt)) {
        if (i >= capacity) {
            capacity *= 2;
            char **tmp = realloc(ret, capacity * sizeof(char *));
            if (!tmp) { free(ret); return NULL; }
            ret = tmp;
        }
        ret[i] = strdup((const char *)sqlite3_column_text(stmt, 0));
        i++;
    }

    *outputlen = i;
    sqlite3_finalize(stmt);
    return ret;
}
cJSON* CreateMessageObject(char* author, char* content, char* where){
	cJSON* object = cJSON_CreateObject();
	cJSON_AddStringToObject(object,"author",author);
	cJSON_AddStringToObject(object,"content",content);
	cJSON_AddStringToObject(object,"where",where);
	return object;
}
void InsertMessage(char *where, char *author, char *content) {
	const char *sql =
	"INSERT INTO \"messages\" (\"where\", \"author\", \"content\", \"timestamp\") VALUES (?, ?, ?, ?)";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, where,    -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, author,   -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, content,  -1, SQLITE_STATIC);
	sqlite3_bind_int (stmt, 4, (int)time(NULL));
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
cJSON* GetMessageHistory(char* where){
	cJSON* list = cJSON_CreateArray();
	const char *sql =
	"SELECT \"author\",\"content\" FROM \"messages\" WHERE \"where\" = ? ORDER BY \"timestamp\" ASC";
		sqlite3_stmt *stmt;
		sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
		sqlite3_bind_text(stmt, 1, where, -1, SQLITE_STATIC);

		for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW; rc = sqlite3_step(stmt)) {
			cJSON_AddItemToArray(list,CreateMessageObject(sqlite3_column_text(stmt,0),sqlite3_column_text(stmt,1),where));
		}

		return list;
}
int PushEvent(int fd, char *event, cJSON *data) {
	cJSON *payload = cJSON_CreateObject();
	cJSON_AddStringToObject(payload, "type", "event");
	cJSON_AddStringToObject(payload, "event", event);
	cJSON_AddItemToObject(payload, "data", data);
	send_framed(fd, cJSON_Print(payload), strlen(cJSON_Print(payload)) + 1);
}
int PushRecvIM(char *toWho, char *where, char *fromWho, char *content) {
	cJSON *payload = cJSON_CreateObject();
	user *usr = ((user *)g_hash_table_lookup(users_by_name, toWho));
	if (usr) {
		int fd = usr->fd;
		printf("Pushing a message recv event to %s at %d, that says %s\n",
		       toWho, fd, content);
		cJSON_AddStringToObject(payload, "content", content);
		cJSON_AddStringToObject(payload, "author", fromWho);
		cJSON_AddStringToObject(payload, "where", where);
		PushEvent(fd, "recvim", payload);
	} else {
		printf("a message was canceled due to the other side being offline!\n");
	}
}
char *MakeDMChannel(const char *a, const char *b) {
	if (strcmp(a, b) < 0)
		return g_strdup_printf("%s|%s", a, b);
	else
		return g_strdup_printf("%s|%s", b, a);
}

int ProcessRequest(char *payload, char **response, int sockid, int sockfd) {
	printf("%s\n", payload);
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
			if (sqlite3_step(stmt) == SQLITE_ROW) {
				printf("hello there, %s!", username);
				cJSON_AddStringToObject(responsebuild, "response", "success");
				user *newUser = malloc(sizeof(user));
				newUser->username = username;
				newUser->fd = sockfd;
				newUser->status = (status){"online","","",""};
				g_hash_table_insert(users_by_name, username, (gpointer)newUser);
				g_hash_table_insert(users_by_fd, GINT_TO_POINTER(sockfd),
									(gpointer)newUser);
				cJSON *tmp;
				CreateUsersOwnObjectFromUsername(username, &tmp);
				cJSON_AddItemToObject(responsebuild, "user", tmp);
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
			if (username) {
				if (CreateFriendsListFromUsername(username, &tmp)) {
					cJSON_AddItemToObject(responsebuild, "response", tmp);
				}
			}
		} else if (strcmp(endpoint, "sendim") == 0) {
			char *content =
			    cJSON_GetObjectItem(PayloadParsed, "content")->valuestring;
			char *fromWho = ((user *)g_hash_table_lookup(
			                     users_by_fd, GINT_TO_POINTER(sockfd)))
			                    ->username;
			char *where =
			    cJSON_GetObjectItem(PayloadParsed, "where")->valuestring;
			chat chatCtx;
			YAMPProcessWhere(where, fromWho, &chatCtx);
			if (chatCtx.type == YAMP_GUILD) {
				int outputLen;
				char **start =
				    ListSpaceMembersNames(chatCtx.GuildName, &outputLen);
				for (int i = 0; i < outputLen; i++) {
					printf("%s\n", *(start + i));
					PushRecvIM(*(start+i), where, fromWho,
						content);
					InsertMessage(where,fromWho,content);
				}
			} else if (chatCtx.type == YAMP_DM) {
				PushRecvIM(chatCtx.OtherGuy, where, fromWho,
				           content);
				PushRecvIM(fromWho, where, fromWho, content);
			}
		} else if (strcmp(endpoint, "getchannels") == 0) {
			char *guild =
			    cJSON_GetObjectItem(PayloadParsed, "space")->valuestring;
			cJSON *channels;
			CreateChannelsListFromName(guild, &channels);
			cJSON_AddItemToObject(responsebuild, "response", channels);
		} else if (strcmp(endpoint, "GetUserDetails") == 0) {
			cJSON *details;
			CreateUserObjectFromUsername(cJSON_GetObjectItem(PayloadParsed,"name")->valuestring, &details);
			cJSON_AddItemToObject(responsebuild, "response", details);
		} else if (strcmp(endpoint, "GetGuildDetails") == 0) {
			cJSON *details;
			CreateSpaceObjectFromName(cJSON_GetObjectItem(PayloadParsed,"name")->valuestring, &details);
			cJSON_AddItemToObject(responsebuild, "response", details);
		} else if (strcmp(endpoint,"GetMessageHistory") == 0){ //might use pascal case more... beware of breaking changes to other ones soon
			cJSON *messages = GetMessageHistory(cJSON_GetObjectItem(PayloadParsed, "where")->valuestring);
			cJSON_AddItemToObject(responsebuild, "response", messages);
		} else if (strcmp(endpoint,"ChangeChannelList") == 0){

		} else if (strcmp(endpoint,"CreateGuild") == 0){

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
