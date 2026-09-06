#include <cjson/cJSON.h>
#include "types.h"
#include "globals.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include "network.h"
#include <stdlib.h>
#include <time.h>
cJSON *CreateUserObject(user* user) {
	cJSON *returnObj = cJSON_CreateObject();
	cJSON_AddStringToObject(returnObj, "name", user->username);
	cJSON_AddStringToObject(returnObj, "display_name", user->displayname);
	cJSON_AddStringToObject(returnObj, "description", user->description);
	cJSON_AddStringToObject(returnObj, "pfp", user->pfp);
	cJSON* statusObj = cJSON_CreateObject();
	cJSON_AddStringToObject(statusObj, "RPCName", user->status.RPCName);
	cJSON_AddStringToObject(statusObj, "RPCDesc", user->status.RPCDesc);
	cJSON_AddStringToObject(statusObj, "RPCIcon", user->status.RPCIcon);
	cJSON_AddStringToObject(statusObj, "status", user->status.status);
	cJSON_AddItemToObject(returnObj, "status", statusObj);
	return returnObj;
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
		                        (char*)sqlite3_column_text(stmt, 0));
		return 1;
	} else {
		return 0;
	}

	return 1;
}
int CreateUserObjectFromUsername(char *name, cJSON **output) {
	const char *sql = "SELECT display_name, pfp, description FROM users WHERE name = ?";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		user search;
		search.username = name;
		const user *usr = hashmap_get(UsersByName, &search);

		user built;
		built.username = name;
		built.displayname = (char*)sqlite3_column_text(stmt, 0);
		built.pfp = (char*)sqlite3_column_text(stmt, 1);
		built.description = (char*)sqlite3_column_text(stmt, 2);

		if (usr && strcmp(usr->status.status, "offline") != 0) {
			built.status = usr->status;
		} else {
			built.status.status = "offline";
			built.status.RPCName = built.status.RPCDesc = built.status.RPCIcon = "";
		}

		*output = CreateUserObject(&built);
		sqlite3_finalize(stmt);
		return 1;
	} else {
		sqlite3_finalize(stmt);
		return 0;
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
		if (CreateSpaceObjectFromName((char*)sqlite3_column_text(stmt, 0), &userObj)) {
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
			cJSON_AddItemToArray(list,CreateMessageObject((char*)sqlite3_column_text(stmt,0),(char*)sqlite3_column_text(stmt,1),where));
		}


		return list;
}
int PushEvent(int fd, char *event, cJSON *data) {
	cJSON *payload = cJSON_CreateObject();
	cJSON_AddStringToObject(payload, "type", "event");
	cJSON_AddStringToObject(payload, "event", event);
	cJSON_AddItemToObject(payload, "data", data);
	YAMPSend(fd, cJSON_Print(payload), strlen(cJSON_Print(payload)));
}
int PushRecvIM(char *toWho, char *where, char *fromWho, char *content) {
	cJSON *payload = cJSON_CreateObject();
    user search;
    search.username = toWho;
	const user *usr = hashmap_get(UsersByName,&search);
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
int PushStatusUpdate(char *toWho, char *who, status status) {
	cJSON *payload = cJSON_CreateObject();
    user search;
    search.username = toWho;
	const user *usr = hashmap_get(UsersByName,&search);
	if (usr) {
		int fd = usr->fd;
		printf("Pushing a status update event to %s at %d, with the status %s\n",
		       toWho, fd, status.status);
		cJSON* stat = cJSON_CreateObject();
		cJSON_AddStringToObject(stat, "status", status.status);
		cJSON_AddStringToObject(stat, "RPCDesc", status.RPCDesc);
		cJSON_AddStringToObject(stat, "RPCIcon", status.RPCIcon);
		cJSON_AddStringToObject(stat, "RPCName", status.RPCName);
		cJSON_AddStringToObject(payload, "name", who);
		cJSON_AddItemToObject(payload, "status", stat);
		PushEvent(fd, "StatusUpdate", payload);
	} else {
		printf("a status update msg was canceled due to the other side being offline!\n");
	}
}