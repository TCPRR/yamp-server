#include <cjson/cJSON.h>
#include "types.h"
#include "globals.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include "network.h"
#include <stdlib.h>
#include <time.h>
#include "helpers.h"
cJSON *CreateUserObject(user *user) {
	cJSON *returnObj = cJSON_CreateObject();
	cJSON_AddStringToObject(returnObj, "name", user->username);
	cJSON_AddStringToObject(returnObj, "display_name", user->displayname);
	cJSON_AddStringToObject(returnObj, "description", user->description);
	cJSON_AddStringToObject(returnObj, "pfp", user->pfp);
	cJSON *statusObj = cJSON_CreateObject();
	cJSON_AddStringToObject(statusObj, "RPCName", user->status.RPCName);
	cJSON_AddStringToObject(statusObj, "RPCDesc", user->status.RPCDesc);
	cJSON_AddStringToObject(statusObj, "RPCIcon", user->status.RPCIcon);
	cJSON_AddStringToObject(statusObj, "status", user->status.status);
	cJSON_AddItemToObject(returnObj, "status", statusObj);
	return returnObj;
}
int RegisterUserAccount(char *name, char *passwd) {
	const char *sql =
		"INSERT INTO users (name, display_name, password) VALUES (?,?,?)";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	char passwdh[65];
	sha256_hex(passwd, passwdh);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, passwdh, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return 1;
	} else {
		sqlite3_finalize(stmt);
		return 0;
	}
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
								(char *)sqlite3_column_text(stmt, 0));
		sqlite3_finalize(stmt);
		return 1;
	} else {
		sqlite3_finalize(stmt);
		return 0;
	}
	sqlite3_finalize(stmt);

	return 1;
}
int CreateUserObjectFromUsername(char *name, cJSON **output) {
	const char *sql =
		"SELECT display_name, pfp, description FROM users WHERE name = ?";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		user search;
		search.username = name;
		const user *usr = hashmap_get(UsersByName, &search);

		user built;
		built.username = name;
		built.displayname = (char *)sqlite3_column_text(stmt, 0);
		built.pfp = (char *)sqlite3_column_text(stmt, 1);
		built.description = (char *)sqlite3_column_text(stmt, 2);

		if (usr && strcmp(usr->status.status, "offline") != 0) {
			built.status = usr->status;
		} else {
			built.status.status = "offline";
			built.status.RPCName = built.status.RPCDesc = built.status.RPCIcon =
				"";
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

	const char *sql = "SELECT starter, accepter FROM friendship WHERE starter "
					  "= ? OR accepter = ?";
	sqlite3_stmt *stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);

	cJSON *array = cJSON_CreateArray();
	while (sqlite3_step(stmt) == SQLITE_ROW) {

		char *p1 = sqlite3_column_text(stmt, 0);
		char *p2 = sqlite3_column_text(stmt, 1);
		char *friend;
		if (strcmp(p1, name) != 0) {
			friend = p1;
		} else if (strcmp(p2, name) != 0) {
			friend = p2;
		} else {
			return 0;
		}
		cJSON *userObj;
		if (CreateUserObjectFromUsername(friend, &userObj)) {
			cJSON_AddItemToArray(array, userObj);
		}
	}
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
		if (CreateSpaceObjectFromName((char *)sqlite3_column_text(stmt, 0),
									  &userObj)) {
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
		CreateUserObjectFromUsername(name, output);
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

	for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW;
		 rc = sqlite3_step(stmt)) {
		if (i >= capacity) {
			capacity *= 2;
			char **tmp = realloc(ret, capacity * sizeof(char *));
			if (!tmp) {
				free(ret);
				return NULL;
			}
			ret = tmp;
		}
		ret[i] = strdup((const char *)sqlite3_column_text(stmt, 0));
		i++;
	}

	*outputlen = i;
	sqlite3_finalize(stmt);
	return ret;
}
int IsInSpace(char *username, char *spacename) {
	const char *sql = "SELECT \"user-name\" FROM \"user-space\" WHERE "
					  "\"space-name\" = ? AND \"user-name\" = ?";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, spacename, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return 1;
	}
	return 0;
	sqlite3_finalize(stmt);
}
cJSON *CreateMessageObject(char *author, char *content, char *where) {
	cJSON *object = cJSON_CreateObject();
	cJSON_AddStringToObject(object, "author", author);
	cJSON_AddStringToObject(object, "content", content);
	cJSON_AddStringToObject(object, "where", where);
	return object;
}
void InsertMessage(char *where, char *author, char *content) {
	const char *sql = "INSERT INTO \"messages\" (\"where\", \"author\", "
					  "\"content\", \"timestamp\") VALUES (?, ?, ?, ?)";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, where, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, author, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, content, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 4, (int)time(NULL));
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
cJSON *GetMessageHistory(char *where) {
	cJSON *list = cJSON_CreateArray();
	const char *sql = "SELECT \"author\",\"content\" FROM \"messages\" WHERE "
					  "\"where\" = ? ORDER BY \"timestamp\" ASC";
	sqlite3_stmt *stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, where, -1, SQLITE_STATIC);

	for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW;
		 rc = sqlite3_step(stmt)) {
		cJSON_AddItemToArray(
			list,
			CreateMessageObject((char *)sqlite3_column_text(stmt, 0),
								(char *)sqlite3_column_text(stmt, 1), where));
	}

	return list;
}
int PushEvent(Connection con, char *event, cJSON *data) {
	cJSON *payload = cJSON_CreateObject();
	cJSON_AddStringToObject(payload, "type", "event");
	cJSON_AddStringToObject(payload, "event", event);
	cJSON_AddItemToObject(payload, "data", data);
	if (con.connected) {
		char *out = cJSON_Print(payload);
		if (con.encrypt) {
			TLSYAMPSend(con.ssl, out, strlen(out));
		} else {
			YAMPSend(con.fd, out, strlen(out));
		}
		free(out);
	}
	cJSON_Delete(payload);
}
int PushRecvIM(char *toWho, char *where, char *fromWho, char *content) {
	cJSON *payload = cJSON_CreateObject();
	user search;
	search.username = toWho;
	const user *usr = hashmap_get(UsersByName, &search);
	if (usr) {
		Connection con = usr->con;
		printf("Pushing a message recv event to %s at %d, that says %s\n",
			   toWho, con.fd, content);
		cJSON_AddStringToObject(payload, "content", content);
		cJSON_AddStringToObject(payload, "author", fromWho);
		cJSON_AddStringToObject(payload, "where", where);
		PushEvent(con, "recvim", payload);
	} else {
		printf("a message was canceled due to the other side being offline!\n");
	}
}
int PushFQ(char *toWho, char *fromWho) {
	cJSON *payload = cJSON_CreateObject();
	user search;
	search.username = toWho;
	const user *usr = hashmap_get(UsersByName, &search);
	if (usr) {
		Connection con = usr->con;
		printf("Pushing an fq event to %s at %d\n", toWho, con.fd);
		cJSON_AddStringToObject(payload, "from", fromWho);
		PushEvent(con, "IncomingFriendReq", payload);
	} else {
		printf(
			"a friend req was omitted due to the other side being offline!\n");
	}
}
int PushStatusUpdate(char *toWho, char *who, status status) {
	cJSON *payload = cJSON_CreateObject();
	user search;
	search.username = toWho;
	const user *usr = hashmap_get(UsersByName, &search);
	if (usr) {
		Connection con = usr->con;
		printf(
			"Pushing a status update event to %s at %d, with the status %s\n",
			toWho, con.fd, status.status);
		cJSON *stat = cJSON_CreateObject();
		cJSON_AddStringToObject(stat, "status", status.status);
		cJSON_AddStringToObject(stat, "RPCDesc", status.RPCDesc);
		cJSON_AddStringToObject(stat, "RPCIcon", status.RPCIcon);
		cJSON_AddStringToObject(stat, "RPCName", status.RPCName);
		cJSON_AddStringToObject(payload, "name", who);
		cJSON_AddItemToObject(payload, "status", stat);
		PushEvent(con, "StatusUpdate", payload);
	} else {
		printf("a status update msg was canceled due to the other side being "
			   "offline!\n");
	}
}


void CreateFriendship(char *sender, char *accepter) {
	sqlite3_stmt *stmt;
	char *query = "INSERT INTO \"friendship\" (sender,accepter) VALUES (?,?)";
	sqlite3_prepare_v2(DB, query, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, accepter, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
int DestroyFriendReq(char *sender, char *receiver) {
	sqlite3_stmt *stmt;
	char *query = "DELETE FROM \"friendreq\" WHERE sender=? AND receiver=?";
	sqlite3_prepare_v2(DB, query, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, receiver, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if(rc==SQLITE_DONE){
		return 1;
	}else{
		return 0;
	}
}
void CreateFriendReq(char *sender, char *receiver) {
	sqlite3_stmt *stmt;
	char *query = "INSERT INTO \"friendreq\" (sender,recver) VALUES (?,?)";
	sqlite3_prepare_v2(DB, query, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, receiver, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
int ListFriendReqs(char *user, char ***out) {
	sqlite3_stmt *stmt;
	char *query = "SELECT sender, receiver FROM \"friendreq\" WHERE sender=? "
				  "OR receiver=?";
	sqlite3_prepare_v2(DB, query, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);
	int count = 0;
	*out = NULL;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		*out = realloc(*out, (count + 1) * sizeof(char *));

		char *p1 = sqlite3_column_text(stmt, 0);
		char *p2 = sqlite3_column_text(stmt, 1);
		char *friend;
		if (strcmp(p1, user) != 0) {
			friend = p1;
		} else if (strcmp(p2, user) != 0) {
			friend = p2;
		} else {
			return 0;
		}

		(*out)[count] = strdup(friend);
		count++;
	}
	sqlite3_finalize(stmt);
	return count;
}