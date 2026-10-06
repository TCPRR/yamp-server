#include "globals.h"
#include "handlers.h"
#include "helpers.h"
#include "hmap/hashmap.h"
#include "types.h"
#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
typedef struct {
	int code;
	const char *msg;
} ErrorData;

static const ErrorData errors[] = {
	{0, "OK"},
	{1, "Not authenticated"},
	{2, "Not a part of space/group"},
	{3, "Malformed request"},
	{4, "Internal server error"},
	{5, "Ratelimited"},
	{6, "Invalid credentials"},
	{7, "Not allowed as this user"},
};

static const char *ErrorMessage(int code) {
	for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		if (errors[i].code == code)
			return errors[i].msg;
	}
	return "Unknown error";
}

void InsertError(cJSON *resp, int error) {
	cJSON_AddBoolToObject(resp, "success", error == 0);

	cJSON *err = cJSON_CreateObject();
	cJSON_AddNumberToObject(err, "code", error);
	cJSON_AddStringToObject(err, "message", ErrorMessage(error));
	cJSON_AddItemToObject(resp, "error", err);
}
int ProcessRequest(char *payload, char **response, int sockid,
				   Connection *con) {
	cJSON *PayloadParsed = cJSON_Parse(payload);
	if (!PayloadParsed) {
		printf("Failed parsing, probably a client error or the servers "
			   "socketing code is faulty\n");
		return 0;
	}
	cJSON *responsebuild = cJSON_CreateObject();
	if (time(NULL) - con->LastEndpoint < 1) {
		con->ratelimited++;
	} else {
		con->LastEndpoint = time(NULL);
	}
	if(con->ratelimited>60){
		InsertError(responsebuild, 5);
		goto finishresp;
	}
	char *type =
		cJSON_GetStringValue(cJSON_GetObjectItem(PayloadParsed, "type"));
	if (!type) {
		InsertError(responsebuild, 3);
		goto finishresp;
	}
	if (strcmp(type, "request") == 0) {
		cJSON_AddStringToObject(responsebuild, "type", "response");
		cJSON *reqid = cJSON_GetObjectItem(PayloadParsed, "reqid");
		if (reqid) {
			cJSON_AddItemToObject(responsebuild, "reqid",
								  cJSON_Duplicate(reqid, cJSON_True));
		}
		char *endpoint = cJSON_GetStringValue(
			cJSON_GetObjectItem(PayloadParsed, "endpoint"));
		if (!endpoint) {
			InsertError(responsebuild, 3);
			goto finishresp;
		}
		if (strcmp(endpoint, "login") == 0) {
			char *username = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "username"));
			char *passwd = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "password"));
			if (!(username && passwd)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			char hashedPassword[65];
			sha256_hex(passwd, hashedPassword);
			const char *sql = "SELECT name, display_name FROM users WHERE name "
							  "= ? AND password = ?";
			sqlite3_stmt *stmt;
			sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
			sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, hashedPassword, -1, SQLITE_STATIC);
			if (sqlite3_step(stmt) == SQLITE_ROW) {
				printf("user login %s!", username);
				user *newUser = malloc(sizeof(user));
				newUser->username = strdup(username);
				newUser->displayname =
					strdup((const char *)sqlite3_column_text(stmt, 1));
				newUser->con = *con;
				newUser->status = (status){"online", "", "", ""};
				hashmap_set(UsersByFD, newUser);
				hashmap_set(UsersByName, newUser);
				char **usrlist = NULL;
				int nusrlist = 0;
				cJSON *spaces;
				CreateSpacesListFromUsername(username, &spaces);
				for (int i = 0; i < cJSON_GetArraySize(spaces); i++) {
					cJSON *space = cJSON_GetArrayItem(spaces, i);
					char *name =
						cJSON_GetObjectItem(space, "name")->valuestring;
					char **out;
					int outputlen;
					out = ListSpaceMembersNames(name, &outputlen);
					for (int j = 0; j < outputlen; j++) {
						int didntMatch = 1;
						for (int k = 0; k < nusrlist; k++) {
							if (strcmp(out[j], usrlist[k]) == 0) {
								didntMatch = 0;
							}
						}
						if (didntMatch) {

							usrlist = realloc(usrlist,
											  (nusrlist + 1) * sizeof(char *));
							usrlist[nusrlist] = out[j];
							nusrlist++;
						}
					}
				}
				cJSON *friends;
				CreateFriendsListFromUsername(username, &friends);
				for (int i = 0; i < cJSON_GetArraySize(friends); i++) {
					cJSON *friend = cJSON_GetArrayItem(friends, i);
					char *name =
						cJSON_GetObjectItem(friend, "name")->valuestring;
					int didntMatch = 1;
					for (int k = 0; k < nusrlist; k++) {
						if (strcmp(name, usrlist[k]) == 0) {
							didntMatch = 0;
						}
					}
					if (didntMatch) {

						usrlist =
							realloc(usrlist, (nusrlist + 1) * sizeof(char *));
						usrlist[nusrlist] = name;
						nusrlist++;
					}
				}
				for (int i = 0; i < nusrlist; i++) {
					PushStatusUpdate(usrlist[i], username, newUser->status);
				}
				cJSON_Delete(spaces);
				cJSON_Delete(friends);
				cJSON *tmp;
				CreateUsersOwnObjectFromUsername(username, &tmp);
				cJSON_AddItemToObject(responsebuild, "user", tmp);
				char **fql;
				int c = ListFriendReqs(username, &fql);
				cJSON* fqa = cJSON_AddArrayToObject(responsebuild, "pending_fq");
				for(int i = 0; i<c;i++){
					cJSON* tmp;
					CreateUserObjectFromUsername(fql[i], &tmp);
					cJSON_AddItemToArray(tmp, fqa);
					free(fql[i]);
				}
				InsertError(responsebuild, 0);
			} else {
				InsertError(responsebuild, 3);
			}
			sqlite3_finalize(stmt);
		} else if (strcmp(endpoint, "register") == 0) {
			if (time(NULL) - con->LastRegistration < 300) {
				InsertError(responsebuild, 5);
				goto finishresp;
			}
			cJSON *emailp =
				cJSON_GetObjectItem(PayloadParsed, "email"); // for future
			char *username = cJSON_GetStringValue(
				cJSON_GetObjectItemCaseSensitive(PayloadParsed, "username"));
			char *passwd = cJSON_GetStringValue(
				cJSON_GetObjectItemCaseSensitive(PayloadParsed, "password"));
			cJSON *resp = cJSON_CreateObject();
			if (!(username && passwd)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			} else {
				InsertError(responsebuild,
							(!RegisterUserAccount(username, passwd)) * 3);
			}
			con->LastRegistration = time(NULL);
			cJSON_AddItemToObject(responsebuild, "response", resp);
		} else if (strcmp(endpoint, "buddylist") == 0) {
			user search;
			search.con = *con;
			user *usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			printf("%s is asking for its buddies\n", usr->username);
			cJSON *tmp;
			if (usr->username) {
				if (CreateFriendsListFromUsername(usr->username, &tmp)) {
					cJSON_AddItemToObject(responsebuild, "response", tmp);
				}
			}
		} else if (strcmp(endpoint, "sendim") == 0) {
			char *content = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "content"));
			if (!content) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user search;
			search.con = *con;
			user *usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char *fromWho = usr->username;
			char *where = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "where"));
			if (!where) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			chat wherep;
			if (!YAMPProcessWhere(where, fromWho, &wherep)) {
				InsertError(responsebuild, 2);
				goto finishresp;
			} else {
				if (wherep.type == YAMP_GUILD &&
					!IsInSpace(usr->username, wherep.GuildName)) {
					InsertError(responsebuild, 2);
					goto finishresp;
				}
			}
			chat chatCtx;
			YAMPProcessWhere(where, fromWho, &chatCtx);
			if (chatCtx.type == YAMP_GUILD) {
				int outputLen;
				char **start =
					ListSpaceMembersNames(chatCtx.GuildName, &outputLen);
				for (int i = 0; i < outputLen; i++) {
					printf("%s\n", *(start + i));
					PushRecvIM(*(start + i), where, fromWho, content);
				}
				InsertMessage(where, fromWho, content);
			} else if (chatCtx.type == YAMP_DM) {
				PushRecvIM(chatCtx.OtherGuy, where, fromWho, content);
				PushRecvIM(fromWho, where, fromWho, content);
				InsertMessage(where, fromWho, content);
			}
		} else if (strcmp(endpoint, "getchannels") == 0) {
			user search;
			search.con = *con;
			user *usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char *guild = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "space"));
			if (!guild) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			if (!IsInSpace(usr->username, guild)) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			cJSON *channels;
			CreateChannelsListFromName(guild, &channels);
			cJSON_AddItemToObject(responsebuild, "response", channels);
		} else if (strcmp(endpoint, "GetUserDetails") == 0) {
			cJSON *details;
			char *name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "name"));
			if (!name) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			CreateUserObjectFromUsername(name, &details);
			cJSON_AddItemToObject(responsebuild, "response", details);
		} else if (strcmp(endpoint, "GetGuildDetails") == 0) {
			char *name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "name"));
			if (!name) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			cJSON *details;
			CreateSpaceObjectFromName(name, &details);
			cJSON_AddItemToObject(responsebuild, "response", details);
		} else if (strcmp(endpoint, "GetMessageHistory") ==
				   0) { // might use pascal case more... beware of breaking
						// changes to other ones soon
			user search;
			search.con = *con;

			user *usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char *fromWho = usr->username;

			char *where = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "where"));
			if (!where) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			chat wherep;
			if (!YAMPProcessWhere(where, fromWho, &wherep)) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			if (wherep.type == YAMP_GUILD) {
				if (!IsInSpace(usr->username, wherep.GuildName)) {
					InsertError(responsebuild, 2);
					goto finishresp;
				}
			}
			cJSON *messages = GetMessageHistory(where);
			cJSON_AddItemToObject(responsebuild, "response", messages);
		} else if (strcmp(endpoint, "RepositionChannel") == 0) {

		} else if (strcmp(endpoint, "CreateGuild") == 0) {
			const char *sql =
				"INSERT INTO \"spaces\" (\"name\", \"display_name\", "
				"\"channels\") VALUES (?, ?, ?)";
			sqlite3_stmt *stmt;
			sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
			char *name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "name"));
			char *display_name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "display_name"));
			sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, display_name, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 3, "general", -1, SQLITE_STATIC);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
			cJSON_AddStringToObject(responsebuild, "response", "success");

		} else if (strcmp(endpoint, "CreateChannel") == 0) {
		} else if (strcmp(endpoint, "SendFriendReq") == 0) {
			char *target =
				cJSON_GetStringValue(cJSON_GetObjectItem(PayloadParsed, "to"));
			if (!target) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user search;
			search.con = *con;
			const user *usr = hashmap_get(UsersByFD, &search);
			if (usr) {
				CreateFriendReq(usr->username, target);
				PushFQ(target, usr->username);
			}
		} else if (strcmp(endpoint, "AcceptFriendReq") == 0) {
			char *sender = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "user"));
			if (!sender) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user search;
			search.con = *con;
			const user *usr = hashmap_get(UsersByFD, &search);
			if (usr) {
				if(DestroyFriendReq(sender, usr->username)){
				CreateFriendship(sender, usr->username);
				InsertError(responsebuild, 0);
				}else{
				InsertError(responsebuild, 4);
				}
			}
		} else if (strcmp(endpoint, "DenyFriendReq") == 0) {
			char *sender = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "user"));
			if (!sender) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user search;
			search.con = *con;
			const user *usr = hashmap_get(UsersByFD, &search);
			if (usr) {
				DestroyFriendReq(sender, usr->username);
				InsertError(responsebuild, 0);
			}
		}

	} else {
		printf("no req november\n");
	}
finishresp:
	cJSON_Delete(PayloadParsed);
	char *resp = cJSON_Print(responsebuild);
	(*response) = resp;
	printf("%s\n", resp);
	cJSON_Delete(responsebuild);
	return 1;
}