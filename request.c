#include <stdio.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <string.h>
#include "helpers.h"
#include "hmap/hashmap.h"
#include "globals.h"
#include "handlers.h"
int ProcessRequest(char *payload, char **response, int sockid, int sockfd) {
	cJSON *responsebuild = cJSON_CreateObject();
	cJSON *PayloadParsed = cJSON_Parse(payload);
	if (!PayloadParsed) {
		printf("Failed parsing, probably a client error or the servers "
			   "socketing code is faulty\n");
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
				cJSON_AddStringToObject(responsebuild, "response", "success");
				user *newUser = malloc(sizeof(user));
				newUser->username = username;
    			newUser->displayname = strdup((const char *)sqlite3_column_text(stmt, 1));
				newUser->fd = sockfd;
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
			} else {

				cJSON_AddStringToObject(responsebuild, "response", "fail");
			}
			sqlite3_finalize(stmt);
		} else if (strcmp(endpoint, "buddylist") == 0) {
			user search;
			search.fd = sockfd;
			char *username =
				((user *)(hashmap_get(UsersByFD, &search)))->username;
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
			user search;
			search.fd = sockfd;
			char *fromWho =
				((user *)(hashmap_get(UsersByFD, &search)))->username;
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
					PushRecvIM(*(start + i), where, fromWho, content);
				}
				InsertMessage(where, fromWho, content);
			} else if (chatCtx.type == YAMP_DM) {
				PushRecvIM(chatCtx.OtherGuy, where, fromWho, content);
				PushRecvIM(fromWho, where, fromWho, content);
				InsertMessage(where, fromWho, content);
			}
		} else if (strcmp(endpoint, "getchannels") == 0) {
			char *guild =
				cJSON_GetObjectItem(PayloadParsed, "space")->valuestring;
			cJSON *channels;
			CreateChannelsListFromName(guild, &channels);
			cJSON_AddItemToObject(responsebuild, "response", channels);
		} else if (strcmp(endpoint, "GetUserDetails") == 0) {
			cJSON *details;
			CreateUserObjectFromUsername(
				cJSON_GetObjectItem(PayloadParsed, "name")->valuestring,
				&details);
			cJSON_AddItemToObject(responsebuild, "response", details);
		} else if (strcmp(endpoint, "GetGuildDetails") == 0) {
			cJSON *details;
			CreateSpaceObjectFromName(
				cJSON_GetObjectItem(PayloadParsed, "name")->valuestring,
				&details);
			cJSON_AddItemToObject(responsebuild, "response", details);
		} else if (strcmp(endpoint, "GetMessageHistory") ==
				   0) { // might use pascal case more... beware of breaking
						// changes to other ones soon
			cJSON *messages = GetMessageHistory(
				cJSON_GetObjectItem(PayloadParsed, "where")->valuestring);
			cJSON_AddItemToObject(responsebuild, "response", messages);
		} else if (strcmp(endpoint, "RepositionChannel") == 0) {

		} else if (strcmp(endpoint, "CreateGuild") == 0) {
			const char *sql =
				"INSERT INTO \"spaces\" (\"name\", \"display_name\", "
				"\"channels\") VALUES (?, ?, ?)";
			sqlite3_stmt *stmt;
			sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
			sqlite3_bind_text(
				stmt, 1,
				cJSON_GetObjectItem(PayloadParsed, "name")->valuestring, -1,
				SQLITE_STATIC);
			sqlite3_bind_text(
				stmt, 2,
				cJSON_GetObjectItem(PayloadParsed, "display_name")->valuestring,
				-1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 3, "general", -1, SQLITE_STATIC);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
			cJSON_AddStringToObject(responsebuild, "response", "success");

		} else if (strcmp(endpoint, "CreateChannel") == 0) {
		}

	} else {
		printf("no req november\n");
	}
	(*response) = cJSON_Print(responsebuild);
	printf(cJSON_Print(responsebuild));
	printf("\n");
	return 1;
}