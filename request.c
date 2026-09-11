#include <stdio.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <string.h>
#include "helpers.h"
#include "hmap/hashmap.h"
#include "globals.h"
#include "handlers.h"
#include "types.h"
int ProcessRequest(char *payload, char **response, int sockid, Connection* con) {
	if(time(NULL)-con->LastEndpoint<1){
		return 0;
	}else{
		con->LastEndpoint=time(NULL);
	}
	if(time(NULL)-con->LastRegistration<60){
		return 0;
	}
	cJSON *responsebuild = cJSON_CreateObject();
	cJSON *PayloadParsed = cJSON_Parse(payload);
	if (!PayloadParsed) {
		printf("Failed parsing, probably a client error or the servers "
			   "socketing code is faulty\n");
		return 0;
	}
	cJSON* typep = cJSON_GetObjectItem(PayloadParsed, "type");
	char *type;
	if(typep){
		type=typep->valuestring;
	}else{
		return 0;
	}
	if (strcmp(type, "request") == 0) {
		cJSON_AddStringToObject(responsebuild, "type", "response");
		cJSON *reqid = cJSON_GetObjectItem(PayloadParsed, "reqid");
		if(reqid){
		cJSON_AddItemToObject(responsebuild, "reqid",
							  cJSON_Duplicate(reqid, cJSON_True));
		}
		cJSON* endpointp = cJSON_GetObjectItem(PayloadParsed, "endpoint");
		char *endpoint =
			endpointp->valuestring;
		if (strcmp(endpoint, "login") == 0) {
			cJSON* usernamep = cJSON_GetObjectItem(PayloadParsed, "username");
			cJSON* passwdp = cJSON_GetObjectItem(PayloadParsed, "password");
			if(!(usernamep && passwdp)){
				return 0;
			}
			char *username = strdup(
				usernamep->valuestring);
			char *passwd =
				passwdp->valuestring;
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
				newUser->displayname =
					strdup((const char *)sqlite3_column_text(stmt, 1));
				newUser->con=*con;
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
		} else if(strcmp(endpoint,"register")==0){
			cJSON *emailp = cJSON_GetObjectItem(PayloadParsed, "email"); // for future
			cJSON *usernamep = cJSON_GetObjectItem(PayloadParsed, "username");
			cJSON *passwdp = cJSON_GetObjectItem(PayloadParsed, "password");
			cJSON *resp = cJSON_CreateObject();
			if(!(usernamep && passwdp)){
				cJSON_AddBoolToObject(responsebuild, "succeed", 0);
			}else{
				char* username = usernamep->valuestring;
				char* passwd = passwdp->valuestring;
				cJSON_AddBoolToObject(responsebuild, "succeed", RegisterUserAccount(username, passwd));
			}
			con->LastRegistration=time(NULL);
			cJSON_AddItemToObject(responsebuild, "response", resp);
		} else if (strcmp(endpoint, "buddylist") == 0) {
			user search;
			search.con=*con;
			user* usr = hashmap_get(UsersByFD, &search);
			if(!usr){
				return 0;
			}
			printf("%s is asking for its buddies\n", usr->username);
			cJSON *tmp;
			if (usr->username) {
				if (CreateFriendsListFromUsername(usr->username, &tmp)) {
					cJSON_AddItemToObject(responsebuild, "response", tmp);
				}
			}
		} else if (strcmp(endpoint, "sendim") == 0) {
			cJSON* contentp =
				cJSON_GetObjectItem(PayloadParsed, "content");
			if(!contentp){
				return 0;
			}
			char* content = contentp->valuestring;
			user search;
			search.con=*con;
			user* usr = hashmap_get(UsersByFD, &search);
			if(!usr){
				return 0;
			}
			char* fromWho = usr->username;
			cJSON* rwhere = cJSON_GetObjectItem(PayloadParsed, "where");
			if(!rwhere){
				return 0;
			}
			char *where =
				rwhere->valuestring;
			chat wherep;
			if(!YAMPProcessWhere(where, fromWho, &wherep)){
				return 0;
			} else {
				if(wherep.type == YAMP_GUILD && !IsInSpace(usr->username, wherep.GuildName)){
					return 0;
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
			search.con=*con;
			user* usr = hashmap_get(UsersByFD, &search);
			if(!usr){
				return 0;
			}
			cJSON* guildp = cJSON_GetObjectItem(PayloadParsed, "space");
			if(!guildp){
				return 0;
			}
			char *guild =
				guildp->valuestring;
			if(!IsInSpace(usr->username, guild)){
				return 0;
			}
			cJSON *channels;
			CreateChannelsListFromName(guild, &channels);
			cJSON_AddItemToObject(responsebuild, "response", channels);
		} else if (strcmp(endpoint, "GetUserDetails") == 0) {
			cJSON *details;
			cJSON *namep=cJSON_GetObjectItem(PayloadParsed, "name");
			if(!namep){
				return 0;
			}
			CreateUserObjectFromUsername(
				namep->valuestring,
				&details);
			cJSON_AddItemToObject(responsebuild, "response", details);
		} else if (strcmp(endpoint, "GetGuildDetails") == 0) {
			cJSON *namep=cJSON_GetObjectItem(PayloadParsed, "name");
			if(!namep){
				return 0;
			}
			cJSON *details;
			CreateSpaceObjectFromName(
				namep->valuestring,
				&details);
			cJSON_AddItemToObject(responsebuild, "response", details);
		} else if (strcmp(endpoint, "GetMessageHistory") ==
				   0) { // might use pascal case more... beware of breaking
						// changes to other ones soon
			user search;
			search.con=*con;
			
			user* usr = hashmap_get(UsersByFD, &search);
			if(!usr){
				return 0;
			}
			char* fromWho = usr->username;

			char *where =
				cJSON_GetObjectItem(PayloadParsed, "where")->valuestring;
			chat wherep;
			if(!YAMPProcessWhere(where, fromWho, &wherep)){
				return 0;
			}
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
		} else if (strcmp(endpoint, "SendFriendReq") == 0) {
			cJSON *targetp = cJSON_GetObjectItem(PayloadParsed, "to");
			char *target = targetp ? targetp->valuestring : "";
			user search;
			search.con=*con;
			const user *usr = hashmap_get(UsersByFD, &search);
			if (usr) {
				PushFQ(target, usr->username);
			}
		} else if (strcmp(endpoint, "AcceptFriendReq")) {
			cJSON *senderp = cJSON_GetObjectItem(PayloadParsed, "user");
			if (senderp) {
				char *sender = senderp->valuestring;
				user search;
				search.con=*con;
				const user *usr = hashmap_get(UsersByFD, &search);
				if (usr) {
					DestroyFriendReq(sender,usr->username);
					CreateFriendship(sender,usr->username);
				}
			}
		} else if (strcmp(endpoint, "DenyFriendReq")) {
			cJSON *senderp = cJSON_GetObjectItem(PayloadParsed, "user");
			if (senderp) {
				char *sender = senderp->valuestring;
				user search;
				search.con=*con;
				const user *usr = hashmap_get(UsersByFD, &search);
				if (usr) {
					DestroyFriendReq(sender,usr->username);
				}
			}
		}

	} else {
		printf("no req november\n");
	}
	cJSON_Delete(PayloadParsed);
	char* resp = cJSON_Print(responsebuild);
	(*response) = resp;
	printf("%s\n",resp);
	cJSON_Delete(responsebuild);
	return 1;
}