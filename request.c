#include "globals.h"
#include "handlers.h"
#include "helpers.h"
#include "hmap/hashmap.h"
#include "types.h"
#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include <unistd.h>
#include <arpa/inet.h>
typedef struct {
	int code;
	const char* msg;
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
	{8, "Already friends"},
	{9, "You cannot friend yourself (That's schizophrenia)"},
	{10, "No such object (user/space)"},
	{11, "No such channel, malformed where field?"},
	{12, "Above the maximum length of a text field"},
};

static const char* ErrorMessage(int code) {
	for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		if (errors[i].code == code)
			return errors[i].msg;
	}
	return "Unknown error";
}

void InsertError(cJSON* resp, int error) {
	cJSON_AddBoolToObject(resp, "success", error == 0);

	cJSON* err = cJSON_CreateObject();
	cJSON_AddNumberToObject(err, "code", error);
	cJSON_AddStringToObject(err, "message", ErrorMessage(error));
	cJSON_AddItemToObject(resp, "error", err);
}
static int IDInList(char** list, int n, const char* id) {
	for (int i = 0; i < n; i++)
		if (strcmp(list[i], id) == 0)
			return 1;
	return 0;
}

static void AddUniqueID(char*** list, int* n, const char* id) {
	if (!id || IDInList(*list, *n, id))
		return;
	char** tmp = realloc(*list, (*n + 1) * sizeof(char*));
	if (!tmp)
		return;
	*list = tmp;
	(*list)[*n] = strdup(id);
	(*n)++;
}

static void FreeIDList(char** list, int n) {
	for (int i = 0; i < n; i++)
		free(list[i]);
	free(list);
}

char** CollectRelatedUserIDs(const char* username, const char* selfid,
							 int* count) {
	char** list = NULL;
	*count = 0;
	if (selfid) {
		AddUniqueID(&list, count, selfid);
	}

	cJSON* spaces = NULL;
	CreateSpacesListFromID(selfid, &spaces);
	for (int i = 0; i < cJSON_GetArraySize(spaces); i++) {
		cJSON* idj = cJSON_GetObjectItem(cJSON_GetArrayItem(spaces, i), "id");
		if (!cJSON_IsString(idj))
			continue;
		cJSON* members = ListSpaceMembersFromID(idj->valuestring);
		for (int j = 0; j < cJSON_GetArraySize(members); j++) {
			cJSON* mid =
				cJSON_GetObjectItem(cJSON_GetArrayItem(members, j), "id");
			if (cJSON_IsString(mid))
				AddUniqueID(&list, count, mid->valuestring);
		}
		cJSON_Delete(members);
	}
	cJSON_Delete(spaces);

	cJSON* friends = NULL;
	CreateFriendsListFromUserID(selfid, &friends);
	for (int i = 0; i < cJSON_GetArraySize(friends); i++) {
		cJSON* fid = cJSON_GetObjectItem(cJSON_GetArrayItem(friends, i), "id");
		if (cJSON_IsString(fid))
			AddUniqueID(&list, count, fid->valuestring);
	}
	cJSON_Delete(friends);
	return list;
}
int ProcessRequest(char* payload, char** response, int sockid,
				   Connection* con) {
	cJSON* WireParsed = cJSON_Parse(payload);
	if (!WireParsed) {
		printf("Failed parsing, probably a client error or the servers "
			   "socketing code is faulty\n");
		return 0;
	}
	cJSON* PayloadParsed = cJSON_GetObjectItem(WireParsed, "payload");
	if (!PayloadParsed) {
		printf("Failed to find the payload, a broken client?\n");
		return 0;
	}
	cJSON* responsebuild = cJSON_CreateObject();
	cJSON* responsepayload = cJSON_CreateObject();
	if (time(NULL) - con->LastEndpoint < 1) {
		con->ratelimited++;
	} else {
		con->LastEndpoint = time(NULL);
	}
	time_t now = time(NULL);
	int elapsed = (int)difftime(now, con->LastEndpoint);
	con->ratelimited = MAX(0, con->ratelimited - elapsed * 3);
	con->LastEndpoint = now;

	if (con->ratelimited > 30) {
		InsertError(responsebuild, 5);
		goto finishresp;
	}
	con->ratelimited--;
	char* type = cJSON_GetStringValue(cJSON_GetObjectItem(WireParsed, "type"));
	if (!type) {
		InsertError(responsebuild, 3);
		goto finishresp;
	}
	if (strcmp(type, "request") == 0) {
		cJSON_AddStringToObject(responsebuild, "type", "response");
		cJSON* reqid = cJSON_GetObjectItem(WireParsed, "reqid");
		if (reqid) {
			cJSON_AddItemToObject(responsebuild, "reqid",
								  cJSON_Duplicate(reqid, cJSON_True));
		}
		char* endpoint =
			cJSON_GetStringValue(cJSON_GetObjectItem(WireParsed, "endpoint"));
		if (!endpoint) {
			InsertError(responsebuild, 3);
			goto finishresp;
		}
		if (strcmp(endpoint, "login") == 0) {
			char* username = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "username"));
			char* passwd = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "password"));
			if (!(username && passwd)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			char hashedPassword[65];
			sha256_hex(passwd, hashedPassword);
			const char* sql =
				"SELECT name, display_name, id FROM users WHERE name "
				"= ? AND password = ?";
			sqlite3_stmt* stmt;
			sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
			sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, hashedPassword, -1, SQLITE_STATIC);
			if (sqlite3_step(stmt) == SQLITE_ROW) {
				printf("user login %s!", username);
				user* newUser = malloc(sizeof(user));
				*newUser = (user){0};
				newUser->username = strdup(username);
				newUser->displayname =
					strdup((const char*)sqlite3_column_text(stmt, 1));
				strncpy(newUser->id, (const char*)sqlite3_column_text(stmt, 2),
						17);
				newUser->con = *con;
				newUser->status = (status){"online", "", "", ""};
				hashmap_set(UsersByFD, newUser);
				hashmap_set(UsersByName, newUser);
				hashmap_set(UsersByID, newUser);
				char** usrlist = NULL;
				int nusrlist = 0;
				cJSON* spaces;
				CreateSpacesListFromUsername(username, &spaces);
				cJSON_AddItemToObject(responsepayload, "spaces", spaces);
				for (int i = 0; i < cJSON_GetArraySize(spaces); i++) {
					cJSON* space = cJSON_GetArrayItem(spaces, i);
					char* spaceid =
						cJSON_GetObjectItem(space, "id")->valuestring;
					cJSON* out;
					int outputlen;
					out = ListSpaceMembersFromID(spaceid);
					for (int j = 0; j < cJSON_GetArraySize(out); j++) {
						cJSON* user = cJSON_GetArrayItem(out, i);
						int didntMatch = 1;
						for (int k = 0; k < nusrlist; k++) {
							if (strcmp(cJSON_GetObjectItem(user, "id")
										   ->valuestring,
									   usrlist[k]) == 0) {
								didntMatch = 0;
							}
						}
						if (didntMatch) {

							usrlist = realloc(usrlist,
											  (nusrlist + 1) * sizeof(char*));
							usrlist[nusrlist] =
								cJSON_GetObjectItem(user, "id")->valuestring;
							nusrlist++;
						}
					}
				}
				cJSON* friends;
				CreateFriendsListFromUserID(newUser->id, &friends);
				for (int i = 0; i < cJSON_GetArraySize(friends); i++) {
					cJSON* friend = cJSON_GetArrayItem(friends, i);
					char* name = cJSON_GetObjectItem(friend, "id")->valuestring;
					int didntMatch = 1;
					for (int k = 0; k < nusrlist; k++) {
						if (strcmp(name, usrlist[k]) == 0) {
							didntMatch = 0;
						}
					}
					if (didntMatch) {

						usrlist =
							realloc(usrlist, (nusrlist + 1) * sizeof(char*));
						usrlist[nusrlist] = name;
						nusrlist++;
					}
				}
				for (int i = 0; i < nusrlist; i++) {
					PushStatusUpdate(usrlist[i], username, newUser->status);
				}
				cJSON* tmp;
				CreateUsersOwnObjectFromUsername(username, &tmp);
				cJSON_AddItemToObject(responsepayload, "user", tmp);
				FriendReqEntry* fql = NULL;
				int c = ListFriendReqs(username, &fql);
				cJSON* incfq =
					cJSON_AddArrayToObject(responsepayload, "incoming_fq");
				cJSON* outfq =
					cJSON_AddArrayToObject(responsepayload, "outgoing_fq");
				for (int i = 0; i < c; i++) {
					cJSON* user = NULL;
					if (CreateUserObjectFromUsername(fql[i].username, &user) &&
						user) {
						if (fql[i].outgoing) {
							cJSON_AddItemToArray(outfq, user);
						} else {
							cJSON_AddItemToArray(incfq, user);
						}
					}
					free(fql[i].username);
				}
				free(fql);
				if (friends) {
					cJSON_AddItemToObject(responsepayload, "friends", friends);
				}
				cJSON* conversations;
				if (CreateConvListFromUserID(newUser->id, &conversations)) {
					cJSON_AddItemToObject(responsepayload, "conversations", conversations);
				}
				for (int i = 0; i < nrespoverrides; i++) {
					cJSON_AddStringToObject(responsepayload,
											respoverrides[i].key,
											respoverrides[i].val);
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
			cJSON* emailp =
				cJSON_GetObjectItem(PayloadParsed, "email"); // for future
			char* username = cJSON_GetStringValue(
				cJSON_GetObjectItemCaseSensitive(PayloadParsed, "username"));
			char* passwd = cJSON_GetStringValue(
				cJSON_GetObjectItemCaseSensitive(PayloadParsed, "password"));
			if (!(username && passwd)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			} else {
				cJSON* resp = cJSON_CreateObject();
				InsertError(responsebuild,
							(!RegisterUserAccount(username, passwd)) * 3);
				cJSON_AddItemToObject(responsebuild, "response", resp);
			}
			con->LastRegistration = time(NULL);
		} else if (strcmp(endpoint, "ListFriends") == 0) {
			user search;
			search.con = *con;
			user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			cJSON* tmp;
			if (usr->username) {
				if (CreateFriendsListFromUserID(usr->id, &tmp)) {
					cJSON_AddItemToObject(responsepayload, "friends", tmp);
				}
			}
		} else if(strcmp(endpoint,"ListConversations")==0){
			user search;
			search.con = *con;
			user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			cJSON* tmp;
			if (usr->username) {
				if (CreateConvListFromUserID(usr->id, &tmp)) {
					cJSON_AddItemToObject(responsepayload, "conversations", tmp);
				}
			}
		} else if(strcmp(endpoint,"StartDM")==0){
			user search;
			search.con = *con;
			user* usr = hashmap_get(UsersByFD,&search);
			if(!usr){
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char* recipient = cJSON_GetStringValue(cJSON_GetObjectItem(PayloadParsed, "recipient"));
			if(!recipient){
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			if(!HasDMs(usr->id,recipient)){
				CreateDM(usr->id,recipient);
			}
			InsertError(responsebuild,0);
		} else if(strcmp(endpoint,"CreateGC")==0){
			user search;
			search.con = *con;
			user* usr = hashmap_get(UsersByFD,&search);
			if(!usr){
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			cJSON* initial_members = cJSON_GetObjectItem(PayloadParsed, "members");
			if(!initial_members){
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user* parsed_initmem = malloc(cJSON_GetArraySize(initial_members)*sizeof(user));
			int validusers = 0;
			for(int i = 0; i<cJSON_GetArraySize(initial_members); i++){
				user usr;
				if(CreateUserTypeFromID(cJSON_GetArrayItem(initial_members, i)->valuestring,&usr)){
					parsed_initmem[i]=usr;
					validusers++;
				}
			}
			CreateGC(*usr,validusers,parsed_initmem);
			InsertError(responsebuild,0);
		} else if(strcmp(endpoint,"AddMemberToGC")==0){
			user search;
			search.con = *con;
			user* usr = hashmap_get(UsersByFD,&search);
			if(!usr){
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char* userid = cJSON_GetStringValue(cJSON_GetObjectItem(PayloadParsed, "user"));
			char* gcid = cJSON_GetStringValue(cJSON_GetObjectItem(PayloadParsed, "gc"));
			if(!userid){
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			if(!gcid){
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			if(IsInGC(usr->id,gcid)){
				AddMemberToGC(userid, gcid);
				InsertError(responsebuild,0);
			} else {
				InsertError(responsebuild,2);
			}
		} else if(strcmp(endpoint,"RemoveFromGC")==0){
		
		} else if (strcmp(endpoint, "ListSpaceMembers") == 0) {
			user search;
			search.con = *con;
			user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char* space = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "space"));
			if (!space) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			if (!IsInSpaceViaUserID(usr->id, space)) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			cJSON* tmp;
			tmp = ListSpaceMembersFromID(usr->username);
			cJSON_AddItemToObject(responsepayload, "space_members", tmp);
		} else if (strcmp(endpoint, "SendMessage") == 0) {
			char* content = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "content"));
			if (!content) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user search;
			search.con = *con;
			user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char* fromWho = usr->id;
			char* where = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "channel"));
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
					!IsInSpaceViaUserID(usr->id, wherep.GuildName)) {
					InsertError(responsebuild, 2);
					goto finishresp;
				}
			}
			chat chatCtx;
			YAMPProcessWhere(where, fromWho, &chatCtx);
			if (chatCtx.type == YAMP_GUILD) {
				int outputLen;
				cJSON* start = ListSpaceMembersFromID(chatCtx.GuildName);
				for (int i = 0; i < cJSON_GetArraySize(start); i++) {
					cJSON* user = cJSON_GetArrayItem(start, i);
					PushRecvIM(cJSON_GetObjectItem(user, "id")->valuestring,
							   where, fromWho, content);
				}
				cJSON_Delete(start);
				InsertMessage(where, fromWho, content);
			} else if (chatCtx.type == YAMP_DM) {
				PushRecvIM(chatCtx.OtherGuy, where, fromWho, content);
				PushRecvIM(fromWho, where, fromWho, content);
				InsertMessage(where, fromWho, content);
			} else if (chatCtx.type == YAMP_GC){
				int outputLen;
				cJSON* start = ListGCMembersFromID(chatCtx.GC_ID);
				for (int i = 0; i < cJSON_GetArraySize(start); i++) {
					cJSON* user = cJSON_GetArrayItem(start, i);
					PushRecvIM(cJSON_GetObjectItem(user, "id")->valuestring,
							   where, fromWho, content);
				}
				cJSON_Delete(start);
				InsertMessage(where, fromWho, content);
			}
			InsertError(responsebuild, 0);
		} else if (strcmp(endpoint, "GetChannels") == 0) {
			user search;
			search.con = *con;
			user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char* guild = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "space"));
			if (!guild) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			if (!IsInSpaceViaUserID(usr->id, guild)) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			cJSON* channels;
			CreateChannelsListFromName(guild, &channels);
			cJSON_AddItemToObject(responsepayload, "channels", channels);
			InsertError(responsebuild, 0);
		} else if (strcmp(endpoint, "GetUserDetails") == 0) {
			cJSON* details;
			char* name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "name"));
			if (!name) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			CreateUserObjectFromUsername(name, &details);
			cJSON_AddItemToObject(responsepayload, "user", details);
			InsertError(responsebuild, 0);
		} else if (strcmp(endpoint, "GetSpaceDetails") == 0) {
			char* space = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "space"));
			if (!space) {
				InsertError(responsebuild, 2);
				goto finishresp;
			}
			cJSON* details;
			CreateSpaceObjectFromID(space, &details);
			cJSON_AddItemToObject(responsepayload, "space", details);
			InsertError(responsebuild, 0);
		} else if (strcmp(endpoint, "GetMessageHistory") ==
				   0) { // might use pascal case more... beware of breaking
						// changes to other ones soon
			user search;
			search.con = *con;

			user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char* fromWho = usr->id;

			char* where = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "channel"));
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
				if (!IsInSpaceViaUserID(usr->id, wherep.GuildName)) {
					InsertError(responsebuild, 2);
					goto finishresp;
				}
			}
			if (wherep.type == YAMP_GC) {
				if (!IsInGC(usr->id, wherep.GC_ID)) {
					InsertError(responsebuild, 2);
					goto finishresp;
				}
			}
			cJSON* messages = GetMessageHistory(where);
			cJSON_AddItemToObject(responsepayload, "messages", messages);
			InsertError(responsebuild, 0);
		} else if (strcmp(endpoint, "RepositionChannel") == 0) {
			char* space = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "space"));
			char* name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "name"));
			cJSON* positem = cJSON_GetObjectItem(PayloadParsed, "pos");

			if (!space || !name || !cJSON_IsNumber(positem)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}

			int newpos = positem->valueint;

			const char* getsql = "SELECT \"pos\" FROM \"channels\" "
								 "WHERE \"space\" = ? AND \"name\" = ?";

			sqlite3_stmt* stmt;
			if (sqlite3_prepare_v2(DB, getsql, -1, &stmt, NULL) != SQLITE_OK) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}

			sqlite3_bind_text(stmt, 1, space, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);

			if (sqlite3_step(stmt) != SQLITE_ROW) {
				sqlite3_finalize(stmt);
				InsertError(responsebuild, 4);
				goto finishresp;
			}

			int oldpos = sqlite3_column_int(stmt, 0);
			sqlite3_finalize(stmt);

			if (oldpos == newpos) {
				InsertError(responsebuild, 0);
				goto finishresp;
			}
			const char* tempsql = "UPDATE \"channels\" SET \"pos\" = -1 "
								  "WHERE \"space\" = ? AND \"name\" = ?";

			if (sqlite3_prepare_v2(DB, tempsql, -1, &stmt, NULL) != SQLITE_OK) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}

			sqlite3_bind_text(stmt, 1, space, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);

			if (newpos < oldpos) {
				const char* sql = "UPDATE \"channels\" "
								  "SET \"pos\" = \"pos\" + 1 "
								  "WHERE \"space\" = ? "
								  "AND \"pos\" >= ? AND \"pos\" < ?";

				if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
					InsertError(responsebuild, 1);
					goto finishresp;
				}

				sqlite3_bind_text(stmt, 1, space, -1, SQLITE_STATIC);
				sqlite3_bind_int(stmt, 2, newpos);
				sqlite3_bind_int(stmt, 3, oldpos);
			} else {
				const char* sql = "UPDATE \"channels\" "
								  "SET \"pos\" = \"pos\" - 1 "
								  "WHERE \"space\" = ? "
								  "AND \"pos\" > ? AND \"pos\" <= ?";

				if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
					InsertError(responsebuild, 1);
					goto finishresp;
				}

				sqlite3_bind_text(stmt, 1, space, -1, SQLITE_STATIC);
				sqlite3_bind_int(stmt, 2, oldpos);
				sqlite3_bind_int(stmt, 3, newpos);
			}

			sqlite3_step(stmt);
			sqlite3_finalize(stmt);

			const char* setsql = "UPDATE \"channels\" SET \"pos\" = ? "
								 "WHERE \"space\" = ? AND \"name\" = ?";

			if (sqlite3_prepare_v2(DB, setsql, -1, &stmt, NULL) != SQLITE_OK) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}

			sqlite3_bind_int(stmt, 1, newpos);
			sqlite3_bind_text(stmt, 2, space, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 3, name, -1, SQLITE_STATIC);

			sqlite3_step(stmt);
			sqlite3_finalize(stmt);

			InsertError(responsebuild, 0);

		} else if (strcmp(endpoint, "CreateSpace") == 0) {
			user search;
			search.con = *con;

			user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char* fromWho = usr->id;
			char* id;
			GenerateID(&id);
			const char* sql = "INSERT INTO \"spaces\" (\"id\", \"name\", "
							  "\"display_name\", \"type\", \"description\", "
							  "\"icon\", \"banner\", \"owner\") VALUES (?, ?, "
							  "?, ?, ?, ?, ?, ?)";
			sqlite3_stmt* stmt;
			sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
			char* name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "name"));
			char* display_name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "display_name"));
			cJSON* descriptionp =
				cJSON_GetObjectItem(PayloadParsed, "description");
			cJSON* iconp = cJSON_GetObjectItem(PayloadParsed, "icon");
			cJSON* bannerp = cJSON_GetObjectItem(PayloadParsed, "banner");
			int type = cJSON_GetNumberValue(
				cJSON_GetObjectItem(PayloadParsed, "space_type"));
			if (!name || !display_name) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			if (descriptionp && !cJSON_IsString(descriptionp)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			if (iconp && !cJSON_IsString(iconp)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			if (bannerp && !cJSON_IsString(bannerp)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
			sqlite3_bind_text(stmt, 3, display_name, -1, SQLITE_STATIC);
			sqlite3_bind_int(stmt, 4, type);
			sqlite3_bind_text(stmt, 5,
							  descriptionp ? descriptionp->valuestring : "", -1,
							  SQLITE_STATIC);
			sqlite3_bind_text(stmt, 6, iconp ? iconp->valuestring : "", -1,
							  SQLITE_STATIC);
			sqlite3_bind_text(stmt, 7, bannerp ? bannerp->valuestring : "", -1,
							  SQLITE_STATIC);
			sqlite3_bind_text(stmt, 8, usr->id, -1, SQLITE_STATIC);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
			const char* csql = "INSERT INTO \"channels\" (\"name\", \"pos\", "
							   "\"space\", \"id\") VALUES (?, ?, ?, ?)";
			sqlite3_stmt* cstmt;
			sqlite3_prepare_v2(DB, csql, -1, &cstmt, NULL);
			sqlite3_bind_text(cstmt, 1, "general", -1, SQLITE_STATIC);
			sqlite3_bind_int(cstmt, 2, 0);
			sqlite3_bind_text(cstmt, 3, id, -1, SQLITE_STATIC);
			char* channel_id;
			GenerateID(&channel_id);
			sqlite3_bind_text(cstmt, 4, channel_id, -1, SQLITE_STATIC);
			sqlite3_step(cstmt);
			sqlite3_finalize(cstmt);
			const char* msql =
				"INSERT INTO \"user-space\" (\"user-id\", \"space-id\", "
				"\"pos\") "
				"VALUES (?, ?, COALESCE((SELECT MAX(\"pos\") + 1 FROM "
				"\"user-space\" WHERE \"user-id\" = ?), 0))";
			sqlite3_stmt* mstmt;
			sqlite3_prepare_v2(DB, msql, -1, &mstmt, NULL);
			sqlite3_bind_text(mstmt, 1, usr->id, -1, SQLITE_STATIC);
			sqlite3_bind_text(mstmt, 2, id, -1, SQLITE_STATIC);
			sqlite3_bind_text(mstmt, 3, usr->id, -1, SQLITE_STATIC);
			int mret = sqlite3_step(mstmt);
			sqlite3_finalize(mstmt);
			if (!(mret == SQLITE_DONE)) {
				printf("%s\n", sqlite3_errmsg(DB));
				InsertError(responsebuild, 4);
			} else {
				InsertError(responsebuild, 0);
			}
			PushNewSpace(fromWho, id);
			free(id);
			free(channel_id);
		} else if (strcmp(endpoint, "InsertChannel") == 0) {
			user search;
			search.con = *con;

			user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			char* space = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "space"));
			char* name = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "name"));
			cJSON* positem = cJSON_GetObjectItem(PayloadParsed, "pos");
			cJSON* typeitem = cJSON_GetObjectItem(PayloadParsed, "channeltype");
			cJSON* parentitem = cJSON_GetObjectItem(PayloadParsed, "parent");

			if (!space || !name) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}

			int pos_provided = positem && cJSON_IsNumber(positem);
			int pos = pos_provided ? positem->valueint : 0;

			int type =
				typeitem && cJSON_IsNumber(typeitem) ? typeitem->valueint : 0;

			char* parent = NULL;
			if (parentitem && cJSON_IsString(parentitem) &&
				parentitem->valuestring && parentitem->valuestring[0] != '\0') {
				parent = parentitem->valuestring;
			} else if (parentitem && !cJSON_IsNull(parentitem) &&
					   !cJSON_IsString(parentitem)) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}

			sqlite3_stmt* stmt;
			if (parent) {
				const char* parent_check_sql =
					"SELECT 1 FROM \"channels\" "
					"WHERE \"space\" = ? AND \"name\" = ? LIMIT 1";

				if (sqlite3_prepare_v2(DB, parent_check_sql, -1, &stmt, NULL) !=
					SQLITE_OK) {
					InsertError(responsebuild, 1);
					goto finishresp;
				}
				sqlite3_bind_text(stmt, 1, space, -1, SQLITE_STATIC);
				sqlite3_bind_text(stmt, 2, parent, -1, SQLITE_STATIC);

				int found = (sqlite3_step(stmt) == SQLITE_ROW);
				sqlite3_finalize(stmt);

				if (!found) {
					InsertError(responsebuild, 4);
					goto finishresp;
				}
			}

			if (!pos_provided) {
				const char* max_pos_sql =
					"SELECT COALESCE(MAX(\"pos\"), -1) + 1 FROM \"channels\" "
					"WHERE \"space\" = ? AND \"parent\" IS ?";

				if (sqlite3_prepare_v2(DB, max_pos_sql, -1, &stmt, NULL) !=
					SQLITE_OK) {
					InsertError(responsebuild, 1);
					goto finishresp;
				}

				sqlite3_bind_text(stmt, 1, space, -1, SQLITE_STATIC);
				if (parent) {
					sqlite3_bind_text(stmt, 2, parent, -1, SQLITE_STATIC);
				} else {
					sqlite3_bind_null(stmt, 2);
				}

				if (sqlite3_step(stmt) == SQLITE_ROW) {
					pos = sqlite3_column_int(stmt, 0);
				} else {
					pos = 0;
				}
				sqlite3_finalize(stmt);
			} else {
				const char* shift_sql =
					"UPDATE \"channels\" "
					"SET \"pos\" = \"pos\" + 1 "
					"WHERE \"space\" = ? AND \"parent\" IS ? AND \"pos\" >= ?";

				if (sqlite3_prepare_v2(DB, shift_sql, -1, &stmt, NULL) !=
					SQLITE_OK) {
					InsertError(responsebuild, 1);
					goto finishresp;
				}

				sqlite3_bind_text(stmt, 1, space, -1, SQLITE_STATIC);
				if (parent) {
					sqlite3_bind_text(stmt, 2, parent, -1, SQLITE_STATIC);
				} else {
					sqlite3_bind_null(stmt, 2);
				}
				sqlite3_bind_int(stmt, 3, pos);
				sqlite3_step(stmt);
				sqlite3_finalize(stmt);
			}

			const char* sql =
				"INSERT INTO \"channels\" "
				"(\"name\", \"pos\", \"space\", \"type\", \"parent\", \"id\") "
				"VALUES (?, ?, ?, ?, ?, ?)";

			if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}

			sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
			sqlite3_bind_int(stmt, 2, pos);
			sqlite3_bind_text(stmt, 3, space, -1, SQLITE_STATIC);
			sqlite3_bind_int(stmt, 4, type);
			if (parent) {
				sqlite3_bind_text(stmt, 5, parent, -1, SQLITE_STATIC);
			} else {
				sqlite3_bind_null(stmt, 5);
			}
			char* channelid;
			GenerateID(&channelid);
			sqlite3_bind_text(stmt, 6, channelid, -1, SQLITE_STATIC);

			if (sqlite3_step(stmt) != SQLITE_DONE) {
				sqlite3_finalize(stmt);
				InsertError(responsebuild, 1);
				goto finishresp;
			}

			sqlite3_finalize(stmt);
			InsertError(responsebuild, 0);
			cJSON* spacemembers = ListSpaceMembersFromID(space);
			for (int i = 0; i < cJSON_GetArraySize(spacemembers); i++) {
				cJSON* user = cJSON_GetArrayItem(spacemembers, i);
				PushUpdatedChannelsList(
					cJSON_GetObjectItem(user, "id")->valuestring, space);
			}
			cJSON_Delete(spacemembers);
			free(channelid);
		} else if (strcmp(endpoint, "SendFriendReq") == 0) {
			char* target =
				cJSON_GetStringValue(cJSON_GetObjectItem(PayloadParsed, "to"));
			if (!target) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}

			user search;
			search.con = *con;
			const user* usr = hashmap_get(UsersByFD, &search);
			if (!usr) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}

			char* targetid = (char*)GetUserIDFromName(target);
			if (!targetid) {
				InsertError(responsebuild, 10);
				goto finishresp;
			}

			if (strcmp(usr->id, targetid) == 0) {
				InsertError(responsebuild, 9);
			} else if (AreFriends(usr->id, targetid)) {
				InsertError(responsebuild, 8);
			} else {
				CreateFriendReq(usr->id, targetid);
				PushFQ(targetid, usr->id);
				InsertError(responsebuild, 0);
			}
			free(targetid);
		} else if (strcmp(endpoint, "AcceptFriendReq") == 0) {
			char* sender = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "user"));
			if (!sender) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user search;
			search.con = *con;
			const user* usr = hashmap_get(UsersByFD, &search);
			if (usr) {
				if (DestroyFriendReq(sender, usr->id)) {
					if (!AreFriends(sender, usr->id)) {
						CreateFriendship(sender, usr->id);
						PushNewFriend(sender, usr->id);
						PushNewFriend(usr->id, sender);
						InsertError(responsebuild, 0);
					} else {
						InsertError(responsebuild, 8);
					}
				} else {
					InsertError(responsebuild, 4);
				}
			}
		} else if (strcmp(endpoint, "DenyFriendReq") == 0) {
			char* sender = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "user"));
			if (!sender) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user search;
			search.con = *con;
			const user* usr = hashmap_get(UsersByFD, &search);
			if (usr) {
				if (!AreFriends(sender, usr->id)) {
					DestroyFriendReq(sender, usr->id);
					InsertError(responsebuild, 0);
				} else {
					InsertError(responsebuild, 8);
				}
			}
		} else if (strcmp(endpoint, "CreateSpaceInvite") == 0) {
			char* space = cJSON_GetStringValue(
				cJSON_GetObjectItem(PayloadParsed, "space"));
			if (!space) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			user search;
			search.con = *con;
			const user* usr = hashmap_get(UsersByFD, &search);
			if (usr) {
				if (IsInSpaceViaUserID(usr->id, space)) {
					int uses = cJSON_GetNumberValue(
						cJSON_GetObjectItem(PayloadParsed, "uses"));
					if (uses < 0 || uses > 320) {
						InsertError(responsebuild, 3);
						goto finishresp;
					}
					char* code = CreateSpaceInvite(space, uses);
					if (code) {
						cJSON_AddStringToObject(responsepayload, "invite_code",
												code);
					} else {
						InsertError(responsebuild, 4);
						goto finishresp;
					}
				}
			}
		} else if (strcmp(endpoint, "UpdateUserProfile") == 0) {
			user search = {0};
			search.con = *con;
			user* found = hashmap_get(UsersByFD, &search);
			if (!found) {
				InsertError(responsebuild, 1);
				goto finishresp;
			}
			user oldusr = *found;
			user newusr = oldusr;

			cJSON* profile = cJSON_GetObjectItem(PayloadParsed, "profile");
			if (!profile) {
				InsertError(responsebuild, 3);
				goto finishresp;
			}
			char* name =
				cJSON_GetStringValue(cJSON_GetObjectItem(profile, "name"));
			char* displayname = cJSON_GetStringValue(
				cJSON_GetObjectItem(profile, "display_name"));
			char* pfp =
				cJSON_GetStringValue(cJSON_GetObjectItem(profile, "pfp"));
			char* desc = cJSON_GetStringValue(
				cJSON_GetObjectItem(profile, "description"));

			if (displayname)
				newusr.displayname = displayname;
			if (pfp)
				newusr.pfp = pfp;
			if (desc)
				newusr.description = desc;

			if (!UpdateUserProfile(found->id, newusr)) {
				InsertError(responsebuild, 4);
				goto finishresp;
			}

			if (displayname)
				newusr.displayname = strdup(displayname);
			if (pfp)
				newusr.pfp = strdup(pfp);
			if (desc)
				newusr.description = strdup(desc);

			if (name && strcmp(name, oldusr.username) != 0)
				hashmap_delete(UsersByName, &oldusr);

			hashmap_set(UsersByFD, &newusr);
			hashmap_set(UsersByName, &newusr);
			hashmap_set(UsersByID, &newusr);

			if (displayname)
				free(oldusr.displayname);
			if (pfp)
				free(oldusr.pfp);
			if (desc)
				free(oldusr.description);

			int nids = 0;
			char** ids =
				CollectRelatedUserIDs(newusr.username, newusr.id, &nids);
			for (int i = 0; i < nids; i++)
				PushProfileUpdate(ids[i], newusr.id);
			FreeIDList(ids, nids);

			InsertError(responsebuild, 0);
		} else if (strcmp(endpoint, "UploadFile") == 0) {
			char id[17];
			GenerateID((char**)&id);
			cJSON_AddStringToObject(responsepayload, "upload_token", id);
			for (int i = 0; i < MAX_IPC_CLIENTS; i++) {
				cJSON* uploadwire = cJSON_CreateObject();
				cJSON_AddStringToObject(uploadwire, "endpoint",
										"NewUploadToken");
				cJSON* uploadpayload = cJSON_CreateObject();
				cJSON_AddStringToObject(uploadpayload, "token", id);
				cJSON_AddItemToObject(uploadwire, "payload", uploadpayload);
				char* finalpayload = cJSON_PrintUnformatted(uploadwire);
				uint32_t len = htonl(strlen(finalpayload));

				if (IPCSockets[i]) {
					write(IPCSockets[i], &len, 4);
					write(IPCSockets[i], finalpayload, strlen(finalpayload));
				}

				free(finalpayload);
				cJSON_Delete(uploadwire);
			}
		} else {
			// Invalid endpoint!?
			InsertError(responsebuild, 3);
		}
	} else {
		printf("no req november\n");
	}
finishresp:
	cJSON_Delete(PayloadParsed);
	cJSON_AddItemToObject(responsebuild, "response", responsepayload);
	char* resp = cJSON_PrintUnformatted(responsebuild);
	(*response) = resp;
	printf("%s\n", resp);
	cJSON_Delete(responsebuild);
	return 1;
}