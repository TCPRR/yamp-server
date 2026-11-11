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
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "handlers.h"

char* Base36(unsigned long num, char* buf) {
	const char* alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
	char* p = buf;
	char* start = buf;

	if (num == 0) {
		buf[0] = '0';
		buf[1] = '\0';
		return buf;
	}

	while (num > 0) {
		*p++ = alphabet[num % 36];
		num /= 36;
	}
	*p = '\0';

	p--;
	while (start < p) {
		char tmp = *start;
		*start = *p;
		*p = tmp;
		start++;
		p--;
	}

	return buf;
}
int64_t NowMs(void) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
int GenerateID_Inline(char* id) {
	static const char alphabet[] = "0123456789abcdefghijklmnopqrstuv";
	uint64_t t = (uint64_t)NowMs();

	for (int i = 8; i >= 0; i--) {
		id[i] = alphabet[t & 31];
		t >>= 5;
	}
	for (int pos = 9; pos < 12;) {
		unsigned char byte;
		if (RAND_bytes(&byte, 1) != 1)
			return 0;
		if (byte >= 224)
			continue;
		id[pos++] = alphabet[byte % 32];
	}
	id[12] = '\0';
	return 1;
}
int GenerateID(char** id) {
	if (!id)
		return 0;
	if (!*id) {
		*id = malloc(13);
	}
	int ok = GenerateID_Inline(*id);
	if (!ok) {
		free(*id);
	}
	return ok;
}

int GenerateToken_Inline(char* id) {
	static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";

	int pos = 0;

	while (pos < 256) {
		unsigned char byte;

		if (RAND_bytes(&byte, 1) != 1) {
			return 0;
		}

		if (byte >= 252)
			continue;

		(id)[pos++] = alphabet[byte % 36];
	}

	(id)[256] = '\0';

	return 1;
}

int GenerateUploadToken_Inline(char* id) {
	static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";

	int pos = 0;

	while (pos < 256) {
		unsigned char byte;

		if (RAND_bytes(&byte, 1) != 1) {
			return 0;
		}

		if (byte >= 252)
			continue;

		(id)[pos++] = alphabet[byte % 36];
	}

	(id)[256] = '\0';

	return 1;
}

cJSON* CreateStatusJSON(YampStatus* status) {
	cJSON* stat = cJSON_CreateObject();
	cJSON_AddStringToObject(stat, "status", status->status);
	cJSON_AddStringToObject(stat, "rpc_desc", status->RPCDesc);
	cJSON_AddStringToObject(stat, "rpc_icon", status->RPCIcon);
	cJSON_AddStringToObject(stat, "rpc_name", status->RPCName);
	return stat;
}
YampStatus* ParseStatusJSON(cJSON* status) {
	YampStatus* stat = malloc(sizeof(*stat));
	stat->status =
		dup0(cJSON_GetStringValue(cJSON_GetObjectItem(status, "status")));
	stat->RPCDesc =
		dup0(cJSON_GetStringValue(cJSON_GetObjectItem(status, "rpc_desc")));
	stat->RPCIcon =
		dup0(cJSON_GetStringValue(cJSON_GetObjectItem(status, "rpc_icon")));
	stat->RPCName =
		dup0(cJSON_GetStringValue(cJSON_GetObjectItem(status, "rpc_name")));
	return stat;
}
void FreeStatusFields(YampStatus* stat) {
	if (!stat) {
		return;
	}
	free(stat->status);
	free(stat->RPCDesc);
	free(stat->RPCIcon);
	free(stat->RPCName);
}
void FreeStatusObject(YampStatus* stat) {
	if (!stat) {
		return;
	}
	FreeStatusFields(stat);
	free(stat);
}
YampStatus* DupStatusObject(YampStatus* stat) {
	YampStatus* heapstat = malloc(sizeof(*heapstat));
	heapstat->status = dup0(stat->status);
	heapstat->RPCDesc = dup0(stat->RPCDesc);
	heapstat->RPCIcon = dup0(stat->RPCIcon);
	heapstat->RPCName = dup0(stat->RPCName);
	return heapstat;
}
// Handy filler if the users are not logged in
YampStatus* CreateOfflineStatus() {
	YampStatus* heapstat = malloc(sizeof(*heapstat));
	heapstat->status = strdup("offline");
	heapstat->RPCDesc = NULL;
	heapstat->RPCIcon = NULL;
	heapstat->RPCName = NULL;
	return heapstat;
}
// Handy filler when the user logs in now
YampStatus* CreateOnlineStatus() {
	YampStatus* heapstat = malloc(sizeof(*heapstat));
	heapstat->status = strdup("online");
	heapstat->RPCDesc = NULL;
	heapstat->RPCIcon = NULL;
	heapstat->RPCName = NULL;
	return heapstat;
}
cJSON* CreateUserJSON(YampUser* user) {
	cJSON* obj = cJSON_CreateObject();

	cJSON_AddStringToObject(obj, "id", user->id);
	cJSON_AddStringToObject(obj, "name", user->username);
	cJSON_AddStringToObject(obj, "display_name", user->displayname);
	cJSON_AddStringToObject(obj, "description", user->description);
	cJSON_AddStringToObject(obj, "avatar", user->pfp);

	cJSON* status_obj = CreateStatusJSON(user->status);
	cJSON_AddItemToObject(obj, "status", status_obj);

	return obj;
}

void FreeUserFields(YampUser* u) {
	free(u->username);
	free(u->displayname);
	free(u->pfp);
	free(u->description);
	FreeStatusObject(u->status);
}
void FreeUserObject(YampUser* u) {
	if (!u)
		return;
	FreeUserFields(u);
	free(u);
}

YampUser* DupUserObject(YampUser* usr) {
	YampUser* heapusr = malloc(sizeof(*heapusr));
	*heapusr = *usr;
	heapusr->username = dup0(usr->username);
	heapusr->displayname = dup0(usr->displayname);
	heapusr->description = dup0(usr->description);
	heapusr->pfp = dup0(usr->pfp);

	heapusr->status = DupStatusObject(usr->status);
	return heapusr;
}
/*******************************************************************************
 * Note: Sessions are not filled in, as theres not really any lookup code here,
 * be aware for networking-side code
 * @param rawusr The raw cJSON YAMP user
 * @return the final user object
 *******************************************************************************/
YampUser* ParseUserJSON(cJSON* rawusr) {
	YampUser usr;
	strncpy(usr.id, cJSON_GetObjectItem(rawusr, "id")->valuestring, 17);
	usr.username = (cJSON_GetObjectItem(rawusr, "name")->valuestring);
	cJSON* rawdisp = cJSON_GetObjectItem(rawusr, "display_name");
	if (rawdisp) {
		usr.displayname = (rawdisp->valuestring);
	} else {
		usr.displayname = NULL;
	}
	cJSON* rawdesc = cJSON_GetObjectItem(rawusr, "description");
	if (rawdesc) {
		usr.description = (rawdesc->valuestring);
	} else {
		usr.description = NULL;
	}
	cJSON* rawpfp = cJSON_GetObjectItem(rawusr, "avatar");
	if (rawpfp) {
		usr.pfp = (rawpfp->valuestring);
	} else {
		usr.pfp = NULL;
	}
	cJSON* rawstatus = cJSON_GetObjectItem(rawusr, "status");
	usr.status = NULL;
	if (rawstatus) {
		usr.status = ParseStatusJSON(rawstatus);
	} else {
		// Populate if the user was found
		YampUser* usr_stat = hashmap_get(UsersByID, &usr);
		if (usr_stat) {
			usr.status = usr_stat->status;
		} else {
			usr.status = CreateOfflineStatus(); // filler
		}
	}

	return DupUserObject(&usr);
}

/*********************************************************
  * RegisterUserAccount
  * Registers an user account

  * @return the registered user ID (HEAP! FREE THIS AS THE CALLER)
*********************************************************/
char* RegisterUserAccount(char* email, char* name, char* passwd) {
	const char* sql = "INSERT INTO users (name, display_name, password, id, "
					  "email) VALUES (?,?,?,?,?)";

	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	char passwdh[65];
	char* id = NULL;

	sha256_hex(passwd, passwdh);

	if (!GenerateID(&id)) {
		sqlite3_finalize(stmt);
		return 0;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, passwdh, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 5, email, -1, SQLITE_STATIC);

	int ok = sqlite3_step(stmt) == SQLITE_DONE;

	sqlite3_finalize(stmt);

	return ok ? id : 0;
}
int UpdateUserProfile(char* id, YampUser newprofile) {
	const char* sql =
		"UPDATE users SET display_name=?,pfp=?,description=? WHERE id=?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, newprofile.displayname, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, newprofile.pfp, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, newprofile.description, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 4, id, -1, SQLITE_TRANSIENT);
	int ok = sqlite3_step(stmt) == SQLITE_DONE;

	sqlite3_finalize(stmt);

	return ok;
}
char* GetSpaceIDFromName(char* name) {
	const char* sql = "SELECT id FROM spaces WHERE name = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		return strdup(sqlite3_column_text(stmt, 0));
	}
	sqlite3_finalize(stmt);
	return NULL;
}
char* GetUserIDFromName(char* name) {
	const char* sql = "SELECT id FROM users WHERE name = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		return strdup(sqlite3_column_text(stmt, 0));
	}
	sqlite3_finalize(stmt);
	return NULL;
}
int CreateSpaceObjectFromName(char* name, cJSON** output) {
	const char* sql = "SELECT id, display_name FROM spaces WHERE id "
					  "= ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		*output = cJSON_CreateObject();
		cJSON_AddStringToObject(*output, "name", name);
		cJSON_AddStringToObject(*output, "id",
								(char*)sqlite3_column_text(stmt, 0));
		cJSON_AddStringToObject(*output, "display_name",
								(char*)sqlite3_column_text(stmt, 1));
		sqlite3_finalize(stmt);
		return 1;
	} else {
		sqlite3_finalize(stmt);
		return 0;
	}
	sqlite3_finalize(stmt);

	return 1;
}
int CreateSpaceObjectFromID(char* id, cJSON** output) {
	const char* sql = "SELECT name, display_name FROM spaces WHERE id "
					  "= ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		*output = cJSON_CreateObject();
		cJSON_AddStringToObject(*output, "id", id);
		cJSON_AddStringToObject(*output, "name",
								(char*)sqlite3_column_text(stmt, 0));
		cJSON_AddStringToObject(*output, "display_name",
								(char*)sqlite3_column_text(stmt, 1));
		sqlite3_finalize(stmt);
		return 1;
	} else {
		sqlite3_finalize(stmt);
		return 0;
	}
	sqlite3_finalize(stmt);

	return 1;
}
int CreateUserObjectFromID(const char* id, YampUser** output) {
	const char* sql = "SELECT name, display_name, pfp, description "
					  "FROM users WHERE id = ?";

	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return 0;
	}

	*output = malloc(sizeof(YampUser));
	**output = (YampUser){0};

	strncpy((*output)->id, id, sizeof((*output)->id) - 1);

	(*output)->username = dup0(sqlite3_column_text(stmt, 0));
	(*output)->displayname = dup0(sqlite3_column_text(stmt, 1));
	(*output)->pfp = dup0(sqlite3_column_text(stmt, 2));
	(*output)->description = dup0(sqlite3_column_text(stmt, 3));

	sqlite3_finalize(stmt);

	const YampUser* usr = hashmap_get(UsersByID, *output);

	if (usr && usr->status && strcmp(usr->status->status, "offline") != 0) {
		(*output)->status = DupStatusObject(usr->status);
	} else {
		(*output)->status = CreateOfflineStatus();
	}

	return 1;
}

int CreateUserJSONFromID(const char* id, cJSON** output) {
	YampUser* u;
	if (!CreateUserObjectFromID(id, &u))
		return 0;
	*output = CreateUserJSON(u);
	FreeUserObject(u);
	return 1;
}

int CreateUserJSONFromUsername(const char* name, cJSON** output) {
	char* id = GetUserIDFromName(name);
	if (!id)
		return 0;
	int ok = CreateUserJSONFromID(id, output);
	free(id);
	return ok;
}
char* CreateSpaceInvite(const char* space_id, int uses) {
	static const char A[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	uint64_t v;
	if (RAND_bytes((unsigned char*)&v, sizeof v) != 1)
		return NULL;
	v %= 2821109907456ULL; // ultra massive fucking number to make it even more
						   // random
	char code[9];
	for (int i = 7; i >= 0; i--) {
		code[i] = A[v % 36];
		v /= 36;
	}
	code[8] = '\0';

	const char* sql =
		"INSERT INTO spaceinvite (space, uses, code) VALUES (?,?,?)";
	sqlite3_stmt* stmt;
	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;
	sqlite3_bind_text(stmt, 1, space_id, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, uses);
	sqlite3_bind_text(stmt, 3, code, -1, SQLITE_STATIC);
	int ok = sqlite3_step(stmt) == SQLITE_DONE;
	sqlite3_finalize(stmt);
	return ok ? strdup(code) : NULL;
}
cJSON* GetSpaceDetailsFromInvite(const char* invite) {
	const char* sql = "SELECT space FROM spaceinvite WHERE code = ?";
	sqlite3_stmt* stmt;
	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return NULL;
	sqlite3_bind_text(stmt, 1, invite, -1, SQLITE_STATIC);

	cJSON* space = NULL;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		CreateSpaceObjectFromID((const char*)sqlite3_column_text(stmt, 0),
								&space);
	}
	sqlite3_finalize(stmt);
	return space;
}
int AreFriends(const char* user1, const char* user2) {
	const char* sql = "SELECT 1 FROM friendship "
					  "WHERE (sender = ? AND accepter = ?) "
					  "   OR (accepter = ? AND sender = ?) "
					  "LIMIT 1";

	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, user1, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, user2, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, user2, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, user1, -1, SQLITE_STATIC);

	int friends = sqlite3_step(stmt) == SQLITE_ROW;

	sqlite3_finalize(stmt);
	return friends;
}
int IsUserNameExisting(const char* user) {
	const char* sql = "SELECT 1 FROM users "
					  "WHERE name = ?";

	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);

	int real = sqlite3_step(stmt) == SQLITE_ROW;

	sqlite3_finalize(stmt);
	return real;
}
int IsSpaceNameExisting(const char* space) {
	const char* sql = "SELECT 1 FROM spaces "
					  "WHERE name = ?";

	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, space, -1, SQLITE_STATIC);

	int real = sqlite3_step(stmt) == SQLITE_ROW;

	sqlite3_finalize(stmt);
	return real;
}
int CreateFriendsListFromUserID(const char* id, cJSON** output) {
	const char* sql = "SELECT sender, accepter FROM friendship WHERE sender "
					  "= ? OR accepter = ?";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, id, -1, SQLITE_STATIC);

	cJSON* array = cJSON_CreateArray();
	while (sqlite3_step(stmt) == SQLITE_ROW) {

		char* p1 = sqlite3_column_text(stmt, 0);
		char* p2 = sqlite3_column_text(stmt, 1);
		char* friend;
		if (strcmp(p1, id) != 0) {
			friend = p1;
		} else if (strcmp(p2, id) != 0) {
			friend = p2;
		} else {
			return 0;
		}
		cJSON* userObj;
		if (CreateUserJSONFromID(friend, &userObj)) {
			cJSON_AddItemToArray(array, userObj);
		}
	}
	sqlite3_finalize(stmt);
	*output = array;
	return 1;
}
static cJSON* CreateMembersArray(cJSON* obj, YampUser* const* people, int n) {
	cJSON* arr = cJSON_AddArrayToObject(obj, "members");
	if (!arr)
		return NULL;

	for (int i = 0; i < n; i++) {
		cJSON* u = CreateUserJSON(people[i]);
		if (!u || !cJSON_AddItemToArray(arr, u)) {
			cJSON_Delete(u);
			return NULL;
		}
	}
	return arr;
}

cJSON* CreateConvObject(const YampChannel* conv) {
	YampUser* const* people = (YampUser* const*)(conv + 1);
	char addr_id[2 * 16 + 2];
	int n;

	switch (conv->type) {
	case YAMP_DM:
		if (conv->npeople != 2)
			return NULL;
		n = 2;
		{
			const char* a = people[0]->id;
			const char* b = people[1]->id;
			if (strncmp(a, b, 16) > 0) {
				const char* t = a;
				a = b;
				b = t;
			}
			snprintf(addr_id, sizeof addr_id, "%s|%s", a, b);
		}
		break;
	case YAMP_GC:
		n = conv->npeople;
		snprintf(addr_id, sizeof addr_id, "&%s", conv->id);
		break;
	default:
		return NULL;
	}
	cJSON* obj = cJSON_CreateObject();
	if (!obj)
		return NULL;

	if (conv->name) {
		cJSON_AddStringToObject(obj, "name", conv->name);
	}

	if (!cJSON_AddStringToObject(obj, "id", addr_id) ||
		!cJSON_AddNumberToObject(obj, "type", conv->type) ||
		!CreateMembersArray(obj, people, n)) {
		cJSON_Delete(obj);
		return NULL;
	}
	return obj;
}
int CreateConvListFromUserID(const char* id, cJSON** output) {
	static const char* dm_sql = "SELECT starter, recipient FROM dm "
								"WHERE starter = ?1 OR recipient = ?1";
	static const char* gc_sql =
		"SELECT \"gc-id\" FROM \"user-gc\" WHERE \"user-id\" = ?1";
	static const char* mem_sql =
		"SELECT \"user-id\" FROM \"user-gc\" WHERE \"gc-id\" = ?1";

	cJSON* array = cJSON_CreateArray();
	if (!array)
		return 0;

	sqlite3_stmt *st = NULL, *ms = NULL;
	YampChannel* conv = NULL;
	int rc;

	// dms always have 2 people so we can just use that fixed
	conv = calloc(1, sizeof *conv + 2 * sizeof(YampUser*));
	if (!conv)
		goto fail;
	YampUser** dm_people = (YampUser**)(conv + 1);

	if (sqlite3_prepare_v2(DB, dm_sql, -1, &st, NULL) != SQLITE_OK)
		goto fail;
	sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);

	while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
		const char* a = (const char*)sqlite3_column_text(st, 0);
		const char* b = (const char*)sqlite3_column_text(st, 1);
		if (!a || !b)
			continue;

		conv->type = YAMP_DM;
		conv->npeople = 2;

		memset(dm_people, 0, 2 * sizeof(YampUser*));
		if (CreateUserObjectFromID(a, &dm_people[0]) &&
			CreateUserObjectFromID(b, &dm_people[1])) {
			cJSON* obj = CreateConvObject(conv);
			if (obj && !cJSON_AddItemToArray(array, obj))
				cJSON_Delete(obj);
		}
		FreeUserObject(dm_people[0]);
		FreeUserObject(dm_people[1]);
	}
	if (rc != SQLITE_DONE)
		goto fail;
	sqlite3_finalize(st);
	st = NULL;
	free(conv);
	conv = NULL;

	if (sqlite3_prepare_v2(DB, gc_sql, -1, &st, NULL) != SQLITE_OK)
		goto fail;
	sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);

	while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
		const char* gid = (const char*)sqlite3_column_text(st, 0);
		if (!gid)
			continue;

		size_t cap = 8;
		conv = calloc(1, sizeof *conv + cap * sizeof(YampUser*));
		if (!conv)
			goto fail;
		conv->type = YAMP_GC;
		snprintf(conv->id, sizeof conv->id, "%s", gid);

		if (sqlite3_prepare_v2(DB, mem_sql, -1, &ms, NULL) != SQLITE_OK)
			goto fail;
		sqlite3_bind_text(ms, 1, gid, -1, SQLITE_STATIC);

		int n = 0, mrc;
		while ((mrc = sqlite3_step(ms)) == SQLITE_ROW) {
			const char* uid = (const char*)sqlite3_column_text(ms, 0);
			if (!uid)
				continue;

			if ((size_t)n == cap) {
				cap *= 2;
				YampChannel* grown =
					realloc(conv, sizeof *conv + cap * sizeof(YampUser*));
				if (!grown)
					goto fail;
				conv = grown;
			}
			YampUser** people = (YampUser**)(conv + 1);
			if (CreateUserObjectFromID(uid, &people[n]))
				conv->npeople = ++n;
		}
		sqlite3_finalize(ms);
		ms = NULL;
		if (mrc != SQLITE_DONE)
			goto fail;

		conv->npeople = n;
		cJSON* obj = CreateConvObject(conv);
		if (obj && !cJSON_AddItemToArray(array, obj))
			cJSON_Delete(obj);

		FreeYampChannel(conv);
		conv = NULL;
	}
	if (rc != SQLITE_DONE)
		goto fail;

	sqlite3_finalize(st);
	*output = array;
	return 1;

fail:
	fprintf(stderr, "CreateConvListFromUserID failed with this db err %s\n",
			sqlite3_errmsg(DB));
	sqlite3_finalize(ms);
	sqlite3_finalize(st);
	free(conv);
	cJSON_Delete(array);
	return 0;
}
int CreateSpacesListFromID(const char* name, cJSON** output) {

	const char* sql =
		"SELECT \"space-id\" FROM \"user-space\" WHERE \"user-id\" = ?";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);

	cJSON* array = cJSON_CreateArray();
	for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW;
		 rc = sqlite3_step(stmt)) {
		cJSON* userObj;
		if (CreateSpaceObjectFromID((char*)sqlite3_column_text(stmt, 0),
									&userObj)) {
			cJSON_AddItemToArray(array, userObj);
		}
	}

	sqlite3_finalize(stmt);

	*output = array;
	return 1;
}
int CreateSpacesListFromUsername(const char* name, cJSON** output) {
	char* id = GetUserIDFromName(name);
	if (!id) {
		return 0;
	}
	return CreateSpacesListFromID(id, output);
}

typedef struct {
	char* id;
	char* name;
	char* parent;
	cJSON* item;
} ChannelRow;
static ChannelRow* FindRowByID(ChannelRow* rows, size_t count, const char* id) {
	for (size_t i = 0; i < count; i++) {
		if (rows[i].id && strcmp(rows[i].id, id) == 0) {
			return &rows[i];
		}
	}
	return NULL;
}

int CreateChannelsListFromName(const char* name, cJSON** output) {
	const char* sql = "SELECT pos, name, type, parent, id FROM channels WHERE "
					  "space = ? ORDER BY pos ASC";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return 0;
	}

	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

	ChannelRow* rows = NULL;
	int count = 0, capacity = 0;

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* cname = (const char*)sqlite3_column_text(stmt, 1);
		const char* cparent = (const char*)sqlite3_column_text(stmt, 3);
		const char* cid = (const char*)sqlite3_column_text(stmt, 4);

		cJSON* item = cJSON_CreateObject();
		cJSON_AddNumberToObject(item, "position", sqlite3_column_int(stmt, 0));
		cJSON_AddStringToObject(item, "name", cname ? cname : "");
		cJSON_AddStringToObject(item, "id", cid ? cid : "");
		cJSON_AddNumberToObject(item, "type", sqlite3_column_int(stmt, 2));
		if (cparent) {
			cJSON_AddStringToObject(item, "parent", cparent);
		} else {
			cJSON_AddNullToObject(item, "parent");
		}
		cJSON_AddItemToObject(item, "children", cJSON_CreateArray());

		if (count == capacity) {
			capacity = capacity ? capacity * 2 : 16;
			ChannelRow* grown = realloc(rows, capacity * sizeof(ChannelRow));
			if (!grown) {
				sqlite3_finalize(stmt);
				return 0;
			}
			rows = grown;
		}
		rows[count].name = cname ? strdup(cname) : NULL;
		rows[count].id = cid ? strdup(cid) : NULL;
		rows[count].parent = cparent ? strdup(cparent) : NULL;
		rows[count].item = item;
		count++;
	}
	sqlite3_finalize(stmt);

	cJSON* root = cJSON_CreateArray();
	for (size_t i = 0; i < count; i++) {
		cJSON* item = rows[i].item;
		ChannelRow* parentRow =
			rows[i].parent ? FindRowByID(rows, count, rows[i].parent) : NULL;

		if (parentRow) {
			cJSON* children =
				cJSON_GetObjectItemCaseSensitive(parentRow->item, "children");
			cJSON_AddItemToArray(children, item);
		} else {
			cJSON_AddItemToArray(root, item);
		}
	}

	for (size_t i = 0; i < count; i++) {
		free(rows[i].id);
		free(rows[i].name);
		free(rows[i].parent);
	}
	free(rows);

	*output = root;
	return 1;
}

int CreateUserSelfJSONFromID(char* name, cJSON** output) {
	CreateUserJSONFromID(name, output);
	return 1;
}
int CreateUserSelfJSONFromUsername(char* name, cJSON** output) {
	char* id = GetUserIDFromName(name);
	if (!id) {
		return 0;
	}
	CreateUserSelfJSONFromID(id, output);
	free(id);
	return 1;
}

cJSON* ListSpaceMembersJSONFromID(char* id) {
	const char* sql =
		"SELECT \"user-id\" FROM \"user-space\" WHERE \"space-id\" = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

	cJSON* members = cJSON_CreateArray();

	for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW;
		 rc = sqlite3_step(stmt)) {
		cJSON* tmp;
		CreateUserJSONFromID(sqlite3_column_text(stmt, 0), &tmp);
		cJSON_AddItemToArray(members, tmp);
	}

	sqlite3_finalize(stmt);
	return members;
}
int CanAccessChat(const YampUser* usr, char* id) {
	chat cchat;
	int ok = YAMPProcessWhere(id, usr->id, &cchat);
	if (!ok) {
		return 0;
	}
	switch (cchat.type) {
	case YAMP_SPACE_TEXT: {
		return IsInSpaceViaUserID(usr->id, GetSpaceFromChannelID(id));
	}
	case YAMP_GC:
		return IsInGC(usr->id, cchat.GC_ID);
	case YAMP_DM:
		return 1; // its validified in YAMPProcessWhere
	default:
		return 0;
	}
}
int ListSpaceMembersObjectsFromID(char* id, YampUser*** out) {
	const char* sql =
		"SELECT \"user-id\" FROM \"user-space\" WHERE \"space-id\" = ?";
	sqlite3_stmt* stmt;
	*out = NULL;
	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

	int n = 0, cap = 0;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* uid = (const char*)sqlite3_column_text(stmt, 0);
		if (!uid)
			continue;
		if (n == cap) {
			cap = cap ? cap * 2 : 8;
			YampUser** g = realloc(*out, cap * sizeof(YampUser*));
			if (!g) {
				for (int i = 0; i < n; i++)
					FreeUserFields((*out)[i]);
				free(*out);
				*out = NULL;
				sqlite3_finalize(stmt);
				return 0;
			}
			*out = g;
		}
		if (CreateUserObjectFromID(uid, &(*out)[n]))
			n++;
	}
	sqlite3_finalize(stmt);
	return n;
}
char* GetSpaceFromChannelID(char* channel_id) {
	const char* sql = "SELECT \"space\" FROM \"channels\" WHERE "
					  "\"id\" = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, channel_id, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		char* str = strdup(sqlite3_column_text(stmt, 0));
		sqlite3_finalize(stmt);
		return str;
	}
	sqlite3_finalize(stmt);
	return NULL;
}
int JoinSpaceViaInvite(const char* user_id, const char* code,
					   char** space_out) {
	*space_out = NULL;
	char* space_id = NULL;
	sqlite3_stmt* stmt = NULL;
	int uses = 0;
	int err = 4;

	if (sqlite3_exec(DB, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
		return 4;

	if (sqlite3_prepare_v2(DB,
						   "SELECT space, uses FROM spaceinvite WHERE code = ?",
						   -1, &stmt, NULL) != SQLITE_OK)
		goto fail;
	sqlite3_bind_text(stmt, 1, code, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		err = 10;
		goto fail;
	}
	space_id = strdup((const char*)sqlite3_column_text(stmt, 0));
	uses = sqlite3_column_int(stmt, 1);
	sqlite3_finalize(stmt);
	stmt = NULL;
	if (!space_id)
		goto fail;

	if (IsInSpaceViaUserID((char*)user_id, space_id)) {
		err = 14;
		goto fail;
	}

	const char* msql =
		"INSERT INTO \"user-space\" (\"user-id\", \"space-id\", \"pos\") "
		"VALUES (?1, ?2, COALESCE((SELECT MAX(\"pos\") + 1 FROM "
		"\"user-space\" WHERE \"user-id\" = ?1), 0))";
	if (sqlite3_prepare_v2(DB, msql, -1, &stmt, NULL) != SQLITE_OK)
		goto fail;
	sqlite3_bind_text(stmt, 1, user_id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, space_id, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = NULL;
	if (rc != SQLITE_DONE)
		goto fail;

	if (uses > 0) {
		const char* usql =
			uses == 1 ? "DELETE FROM spaceinvite WHERE code = ?"
					  : "UPDATE spaceinvite SET uses = uses - 1 WHERE code = ?";
		if (sqlite3_prepare_v2(DB, usql, -1, &stmt, NULL) != SQLITE_OK)
			goto fail;
		sqlite3_bind_text(stmt, 1, code, -1, SQLITE_STATIC);
		rc = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;
		if (rc != SQLITE_DONE)
			goto fail;
	}

	if (sqlite3_exec(DB, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
		goto fail;
	*space_out = space_id;
	return 0;

fail:
	sqlite3_exec(DB, "ROLLBACK", NULL, NULL, NULL);
	free(space_id);
	return err;
}

int IsInSpaceViaUserID(char* userid, char* spaceid) {
	if (!(userid && spaceid)) {
		return 0; // It can be paired with GetSpaceFromChannelID without checks
				  // thanks to this
	}
	const char* sql = "SELECT 1 FROM \"user-space\" WHERE "
					  "\"space-id\" = ? AND \"user-id\" = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, spaceid, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, userid, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return 1;
	}
	sqlite3_finalize(stmt);
	return 0;
}
YampMessage* AllocMessageType(YampMessage msg) {
	YampMessage* heapmsg = malloc(sizeof(YampMessage));
	*heapmsg = msg;
	heapmsg->type = msg.type;
	heapmsg->content = dup0(msg.content);
	return heapmsg;
}
YampAttachment* DupAttachmentObject(YampAttachment* attachment) {
	YampAttachment* ret = malloc(sizeof(*ret));
	*ret = *attachment;
	ret->url = dup0(attachment->url);
	ret->mime = dup0(attachment->mime);
	ret->filename = dup0(attachment->filename);
	return ret;
}
int ListAttachmentObjectsForID(char* msg_id, YampAttachment*** out) {
	const char* sql = "SELECT url,mime,filename FROM attachments WHERE "
					  "\"msg-id\"=? ORDER BY idx";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, msg_id, -1, SQLITE_STATIC);

	YampAttachment** attachements = NULL;
	int nAttachements = 0;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		attachements = realloc(attachements,
							   sizeof(YampAttachment*) * (nAttachements + 1));
		YampAttachment attachement;
		attachement.url = (sqlite3_column_text(stmt, 0));
		attachement.mime = (sqlite3_column_text(stmt, 1));
		attachement.filename =
			(sqlite3_column_text(stmt, 2) ? sqlite3_column_text(stmt, 2)
										  : sqlite3_column_text(stmt, 0));
		attachements[nAttachements] = DupAttachmentObject(&attachement);
		nAttachements++;
	}
	sqlite3_finalize(stmt);
	*out = attachements;
	return nAttachements;
}
cJSON* CreateAttachmentJSON(YampAttachment* attachment) {
	cJSON* obj = cJSON_CreateObject();
	cJSON_AddStringToObject(obj, "url", attachment->url);
	cJSON_AddStringToObject(obj, "mime", attachment->mime);
	cJSON_AddStringToObject(obj, "filename", attachment->filename);
	return obj; // very meowsome
}
void FreeAttachmentTypeFields(YampAttachment* attach) {
	free(attach->url);
	free(attach->mime);
	free(attach->filename);
}
void FreeAttachmentObject(YampAttachment* attach) {
	FreeAttachmentTypeFields(attach);
	free(attach);
}
YampAttachment* ParseAttachmentJSON(cJSON* json) {
	const char* mime = cJSON_GetStringValue(cJSON_GetObjectItem(json, "mime"));
	const char* url = cJSON_GetStringValue(cJSON_GetObjectItem(json, "url"));
	const char* filename =
		cJSON_GetStringValue(cJSON_GetObjectItem(json, "filename"));
	if (!filename) {
		filename = url;
	}
	if (!mime || !url)
		return NULL;
	YampAttachment tmp = {
		.mime = (char*)mime, .url = (char*)url, .filename = (char*)filename};
	return DupAttachmentObject(&tmp);
}
cJSON* ListAttachmentsJSON(char* msg_id) {
	YampAttachment** list;
	int nlist = ListAttachmentObjectsForID(msg_id, &list);
	cJSON* arr = cJSON_CreateArray();
	for (int i = 0; i < nlist; i++) {
		cJSON_AddItemToArray(arr, CreateAttachmentJSON(list[i]));
		FreeAttachmentObject(list[i]);
	}
	free(list);
	return arr;
}
int InsertAttachmentForMessageID(char* msg_id, YampAttachment* att) {
	const char* sql =
		"INSERT INTO attachments(\"msg-id\",url,idx,mime,filename) "
		"VALUES(?1,?2,(SELECT COALESCE(MAX(idx)+1,0) FROM "
		"attachments WHERE \"msg-id\"=?1),?3, ?4) "
		"RETURNING idx";
	sqlite3_stmt* stmt;
	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;

	sqlite3_bind_text(stmt, 1, msg_id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, att->url, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, att->mime, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, att->filename, -1, SQLITE_STATIC);

	int idx = -1;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		idx = sqlite3_column_int(stmt, 0);
		if (sqlite3_step(stmt) != SQLITE_DONE)
			idx = -1;
	}
	sqlite3_finalize(stmt);
	return idx;
}
int InsertReactionForMessageID(const char* msg_id, const char* user_id,
							   const char* codepoint) {
	if (!msg_id || !user_id || !codepoint)
		return -1;
	size_t cl = strlen(codepoint);
	if (cl == 0 || cl > 64)
		return -1;

	const char* sql =
		"INSERT OR IGNORE INTO reactions(\"msg-id\",idx,\"user-id\",codepoint) "
		"VALUES(?1,(SELECT COALESCE(MAX(idx)+1,0) FROM reactions "
		"WHERE \"msg-id\"=?1),?2,?3) RETURNING idx";
	sqlite3_stmt* stmt;
	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(stmt, 1, msg_id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, user_id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, codepoint, -1, SQLITE_STATIC);

	int idx = -1;
	if (sqlite3_step(stmt) ==
		SQLITE_ROW) { // an ignored duplicate returns no row
		idx = sqlite3_column_int(stmt, 0);
		if (sqlite3_step(stmt) != SQLITE_DONE)
			idx = -1;
	}
	sqlite3_finalize(stmt);
	return idx;
}

int RemoveReaction(const char* msg_id, const char* user_id,
				   const char* codepoint) {
	const char* sql = "DELETE FROM reactions WHERE \"msg-id\"=? AND "
					  "\"user-id\"=? AND codepoint=?";
	sqlite3_stmt* stmt;
	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_text(stmt, 1, msg_id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, user_id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, codepoint, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	int removed = (rc == SQLITE_DONE) ? sqlite3_changes(DB) : 0;
	sqlite3_finalize(stmt);
	return removed > 0;
}

void DeleteReactionsForMessageID(const char* msg_id) {
	sqlite3_stmt* stmt;
	if (sqlite3_prepare_v2(DB, "DELETE FROM reactions WHERE \"msg-id\"=?", -1,
						   &stmt, NULL) != SQLITE_OK)
		return;
	sqlite3_bind_text(stmt, 1, msg_id, -1, SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
void FreeReactionObject(YampReaction* r) {
	if (!r)
		return;
	FreeUserObject(r->user);
	free(r->codepoint);
	free(r);
}
void FreeReactionArray(YampReaction** arr, int n) {
	for (int i = 0; i < n; i++)
		FreeReactionObject(arr[i]);
	free(arr);
}

int ListReactionObjectsForID(const char* msg_id, YampReaction*** out) {
	const char* sql = "SELECT \"user-id\",codepoint FROM reactions "
					  "WHERE \"msg-id\"=? ORDER BY idx";
	sqlite3_stmt* stmt;
	*out = NULL;
	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_text(stmt, 1, msg_id, -1, SQLITE_STATIC);

	YampReaction** arr = NULL;
	int n = 0, cap = 0;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* uid = (const char*)sqlite3_column_text(stmt, 0);
		const char* cp = (const char*)sqlite3_column_text(stmt, 1);
		if (!uid || !cp)
			continue;

		if (n == cap) {
			cap = cap ? cap * 2 : 8;
			YampReaction** g = realloc(arr, cap * sizeof *arr);
			if (!g) {
				FreeReactionArray(arr, n);
				sqlite3_finalize(stmt);
				return 0;
			}
			arr = g;
		}
		YampReaction* r = calloc(1, sizeof *r);
		if (!r) {
			free(r);
			FreeReactionArray(arr, n);
			sqlite3_finalize(stmt);
			return 0;
		}
		snprintf(r->msg_id, sizeof r->msg_id, "%s", msg_id);
		CreateUserObjectFromID(uid, &r->user);
		r->codepoint = strdup(cp);
		arr[n++] = r;
	}
	sqlite3_finalize(stmt);
	*out = arr;
	return n;
}

cJSON* CreateReactionJSON(const YampReaction* r) {
	cJSON* obj = cJSON_CreateObject();
	if (!obj)
		return NULL;
	cJSON_AddStringToObject(obj, "user_id", r->user->id);
	cJSON_AddStringToObject(obj, "codepoint", r->codepoint);
	return obj;
}

void FreeMessageFields(YampMessage* msg) {
	if (!msg)
		return;
	free(msg->content);
	msg->content = NULL;
	if (msg->reply) {
		FreeMessageObject(msg->reply);
		msg->reply = NULL;
	}
	for (int i = 0; i < msg->nAttachments; i++) {
		FreeAttachmentTypeFields(msg->attachments[i]);
		free(msg->attachments[i]);
	}
	free(msg->attachments);
	msg->attachments = NULL;
	msg->nAttachments = 0;
}

void FreeMessageObject(YampMessage* msg) {
	if (!msg)
		return;
	FreeMessageFields(msg);
	free(msg);
}
YampMessage* CreateMessageTypeFromID(char* id) {
	if (id == NULL) {
		return NULL;
	}
	const char* sql =
		"SELECT "
		"\"author\",\"content\",\"id\",\"type\",\"reply\",\"timestamp\","
		"\"channel\" FROM \"messages\" WHERE \"id\" = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		YampMessage msg = {0};
		CreateUserObjectFromID(sqlite3_column_text(stmt, 0), &msg.author);
		msg.content = sqlite3_column_text(stmt, 1);
		strcpy(msg.id, sqlite3_column_text(stmt, 2));
		msg.type = sqlite3_column_int(stmt, 3);
		msg.reply = CreateMessageTypeFromID(sqlite3_column_text(stmt, 4));
		msg.timestamp = sqlite3_column_int(stmt, 5);
		YampAttachment** attachments;
		int nAttachments = ListAttachmentObjectsForID(id, &attachments);
		msg.attachments = attachments;
		msg.nAttachments = nAttachments;
		strcpy(msg.channel, sqlite3_column_text(stmt, 6));
		YampMessage* heapmsg = AllocMessageType(msg);
		sqlite3_finalize(stmt);
		return heapmsg;
	} else {
		sqlite3_finalize(stmt);
	}
	return NULL;
}
int DeleteMessage(char* id) {
	if (id == NULL) {
		return 0;
	}
	const char* sql = "DELETE FROM \"messages\" WHERE \"id\" = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return 1;
	} else {
		sqlite3_finalize(stmt);
	}
	return 0;
}
cJSON* CreateMessageObject(YampMessage* msg) {
	cJSON* object = cJSON_CreateObject();
	cJSON* author = CreateUserJSON(msg->author);
	cJSON_AddItemToObject(object, "author", author);
	cJSON_AddStringToObject(object, "content", msg->content);
	cJSON_AddStringToObject(object, "channel", msg->channel);
	if (msg->reply) {
		cJSON_AddItemToObject(object, "reply", CreateMessageObject(msg->reply));
	}
	cJSON_AddStringToObject(object, "id", msg->id);
	cJSON_AddNumberToObject(object, "timestamp", msg->timestamp);
	cJSON_AddNumberToObject(object, "type", msg->type);
	if (msg->attachments && msg->nAttachments) {
		cJSON_AddItemToObject(object, "attachments",
							  ListAttachmentsJSON(msg->id));
	}
	return object;
}
void InsertMessage(YampMessage* msg) {
	const char* sql = "INSERT INTO \"messages\" "
					  "(\"author\",\"content\",\"id\",\"type\",\"reply\","
					  "\"timestamp\",\"channel\") VALUES (?, ?, ?, ?, ?, ?, ?)";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, msg->author->id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, msg->content, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, msg->id, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 4, msg->type);
	if (msg->reply) {
		sqlite3_bind_text(stmt, 5, msg->reply->id, -1, SQLITE_STATIC);
	} else {
		sqlite3_bind_null(stmt, 5);
	}
	sqlite3_bind_int(stmt, 6, msg->timestamp);
	sqlite3_bind_text(stmt, 7, msg->channel, -1, SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if (msg->attachments && msg->nAttachments) {
		for (int i = 0; i < msg->nAttachments; i++) {
			InsertAttachmentForMessageID(msg->id, msg->attachments[i]);
		}
	}
}
YampChannel CreateDM(char* starter, char* recipient) {
	const char* sql =
		"INSERT INTO \"dm\" (\"starter\", \"recipient\") VALUES (?, ?)";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, starter, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, recipient, -1, SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
int HasDMs(char* starter, char* recipient) {
	const char* sql =
		"SELECT 1 FROM \"dm\" WHERE (\"starter\" = ? AND \"recipient\" = ?) OR "
		"(\"starter\" = ? AND \"recipient\" = ?)";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, starter, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, recipient, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, recipient, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, starter, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return 1;
	}
	sqlite3_finalize(stmt);
	return 0;
}
char* JoinUsernames(const YampUser* people, int n) {
	size_t len = 1;
	for (int i = 0; i < n; i++) {
		const char* nm =
			people[i].displayname ? people[i].displayname : people[i].username;
		len += strlen(nm) + (i ? 2 : 0);
	}

	char* out = malloc(len);
	if (!out)
		return NULL;

	char* p = out;
	for (int i = 0; i < n; i++) {
		const char* nm =
			people[i].displayname ? people[i].displayname : people[i].username;
		if (i) {
			*p++ = ',';
			*p++ = ' ';
		}
		size_t l = strlen(nm);
		memcpy(p, nm, l);
		p += l;
	}
	*p = '\0';
	return out;
}
void CreateGC(YampUser* creator, int ninitmember, YampUser** initmembers) {
	const char* sql = "INSERT INTO \"gc\" (\"id\", \"owner\") VALUES (?, ?)";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	char* id = NULL;
	GenerateID(&id);
	//  char* initialname = JoinUserNames(initmembers, ninitmember);
	// sqlite3_bind_text(stmt, 1, initialname, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, creator->id, -1, SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	for (int i = 0; i < ninitmember + 1; i++) {
		YampUser* usr = i == 0 ? creator : initmembers[i - 1];
		const char* memsql =
			"INSERT INTO \"user-gc\" (\"user-id\", \"gc-id\") VALUES (?, ?)";
		sqlite3_stmt* memstmt;
		sqlite3_prepare_v2(DB, memsql, -1, &memstmt, NULL);
		sqlite3_bind_text(memstmt, 1, usr->id, -1, SQLITE_STATIC);
		sqlite3_bind_text(memstmt, 2, id, -1, SQLITE_STATIC);
		sqlite3_step(memstmt);
		sqlite3_finalize(memstmt);
	}


	// free(initialname);
	free(id);
}
int UpdateGC(YampChannel* conv) {
	if (!conv)
		return 0;

	const char* sql = "UPDATE \"gc\" SET \"name\" = ? WHERE \"id\" = ?";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, conv->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, conv->id, -1, SQLITE_STATIC);

	int ok = sqlite3_step(stmt) == SQLITE_DONE;
	sqlite3_finalize(stmt);
	return ok;
}
int IsGCOwner(char* uid, char* gcid) {
	const char* sql = "SELECT \"owner\" FROM \"gc\" WHERE \"id\" = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, gcid, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW &&
		strcmp(uid, sqlite3_column_text(stmt, 0)) == 0) {
		sqlite3_finalize(stmt);
		return 1;
	}
	sqlite3_finalize(stmt);
	return 0;
}
int IsInGC(char* uid, char* gcid) {
	const char* sql =
		"SELECT 1 FROM \"user-gc\" WHERE \"user-id\" = ? AND \"gc-id\" = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, uid, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, gcid, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return 1;
	}
	sqlite3_finalize(stmt);
	return 0;
}
cJSON* ListGCMembersJSONFromID(const char* id) {
	const char* sql = "SELECT \"user-id\" FROM \"user-gc\" WHERE \"gc-id\" = ?";
	sqlite3_stmt* stmt;

	cJSON* members = cJSON_CreateArray();
	if (!members)
		return NULL;

	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK) {
		cJSON_Delete(members);
		return NULL;
	}
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* uid = (const char*)sqlite3_column_text(stmt, 0);
		if (!uid)
			continue;

		cJSON* tmp = NULL;
		if (CreateUserJSONFromID(uid, &tmp))
			cJSON_AddItemToArray(members, tmp);
	}

	sqlite3_finalize(stmt);
	return members;
}
int ListGCMembersObjectsFromID(char* id, YampUser*** out) {
	const char* sql = "SELECT \"user-id\" FROM \"user-gc\" WHERE \"gc-id\" = ?";
	sqlite3_stmt* stmt;
	*out = NULL;
	if (sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL) != SQLITE_OK)
		return 0;
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

	YampUser** arr = NULL;
	int n = 0, cap = 0;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* uid = (const char*)sqlite3_column_text(stmt, 0);
		if (!uid)
			continue;
		if (n == cap) {
			cap = cap ? cap * 2 : 8;
			YampUser** g = realloc(arr, cap * sizeof *arr);
			if (!g) {
				FreeUserArray(arr, n);
				sqlite3_finalize(stmt);
				return 0;
			}
			arr = g;
		}
		if (CreateUserObjectFromID(uid, &arr[n]))
			n++;
	}
	sqlite3_finalize(stmt);
	*out = arr;
	return n;
}

void FreeUserArray(YampUser** arr, int n) {
	for (int i = 0; i < n; i++)
		FreeUserObject(arr[i]);
	free(arr);
}

int AddMemberToGC(char* uid, char* gcid) {
	const char* sql =
		"INSERT INTO \"user-gc\" (\"user-id\", \"gc-id\") VALUES (?, ?)";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, uid, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, gcid, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return 1;
	}
	sqlite3_finalize(stmt);
	return 0;
}

cJSON* GetMessageHistoryPage(const char* where, const char* before, int limit) {
	static const char* sql_newest =
		"SELECT \"author\",\"content\",\"id\",\"type\",\"reply\",\"timestamp\" "
		"FROM \"messages\" WHERE \"channel\" = ?1 "
		"ORDER BY \"timestamp\" DESC, rowid DESC LIMIT ?2";

	static const char* sql_before =
		"SELECT \"author\",\"content\",\"id\",\"type\",\"reply\",\"timestamp\" "
		"FROM \"messages\" WHERE \"channel\" = ?1 "
		"AND (\"timestamp\", rowid) < "
		"  (SELECT \"timestamp\", rowid FROM \"messages\" "
		"   WHERE \"id\" = ?3 AND \"channel\" = ?1) "
		"ORDER BY \"timestamp\" DESC, rowid DESC LIMIT ?2";

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(DB, before ? sql_before : sql_newest, -1, &stmt,
						   NULL) != SQLITE_OK) {
		return NULL;
	}

	sqlite3_bind_text(stmt, 1, where, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, limit > 0 ? limit : -1);
	if (before)
		sqlite3_bind_text(stmt, 3, before, -1, SQLITE_STATIC);

	cJSON* list = cJSON_CreateArray();
	if (!list) {
		sqlite3_finalize(stmt);
		return NULL;
	}

	int rc;
	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		YampMessage msg = {0};

		const char* author = (const char*)sqlite3_column_text(stmt, 0);
		const char* content = (const char*)sqlite3_column_text(stmt, 1);
		const char* id = (const char*)sqlite3_column_text(stmt, 2);
		const char* reply = (const char*)sqlite3_column_text(stmt, 4);

		CreateUserObjectFromID(author, &msg.author);
		snprintf(msg.id, sizeof(msg.id), "%s", id ? id : "");
		snprintf(msg.channel, sizeof(msg.channel), "%s", where);
		msg.content = (char*)(content ? content : "");
		msg.type = sqlite3_column_int(stmt, 3);
		if (reply && *reply)
			msg.reply = CreateMessageTypeFromID(reply);
		msg.timestamp = sqlite3_column_int(stmt, 5);
		msg.nAttachments =
			ListAttachmentObjectsForID((char*)id, &msg.attachments);
		cJSON* obj = CreateMessageObject(&msg);
		for (int i = 0; i < msg.nAttachments; i++)
			FreeAttachmentObject(msg.attachments[i]);
		free(msg.attachments);
		if (!obj) {
			rc = SQLITE_ERROR;
			break;
		}
		cJSON_InsertItemInArray(list, 0, obj);
	}

	sqlite3_finalize(stmt);

	if (rc != SQLITE_DONE) {
		cJSON_Delete(list);
		return NULL;
	}
	return list;
}

cJSON* GetMessageHistory(char* where) {
	return GetMessageHistoryPage(where, NULL, 0);
}
int PushEvent(Connection con, char* event, cJSON* data) {
	cJSON* payload = cJSON_CreateObject();
	cJSON_AddStringToObject(payload, "type", "event");
	cJSON_AddStringToObject(payload, "event", event);
	cJSON_AddItemToObject(payload, "data", data);
	if (con.connected) {
		char* out = cJSON_Print(payload);
		if (con.encrypt) {
			TLSYAMPSend(con.ssl, out, strlen(out));
		} else {
			YAMPSend(con.fd, out, strlen(out));
		}
		free(out);
		return 1;
	}
	return 0;
}
int PushEventToUser(char* toID, char* event, cJSON* data) {
	YampUser search;
	strcpy(search.id, toID);
	const YampUser* usr = hashmap_get(UsersByID, &search);
	if (usr) {
		UserSession* ses = usr->sessions;
		int ret = 1;
		while (ses) {
			ret = ret && PushEvent(ses->con, event, data);
			ses = ses->next;
		}
		return ret;
	}
	cJSON_Delete(data);
	return 0;
}
int PushRecvIM(char* toID, char* channel, YampMessage* msg, int nonce) {
	cJSON* payload = cJSON_CreateObject();
	cJSON* message = CreateMessageObject(msg);
	if (message) {
		cJSON_AddItemToObject(payload, "message", message);
	}
	if (strcmp(toID, msg->author->id) == 0) {
		cJSON_AddNumberToObject(payload, "nonce", nonce);
	}
	PushEventToUser(toID, "recvim", payload);
	return 0;
}

int PushFQ(char* toID, char* fromID) {
	cJSON* payload = cJSON_CreateObject();
	cJSON_AddStringToObject(payload, "from", fromID);
	return PushEventToUser(toID, "IncomingFriendReq", payload);
}

int PushStatusUpdate(char* toWho, char* who, YampStatus* status) {
	cJSON* payload = cJSON_CreateObject();
	cJSON_AddStringToObject(payload, "user", who);
	cJSON_AddItemToObject(payload, "status", CreateStatusJSON(status));
	return PushEventToUser(toWho, "StatusUpdate", payload);
}

int PushNewSpace(char* who, char* space_id) {
	cJSON* body = NULL;
	if (!CreateSpaceObjectFromID(space_id, &body))
		return 0;
	return PushEventToUser(who, "NewSpace", body);
}

int PushUpdatedChannelsList(char* who, char* space_id) {
	cJSON* channellist = NULL;
	if (!CreateChannelsListFromName(space_id, &channellist))
		return 0;

	cJSON* body = cJSON_CreateObject();
	cJSON_AddItemToObject(body, "channels", channellist);
	cJSON_AddStringToObject(body, "space", space_id);
	return PushEventToUser(who, "UpdatedChannels", body);
}

int PushNewFriend(char* who, char* user_id) {
	cJSON* body = NULL;
	if (!CreateUserJSONFromID(user_id, &body))
		return 0;
	return PushEventToUser(who, "NewFriend", body);
}

int PushNewConversation(char* userid, YampChannel conv) {
	cJSON* body = CreateConvObject(&conv);
	return PushEventToUser(userid, "NewConversation", body);
}

int PushProfileUpdate(char* fromID, char* toID) {
	cJSON* body = NULL;
	if (!CreateUserJSONFromID(fromID, &body))
		return 0;
	return PushEventToUser(toID, "ProfileUpdate", body);
}

// Shared by JoinChannel / LeftChannel / Typing, which have identical payloads
static int PushUserChannelEvent(char* toID, char* fromID, char* channel,
								const char* event) {
	cJSON* user = NULL;
	if (!CreateUserJSONFromID(fromID, &user))
		return 0;

	cJSON* body = cJSON_CreateObject();
	cJSON_AddItemToObject(body, "user", user);
	cJSON_AddStringToObject(body, "channel_id", channel);
	return PushEventToUser(toID, event, body);
}

int PushJoinChannel(char* toID, char* fromID, char* channel) {
	return PushUserChannelEvent(toID, fromID, channel, "JoinChannel");
}
int PushLeftChannel(char* toID, char* fromID, char* channel) {
	return PushUserChannelEvent(toID, fromID, channel, "LeftChannel");
}
int PushTyping(char* toID, char* fromID, char* channel) {
	return PushUserChannelEvent(toID, fromID, channel, "Typing");
}

int PushMessageDeleted(char* toID, char* message) {
	cJSON* body = cJSON_CreateObject();
	cJSON_AddStringToObject(body, "message_id", message);
	return PushEventToUser(toID, "MessageDeleted", body);
}




void CreateFriendship(char* sender, char* accepter) {
	sqlite3_stmt* stmt;
	char* query = "INSERT INTO \"friendship\" (sender,accepter) VALUES (?,?)";
	sqlite3_prepare_v2(DB, query, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, accepter, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
int DestroyFriendReq(char* sender, char* receiver) {
	static const char* query =
		"DELETE FROM \"friendreq\" WHERE sender = ? AND recver = ?";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(DB, query, -1, &stmt, NULL) != SQLITE_OK)
		return 0;

	sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, receiver, -1, SQLITE_STATIC);

	int rc = sqlite3_step(stmt);
	int deleted = (rc == SQLITE_DONE) ? sqlite3_changes(DB) : 0;

	sqlite3_finalize(stmt);
	return deleted > 0;
}
void CreateFriendReq(char* sender, char* receiver) {
	sqlite3_stmt* stmt;
	char* query = "INSERT INTO \"friendreq\" (sender,recver) VALUES (?,?)";
	sqlite3_prepare_v2(DB, query, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, receiver, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}

int ListFriendReqs(const char* user, FriendReqEntry** out) {
	sqlite3_stmt* stmt;
	const char* query = "SELECT sender, recver FROM friendreq WHERE sender = "
						"? OR recver = ?";
	if (sqlite3_prepare_v2(DB, query, -1, &stmt, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);

	int count = 0, cap = 0;
	*out = NULL;
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* s = (const char*)sqlite3_column_text(stmt, 0);
		const char* r = (const char*)sqlite3_column_text(stmt, 1);
		if (count == cap) {
			cap = cap ? cap * 2 : 16;
			FriendReqEntry* g = realloc(*out, cap * sizeof(**out));
			if (!g) {
				sqlite3_finalize(stmt);
				return -1;
			}
			*out = g;
		}
		int outgoing = strcmp(s, user) == 0;
		(*out)[count].username = strdup(outgoing ? r : s);
		(*out)[count].outgoing = outgoing;
		count++;
	}
	sqlite3_finalize(stmt);
	return count;
}