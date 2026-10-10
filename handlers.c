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
static char* dup0(const char* s) { return strdup(s ? (const char*)s : ""); }
void FreeUserFields(user* u) {
	free(u->username);
	free(u->displayname);
	free(u->pfp);
	free(u->description);
}
int GenerateID(char** id) {
	static const char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";

	if (!id)
		return 0;

	*id = malloc(17);
	if (!*id)
		return 0;

	int pos = 0;

	while (pos < 16) {
		unsigned char byte;

		if (RAND_bytes(&byte, 1) != 1) {
			free(*id);
			*id = NULL;
			return 0;
		}

		if (byte >= 252)
			continue;

		(*id)[pos++] = alphabet[byte % 36];
	}

	(*id)[16] = '\0';

	return 1;
}

cJSON* CreateUserObject(user* user) {
	cJSON* obj = cJSON_CreateObject();

	cJSON_AddStringToObject(obj, "id", user->id);
	cJSON_AddStringToObject(obj, "name", user->username);
	cJSON_AddStringToObject(obj, "display_name", user->displayname);
	cJSON_AddStringToObject(obj, "description", user->description);
	cJSON_AddStringToObject(obj, "pfp", user->pfp);

	cJSON* status_obj = cJSON_CreateObject();

	cJSON_AddStringToObject(status_obj, "RPCName", user->status.RPCName);
	cJSON_AddStringToObject(status_obj, "RPCDesc", user->status.RPCDesc);
	cJSON_AddStringToObject(status_obj, "RPCIcon", user->status.RPCIcon);
	cJSON_AddStringToObject(status_obj, "status", user->status.status);

	cJSON_AddItemToObject(obj, "status", status_obj);

	return obj;
}
/*******************************************************************************
 * Note: connection is NULL, please do **NOT** use this for networking-related
 * stuff.
 *
 * @param rawusr The raw cJSON YAMP user
 * @return the final user object
 *******************************************************************************/
user ParseUserObject(cJSON* rawusr) {
	user usr;
	strncpy(usr.id, cJSON_GetObjectItem(rawusr, "id")->valuestring, 17);
	usr.username = dup0(cJSON_GetObjectItem(rawusr, "name")->valuestring);
	cJSON* rawdisp = cJSON_GetObjectItem(rawusr, "display_name");
	if (rawdisp) {
		usr.displayname = dup0(rawdisp->valuestring);
	} else {
		usr.displayname = NULL;
	}
	cJSON* rawdesc = cJSON_GetObjectItem(rawusr, "description");
	if (rawdesc) {
		usr.description = dup0(rawdesc->valuestring);
	} else {
		usr.description = NULL;
	}
	cJSON* rawpfp = cJSON_GetObjectItem(rawusr, "pfp");
	if (rawpfp) {
		usr.pfp = dup0(rawpfp->valuestring);
	} else {
		usr.pfp = NULL;
	}
	cJSON* rawstatus = cJSON_GetObjectItem(rawusr, "status");
	usr.status.status =
		dup0(cJSON_GetObjectItem(rawstatus, "status")->valuestring);
	usr.status.RPCName =
		dup0(cJSON_GetObjectItem(rawstatus, "RPCName")->valuestring);
	usr.status.RPCDesc =
		dup0(cJSON_GetObjectItem(rawstatus, "RPCDesc")->valuestring);
	usr.status.RPCIcon =
		dup0(cJSON_GetObjectItem(rawstatus, "RPCIcon")->valuestring);
	return usr;
}

int RegisterUserAccount(char* name, char* passwd) {
	const char* sql =
		"INSERT INTO users (name, display_name, password, id) VALUES (?,?,?,?)";

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

	int ok = sqlite3_step(stmt) == SQLITE_DONE;

	sqlite3_finalize(stmt);
	free(id);

	return ok;
}
int UpdateUserProfile(char* id, user newprofile) {
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
const char* GetSpaceIDFromName(char* name) {
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
const char* GetUserIDFromName(char* name) {
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
int CreateUserTypeFromID(const char* id, user* output) {
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

	memset(output, 0, sizeof(*output));

	strncpy(output->id, id, sizeof(output->id) - 1);

	output->username = dup0(sqlite3_column_text(stmt, 0));
	output->displayname = dup0(sqlite3_column_text(stmt, 1));
	output->pfp = dup0(sqlite3_column_text(stmt, 2));
	output->description = dup0(sqlite3_column_text(stmt, 3));

	sqlite3_finalize(stmt);

	user search = {0};
	search.username = output->username;

	const user* usr = hashmap_get(UsersByName, &search);

	if (usr && strcmp(usr->status.status, "offline") != 0)
		output->status = usr->status;
	else
		output->status = (status){"offline", "", "", ""};

	return 1;
}

int CreateUserObjectFromID(const char* id, cJSON** output) {
	user u;
	if (!CreateUserTypeFromID(id, &u))
		return 0;
	*output = CreateUserObject(&u);
	FreeUserFields(&u);
	return 1;
}

int CreateUserObjectFromUsername(const char* name, cJSON** output) {
	char* id = GetUserIDFromName(name);
	if (!id)
		return 0;
	int ok = CreateUserObjectFromID(id, output);
	free(id);
	return ok;
}
char* CreateSpaceInvite(const char* space_id, int uses) {
	static const char A[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	uint64_t v;
	if (RAND_bytes((unsigned char*)&v, sizeof v) != 1)
		return NULL;
	v %= 2821109907456ULL; /* 36^8 */
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
		if (CreateUserObjectFromID(friend, &userObj)) {
			cJSON_AddItemToArray(array, userObj);
		}
	}
	sqlite3_finalize(stmt);
	*output = array;
	return 1;
}
static cJSON* CreateMembersArray(cJSON* obj, const user* people, int n) {
	cJSON* arr = cJSON_AddArrayToObject(obj, "members");
	if (!arr)
		return NULL;

	for (int i = 0; i < n; i++) {
		cJSON* u = CreateUserObject(&people[i]);
		if (!u || !cJSON_AddItemToArray(arr, u)) {
			cJSON_Delete(u);
			return NULL;
		}
	}
	return arr;
}

cJSON* CreateConvObject(const YampChannel* conv) {
	const user* people = (const user*)(conv + 1);
	char addr_id[2 * 16 + 2];
	int n;

	switch (conv->type) {
	case YAMP_DM:
		if (conv->npeople != 2)
			return NULL;
		n = 2;
		{
			const char* a = people[0].id;
			const char* b = people[1].id;
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
	conv = calloc(1, sizeof *conv + 2 * sizeof(user));
	if (!conv)
		goto fail;
	user* dm_people = (user*)(conv + 1);

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

		memset(dm_people, 0, 2 * sizeof(user));
		if (CreateUserTypeFromID(a, &dm_people[0]) &&
			CreateUserTypeFromID(b, &dm_people[1])) {
			cJSON* obj = CreateConvObject(conv);
			if (obj && !cJSON_AddItemToArray(array, obj))
				cJSON_Delete(obj);
		}
		FreeUserFields(&dm_people[0]);
		FreeUserFields(&dm_people[1]);
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
		conv = calloc(1, sizeof *conv + cap * sizeof(user));
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
					realloc(conv, sizeof *conv + cap * sizeof(user));
				if (!grown)
					goto fail;
				conv = grown;
			}
			user* people = (user*)(conv + 1);
			if (CreateUserTypeFromID(uid, &people[n]))
				n++;
		}
		sqlite3_finalize(ms);
		ms = NULL;
		if (mrc != SQLITE_DONE)
			goto fail;

		conv->npeople = n;
		cJSON* obj = CreateConvObject(conv);
		if (obj && !cJSON_AddItemToArray(array, obj))
			cJSON_Delete(obj);

		free(conv);
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
	char* name;
	char* parent;
	cJSON* item;
} ChannelRow;
static ChannelRow* FindRowByName(ChannelRow* rows, size_t count,
								 const char* name) {
	for (size_t i = 0; i < count; i++) {
		if (rows[i].name && strcmp(rows[i].name, name) == 0) {
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
		rows[count].parent = cparent ? strdup(cparent) : NULL;
		rows[count].item = item;
		count++;
	}
	sqlite3_finalize(stmt);

	cJSON* root = cJSON_CreateArray();
	for (size_t i = 0; i < count; i++) {
		cJSON* item = rows[i].item;
		ChannelRow* parentRow =
			rows[i].parent ? FindRowByName(rows, count, rows[i].parent) : NULL;

		if (parentRow) {
			cJSON* children =
				cJSON_GetObjectItemCaseSensitive(parentRow->item, "children");
			cJSON_AddItemToArray(children, item);
		} else {
			cJSON_AddItemToArray(root, item);
		}
	}

	for (size_t i = 0; i < count; i++) {
		free(rows[i].name);
		free(rows[i].parent);
	}
	free(rows);

	*output = root;
	return 1;
}

int CreateUsersOwnObjectFromUsername(char* name, cJSON** output) {
	CreateUserObjectFromUsername(name, output);
	return 1;
}

cJSON* ListSpaceMembersFromID(char* id) {
	const char* sql =
		"SELECT \"user-id\" FROM \"user-space\" WHERE \"space-id\" = ?";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);

	cJSON* members = cJSON_CreateArray();

	for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW;
		 rc = sqlite3_step(stmt)) {
		cJSON* tmp;
		CreateUserObjectFromID(sqlite3_column_text(stmt, 0), &tmp);
		cJSON_AddItemToArray(members, tmp);
	}

	sqlite3_finalize(stmt);
	return members;
}
int IsInSpaceViaUserID(char* userid, char* spaceid) {
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
cJSON* CreateMessageObject(char* author, char* content, char* where) {
	cJSON* object = cJSON_CreateObject();
	cJSON_AddStringToObject(object, "author", author);
	cJSON_AddStringToObject(object, "content", content);
	cJSON_AddStringToObject(object, "channel", where);
	return object;
}
void InsertMessage(char* where, char* author, char* content) {
	const char* sql = "INSERT INTO \"messages\" (\"where\", \"author\", "
					  "\"content\", \"timestamp\") VALUES (?, ?, ?, ?)";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, where, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, author, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, content, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 4, (int)time(NULL));
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}
void CreateDM(char* starter, char* recipient) {
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
char* JoinUsernames(const user* people, int n) {
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
void CreateGC(user creator, int ninitmember, user* initmembers) {
	const char* sql =
		"INSERT INTO \"gc\" (\"id\", \"owner\") VALUES (?, ?)";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	char* id;
	GenerateID(&id);
	//  char* initialname = JoinUserNames(initmembers, ninitmember);
	// sqlite3_bind_text(stmt, 1, initialname, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 1, id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, creator.id, -1, SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	for (int i = 0; i < ninitmember + 1; i++) {
		user usr = i == 0 ? creator : initmembers[i - 1];
		const char* memsql =
			"INSERT INTO \"user-gc\" (\"user-id\", \"gc-id\") VALUES (?, ?)";
		sqlite3_stmt* memstmt;
		sqlite3_prepare_v2(DB, memsql, -1, &memstmt, NULL);
		sqlite3_bind_text(memstmt, 1, usr.id, -1, SQLITE_STATIC);
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
cJSON* ListGCMembersFromID(const char* id) {
	const char* sql =
		"SELECT \"user-id\" FROM \"user-gc\" WHERE \"gc-id\" = ?";
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
		if (CreateUserObjectFromID(uid, &tmp))
			cJSON_AddItemToArray(members, tmp);
	}

	sqlite3_finalize(stmt);
	return members;
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
cJSON* GetMessageHistory(char* where) {
	cJSON* list = cJSON_CreateArray();
	const char* sql = "SELECT \"author\",\"content\" FROM \"messages\" WHERE "
					  "\"where\" = ? ORDER BY \"timestamp\" ASC";
	sqlite3_stmt* stmt;
	sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, where, -1, SQLITE_STATIC);

	for (int rc = sqlite3_step(stmt); rc == SQLITE_ROW;
		 rc = sqlite3_step(stmt)) {
		cJSON_AddItemToArray(
			list,
			CreateMessageObject((char*)sqlite3_column_text(stmt, 0),
								(char*)sqlite3_column_text(stmt, 1), where));
	}

	return list;
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
	}
	cJSON_Delete(payload);
}
int PushRecvIM(char* toID, char* channel, char* fromID, char* content) {
	cJSON* payload = cJSON_CreateObject();
	user search;
	strcpy(search.id, toID);
	const user* usr = hashmap_get(UsersByID, &search);
	if (usr) {
		Connection con = usr->con;
		printf("Pushing a message recv event to %s at %d, that says %s\n", toID,
			   con.fd, content);
		cJSON_AddStringToObject(payload, "content", content);
		cJSON_AddStringToObject(payload, "author", fromID);
		cJSON_AddStringToObject(payload, "channel", channel);
		PushEvent(con, "recvim", payload);
		return 1;
	} else {
		printf("a message was canceled due to the other side being offline!\n");
	}
	return 0;
}
/********************************************************************
 * Pushes a friend req event
 * @param toID The ID of the user to send to
 * @param fromID The ID this comes from
 ********************************************************************/
int PushFQ(char* toID, char* fromID) {
	cJSON* payload = cJSON_CreateObject();
	user search;
	strcpy(search.id, toID);
	const user* usr = hashmap_get(UsersByID, &search);
	if (usr) {
		Connection con = usr->con;
		printf("Pushing an fq event to %s at %d\n", toID, con.fd);
		cJSON_AddStringToObject(payload, "from", fromID);
		PushEvent(con, "IncomingFriendReq", payload);
	} else {
		printf(
			"a friend req was omitted due to the other side being offline!\n");
	}
	return 1;
}
int PushStatusUpdate(char* toWho, char* who, status status) {
	cJSON* payload = cJSON_CreateObject();
	user search;
	strcpy(search.id, toWho);
	const user* usr = hashmap_get(UsersByID, &search);
	if (usr) {
		Connection con = usr->con;
		printf(
			"Pushing a status update event to %s at %d, with the status %s\n",
			toWho, con.fd, status.status);
		cJSON* stat = cJSON_CreateObject();
		cJSON_AddStringToObject(stat, "status", status.status);
		cJSON_AddStringToObject(stat, "RPCDesc", status.RPCDesc);
		cJSON_AddStringToObject(stat, "RPCIcon", status.RPCIcon);
		cJSON_AddStringToObject(stat, "RPCName", status.RPCName);
		cJSON_AddStringToObject(payload, "name", who);
		cJSON_AddItemToObject(payload, "status", stat);
		PushEvent(con, "StatusUpdate", payload);
		return 1;
	} else {
		printf("a status update msg was canceled due to the other side being "
			   "offline!\n");
	}
	return 0;
}
int PushNewSpace(char* who, char* space_id) {
	user search;
	strcpy(search.id, who);
	const user* usr = hashmap_get(UsersByID, &search);
	if (usr) {
		Connection con = usr->con;
		cJSON* body;
		int ok = CreateSpaceObjectFromID(space_id, &body);
		if (!ok) {
			return 0;
		}
		PushEvent(con, "NewSpace", body);
		return 1;
	}
	return 0;
}
int PushUpdatedChannelsList(char* who, char* space_id) {
	user search;
	strcpy(search.id, who);
	const user* usr = hashmap_get(UsersByID, &search);
	if (!usr)
		return 0;

	cJSON* channellist = NULL;
	if (!CreateChannelsListFromName(space_id, &channellist))
		return 0;

	cJSON* body = cJSON_CreateObject();
	cJSON_AddItemToObject(body, "channels", channellist);
	cJSON_AddStringToObject(body, "space", space_id);
	PushEvent(usr->con, "UpdatedChannels",
			  body); // PushEvent takes ownership of body
	return 1;
}
int PushNewFriend(char* who, char* user_id) {
	user search;
	strcpy(search.id, who);
	const user* usr = hashmap_get(UsersByID, &search);
	if (usr) {
		Connection con = usr->con;
		cJSON* body;
		int ok = CreateUserObjectFromID(user_id, &body);
		if (!ok) {
			return 0;
		}
		PushEvent(con, "NewFriend", body);
		return 1;
	}
	return 0;
}
int PushNewConversation(char* userid, YampChannel conv) {
	user search;
	strcpy(search.id, userid);
	const user* usr = hashmap_get(UsersByID, &search);
	if (usr) {
		Connection con = usr->con;
		cJSON* body;
		int ok = CreateUserObjectFromID(userid, &body);
		if (!ok) {
			return 0;
		}
		PushEvent(con, "NewConversation", body);
		return 1;
	}
	return 0;
}
/********************************************************************
 * Pushes a profile update event
 * @param toID The ID of the user to send to
 * @param fromID The ID of the user that just updated
 ********************************************************************/
int PushProfileUpdate(char* fromID, char* toID) {
	user search;
	strcpy(search.id, toID);
	const user* usr = hashmap_get(UsersByID, &search);
	if (usr) {
		Connection con = usr->con;
		cJSON* body;
		if (!CreateUserObjectFromID(fromID, &body)) {
			return 0;
		}
		PushEvent(con, "ProfileUpdate", body);
		return 1;
	}
	return 0;
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