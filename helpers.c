#include "helpers.h"
#include "hmap/hashmap.h"
#include "types.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <sqlite3.h>
#include <cjson/cJSON.h>
#include "globals.h"
#include "handlers.h"

int YAMPProcessWhere(char* where, char* curUserID, chat* out) {
	chat retval = {0};
	if (*where == '&') {
		// Group chat
		retval.GC_ID = strdup(where + 1);
		retval.OtherGuy = NULL;
		retval.type = YAMP_GC;
		retval.where = strdup(where);
		*out = retval;
		return TRUE;
	} else {
		// Could be a damn DM?
		char* firstUsr = strdup(where);
		char* minus = strchr(firstUsr, '|');
		if (!minus) {
			// This means it's a space channel!
			free(firstUsr);
			retval.GuildName = NULL; // long deprecated sorry
			retval.ChannelName = strdup(where);
			retval.OtherGuy = NULL;
			retval.type = YAMP_SPACE_TEXT;
			retval.where = strdup(where);
			*out = retval;
			return TRUE;
		}
		*minus = '\0';
		retval.ChannelName = NULL;
		retval.type = YAMP_DM;
		retval.where = strdup(where);
		if (strcmp(firstUsr, curUserID) == 0) {
			retval.OtherGuy = minus + 1;
		} else if (strcmp(minus + 1, curUserID) == 0) {
			retval.OtherGuy = firstUsr;
		} else {
			return FALSE; // who the FUCK are you
		}
		retval.GuildName = NULL;
		*out = retval;
		return TRUE;
	}
}
uint64_t hmap_username_hash(const void* item, uint64_t seed0, uint64_t seed1) {
	return hashmap_sip(((user*)item)->username, strlen(((user*)item)->username),
					   seed0, seed1);
}
int hmap_username_compare(const void* a, const void* b, void* udata) {
	return strcmp(((const user*)a)->username, ((const user*)b)->username);
}
uint64_t hmap_userid_hash(const void* item, uint64_t seed0, uint64_t seed1) {
	return hashmap_sip(((user*)item)->id, strlen(((user*)item)->id), seed0,
					   seed1);
}
int hmap_userid_compare(const void* a, const void* b, void* udata) {
	return strcmp(((const user*)a)->id, ((const user*)b)->id);
}
void hmap_username_free(void* item) {}
void hmap_userid_free(void* item) {}

uint64_t hmap_userfd_hash(const void* item, uint64_t seed0, uint64_t seed1) {
	int fd = ((user*)item)->con.fd;
	return hashmap_sip(&fd, sizeof(fd), seed0, seed1);
}
int hmap_userfd_compare(const void* a, const void* b, void* udata) {
	if (((const user*)a)->con.fd == ((const user*)b)->con.fd) {
		return 0;
	} else if (((const user*)a)->con.fd < ((const user*)b)->con.fd) {
		return -1;
	} else {
		return 1;
	}
}
void hmap_userfd_free(void* item) {}

char* MakeDMChannel(const char* a, const char* b) {
	if (strcmp(a, b) < 0)
		return g_strdup_printf("%s|%s", a, b);
	else
		return g_strdup_printf("%s|%s", b, a);
}

void sha256_hex(const char* input, char* output_hex) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char*)input, strlen(input), hash);

	// convert to hex string
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(output_hex + (i * 2), "%02x", hash[i]);
	}
	output_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
}



char* dup0(const char* s) { return strdup(s ? (const char*)s : ""); }

void FreeUserFields(user* u) {
	free(u->username);
	free(u->displayname);
	free(u->pfp);
	free(u->description);
}

void FreeYampChannel(YampChannel* ch) {
	if (!ch)
		return;
	user* people = (user*)(ch + 1);
	for (int i = 0; i < ch->npeople; i++)
		FreeUserFields(&people[i]);
	free(ch->name);
	free(ch->parent);
	free(ch);
}

static YampChannel* SpaceChannelFromRow(sqlite3_stmt* st) {
	YampChannel* ch = calloc(1, sizeof *ch);
	if (!ch)
		return NULL;

	const char* name = (const char*)sqlite3_column_text(st, 1);
	const char* parent = (const char*)sqlite3_column_text(st, 3);
	const char* cid = (const char*)sqlite3_column_text(st, 4);
	const char* space = (const char*)sqlite3_column_text(st, 5);

	ch->type = YAMP_SPACE_TEXT;
	ch->pos = sqlite3_column_int(st, 0);
	ch->type = sqlite3_column_int(st, 2);
	ch->name = dup0(name);
	snprintf(ch->parent, sizeof ch->parent, "%s", parent ? parent : "");
	snprintf(ch->id, sizeof ch->id, "%s", cid ? cid : "");
	snprintf(ch->space, sizeof ch->space, "%s", space ? space : "");

	if (!ch->name) {
		FreeYampChannel(ch);
		return NULL;
	}
	return ch;
}

static YampChannel* GetSpaceChannelFromID(const char* id) {
	const char* sql = "SELECT pos, name, type, parent, id, space "
					  "FROM channels WHERE id = ?";
	sqlite3_stmt* st;
	if (sqlite3_prepare_v2(DB, sql, -1, &st, NULL) != SQLITE_OK)
		return NULL;
	sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);

	YampChannel* ch = NULL;
	if (sqlite3_step(st) == SQLITE_ROW)
		ch = SpaceChannelFromRow(st);
	sqlite3_finalize(st);
	return ch;
}

static cJSON* CreateSpaceChannelObject(const YampChannel* ch) {
	cJSON* item = cJSON_CreateObject();
	if (!item)
		return NULL;
	cJSON_AddNumberToObject(item, "position", ch->pos);
	cJSON_AddStringToObject(item, "name", ch->name ? ch->name : "");
	cJSON_AddStringToObject(item, "id", ch->id);
	cJSON_AddNumberToObject(item, "type", ch->type);
	if (ch->parent)
		cJSON_AddStringToObject(item, "parent", ch->parent);
	else
		cJSON_AddNullToObject(item, "parent");
	cJSON_AddItemToObject(item, "children", cJSON_CreateArray());
	return item;
}

YampChannel* GetDMFromAddress(const char* addr) {
	const char* bar = strchr(addr, '|');
	if (!bar || (size_t)(bar - addr) != 16 || strlen(bar + 1) != 16)
		return NULL;

	char a[17], b[17];
	memcpy(a, addr, 16);
	a[16] = '\0';
	memcpy(b, bar + 1, 16);
	b[16] = '\0';

	if (!HasDMs(a, b))
		return NULL;

	YampChannel* conv = calloc(1, sizeof *conv + 2 * sizeof(user));
	if (!conv)
		return NULL;
	user* people = (user*)(conv + 1);

	conv->type = YAMP_DM;
	if (!CreateUserTypeFromID(a, &people[0])) {
		free(conv);
		return NULL;
	}
	conv->npeople = 1;
	if (!CreateUserTypeFromID(b, &people[1])) {
		FreeYampChannel(conv);
		return NULL;
	}
	conv->npeople = 2;
	return conv;
}

YampChannel* GetGCFromID(const char* gid) {
	sqlite3_stmt* st = NULL;
	YampChannel* conv = NULL;
	char* name = NULL;

	if (sqlite3_prepare_v2(DB, "SELECT \"name\" FROM \"gc\" WHERE \"id\" = ?",
						   -1, &st, NULL) != SQLITE_OK)
		return NULL;
	sqlite3_bind_text(st, 1, gid, -1, SQLITE_STATIC);
	if (sqlite3_step(st) != SQLITE_ROW) {
		sqlite3_finalize(st);
		return NULL;
	}
	const char* n = (const char*)sqlite3_column_text(st, 0);
	if (n)
		name = strdup(n);
	sqlite3_finalize(st);
	st = NULL;

	size_t cap = 8;
	conv = calloc(1, sizeof *conv + cap * sizeof(user));
	if (!conv) {
		free(name);
		return NULL;
	}
	conv->type = YAMP_GC;
	conv->name = name;
	snprintf(conv->id, sizeof conv->id, "%s", gid);

	if (sqlite3_prepare_v2(
			DB, "SELECT \"user-id\" FROM \"user-gc\" WHERE \"gc-id\" = ?", -1,
			&st, NULL) != SQLITE_OK) {
		FreeYampChannel(conv);
		return NULL;
	}
	sqlite3_bind_text(st, 1, gid, -1, SQLITE_STATIC);

	int n_people = 0, rc;
	while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
		const char* uid = (const char*)sqlite3_column_text(st, 0);
		if (!uid)
			continue;
		if ((size_t)n_people == cap) {
			cap *= 2;
			YampChannel* grown =
				realloc(conv, sizeof *conv + cap * sizeof(user));
			if (!grown) {
				sqlite3_finalize(st);
				FreeYampChannel(conv);
				return NULL;
			}
			conv = grown;
		}
		user* people = (user*)(conv + 1);
		if (CreateUserTypeFromID(uid, &people[n_people])) {
			n_people++;
			conv->npeople = n_people; /* keep in sync for cleanup */
		}
	}
	sqlite3_finalize(st);
	if (rc != SQLITE_DONE) {
		FreeYampChannel(conv);
		return NULL;
	}
	return conv;
}

/*******************************************************************************
 * Resolves a channel id to a YampChannel, based on the standard descriptors
 *   "&<gcid>"        -> group chat
 *   "<uidA>|<uidB>"  -> DM
 *   anything else    -> space channel (channels.id)
 *
 * Returns a heap object
 * NOTE: does no authorization, check with the functions of the type
 *******************************************************************************/
YampChannel* GetChannelFromID(const char* id) {
	if (!id || !*id)
		return NULL;
	if (id[0] == '&')
		return GetGCFromID(id + 1);
	if (strchr(id, '|'))
		return GetDMFromAddress(id);
	return GetSpaceChannelFromID(id);
}