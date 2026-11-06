#pragma once
#include "glib.h"
#include "types.h"
gboolean YAMPProcessWhere(char *where, char *curUsername, chat *out);
uint64_t hmap_username_hash(const void *item, uint64_t seed0, uint64_t seed1);
int hmap_username_compare(const void *a, const void *b, void *udata);
void hmap_username_free(void *item);
uint64_t hmap_userid_hash(const void *item, uint64_t seed0, uint64_t seed1);
int hmap_userid_compare(const void *a, const void *b, void *udata);
void hmap_userid_free(void *item);
uint64_t hmap_session_hash(const void* item, uint64_t seed0, uint64_t seed1);
int hmap_session_compare(const void* a, const void* b, void* udata);
void sha256_hex(const char *input, char *output_hex);

char* dup0(const char* s);
void FreeUserFields(YampUser* u);

UserSession* FindSessionByFD(int fd);
YampUser* FindUserByFD(int fd);
void hmap_session_free(void* item);