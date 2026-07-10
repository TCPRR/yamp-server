#include "glib.h"
#include "types.h"
gboolean YAMPProcessWhere(char *where, char *curUsername, chat *out);
uint64_t hmap_username_hash(const void *item, uint64_t seed0, uint64_t seed1);
int hmap_username_compare(const void *a, const void *b, void *udata);
void hmap_username_free(void *item);
uint64_t hmap_userfd_hash(const void *item, uint64_t seed0, uint64_t seed1);
int hmap_userfd_compare(const void *a, const void *b, void *udata);
void hmap_userfd_free(void *item);
void sha256_hex(const char *input, char *output_hex);