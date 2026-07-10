#include "helpers.h"
#include "hmap/hashmap.h"
#include <openssl/sha.h>
#include <stdio.h>
gboolean YAMPProcessWhere(char *where, char *curUsername, chat *out) {
	char *dupedwhere = strdup(where);
	char *safewhere = strdup(where);
	chat retval = {0};
	if (*where == '^') {
		// GUILD PROBABLY
		char *hashtag = strchr(safewhere, '#');
		if (!hashtag) {
			return FALSE;
		}
		*hashtag = '\0';
		retval.GuildName = safewhere + 1;
		retval.ChannelName = hashtag + 1;
		retval.OtherGuy = NULL;
		retval.type = YAMP_GUILD;
		retval.where = dupedwhere;
		*out = retval;
		return TRUE;
	} else {
		// Could be a damn DM?
		char *minus = strchr(safewhere, '|');
		if (!minus) {
			return FALSE; // nah it wasnt anything LMFAO
		}
		*minus = '\0';
		retval.ChannelName = NULL;
		retval.type = YAMP_DM;
		retval.where = dupedwhere;
		if (strcmp(minus+1, curUsername) == 0) {
			retval.OtherGuy = safewhere;
		} else {
			retval.OtherGuy = minus + 1;
		}
		retval.GuildName = NULL;
		*out = retval;
		return TRUE;
	}
}
uint64_t hmap_username_hash(const void *item, uint64_t seed0, uint64_t seed1){
	return hashmap_sip(((user*)item)->username,strlen(((user*)item)->username),seed0,seed1);
}
int hmap_username_compare(const void *a, const void *b, void *udata){
	return strcmp(((const user*)a)->username,((const user*)b)->username);
}
void hmap_username_free(void *item){

}

uint64_t hmap_userfd_hash(const void *item, uint64_t seed0, uint64_t seed1){
    int fd = ((user*)item)->fd;
    return hashmap_sip(&fd, sizeof(fd), seed0, seed1);
}
int hmap_userfd_compare(const void *a, const void *b, void *udata){
	if(((const user*)a)->fd == ((const user*)b)->fd){
		return 0;
	}else if(((const user*)a)->fd < ((const user*)b)->fd){
		return -1;
	} else{
		return 1;
	}
}
void hmap_userfd_free(void *item){

}



char *MakeDMChannel(const char *a, const char *b) {
	if (strcmp(a, b) < 0)
		return g_strdup_printf("%s|%s", a, b);
	else
		return g_strdup_printf("%s|%s", b, a);
}



void sha256_hex(const char *input, char *output_hex) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char *)input, strlen(input), hash);

	// Convert to hex string
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(output_hex + (i * 2), "%02x", hash[i]);
	}
	output_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
}