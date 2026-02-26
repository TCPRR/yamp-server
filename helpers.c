#include "helpers.h"
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
		if (strcmp(where, curUsername) == 0) {
			retval.OtherGuy = minus + 1;
		} else {
			retval.OtherGuy = safewhere;
		}
		retval.GuildName = NULL;
		*out = retval;
		return TRUE;
	}
}
