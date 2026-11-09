#pragma once
#include <openssl/ssl.h>

#define YAMP_DM                 0
#define YAMP_GC                 1

#define YAMP_FAMILY_SPACE       (1 << 8)
#define YAMP_FAMILY_MASK        0xFF00
#define YAMP_SUBTYPE_MASK       0x00FF

#define YAMP_SPACE_TEXT         (YAMP_FAMILY_SPACE | 0)
#define YAMP_SPACE_CATEGORY     (YAMP_FAMILY_SPACE | 1)
#define YAMP_SPACE_ANNOUNCEMENT (YAMP_FAMILY_SPACE | 2)
#define YAMP_SPACE_INDEX        (YAMP_FAMILY_SPACE | 3)

#define YAMP_IS_SPACE_TYPE(t)   (((t) & YAMP_FAMILY_MASK) == YAMP_FAMILY_SPACE)


// ID Fields here are still kept 17 bytes for legacy compat with older DB entries, though modern YAMP uses 13 bytes
// Doesn't matter anyway, 17 can fit 13

// TODO: finish deprecating the type chat for the type YampChannel EVERYWHERE
typedef struct {
	char type; // 0 = DM, 1 = Space Channel
	char *where; // to be used in the APIs
	char *OtherGuy; // for DMs only, otherwise NULL.. CHECK AND DO NOT
	                // DEREFERENCE THAAT!
	char *GuildName; // Above but for guilds!
	char *ChannelName; // same same, but differeeeent :sob:
	char* GC_ID; // Group Chat ID
} chat;
typedef struct{
	char* status;
	char* RPCName;
	char* RPCDesc;
	char* RPCIcon;
} status;
typedef struct {
	int connected;
	int encrypt;
	int fd;
	SSL *ssl;
	unsigned long long LastRegistration;
	unsigned long long LastEndpoint;
	int ratelimited;
} Connection;

typedef struct YampUser YampUser;
typedef struct UserSession UserSession;
struct UserSession{
	Connection con;
	int device_type;
	char* device;
	char* token;
	YampUser* user;
	struct UserSession* prev;
	struct UserSession* next; // making this a doubly-linked list item too
};
struct YampUser {
	char id[17];
	char *username;
	char* displayname;
	char* description;
	char* pfp;
	status status;
	int isTyping;
	char typingAt[34];
	char* banner;
	UserSession* sessions;
};

typedef struct {
	char id[17];
	char* name;
	char* displayname;
	char* icon;
	char* banner;
	char* description;
	int type;
} YampSpace;
typedef struct{
	char* key;
	char* val;
} MainRespOverride;
typedef struct YampChannel {
	int type;
	char id[16+1+16+1]; // DM channel IDs are the maximum this field can get, which totals up to 34 (w/ null terminator included)
	char* name;
	struct YampChannel* children;
	int nchildren;
	int pos;
	int npeople;
	char* space;
	char* parent;
} YampChannel;
typedef struct{
	char* url;
	char* mime;
	char* filename;
} YampAttachment; // ALL HEAPP GUH

typedef struct YampMessage YampMessage;
typedef struct{
	char msg_id[17];
	YampUser* user;
	char* codepoint;
} YampReaction;
struct YampMessage {
	char id[16+1];
	YampUser* author;
	int type; // for later use
	uint64_t timestamp;
	char channel[16+1+16+1];
	char* content;
	struct YampMessage* reply;
	YampReaction** reactions;
	int nReactions;
	YampAttachment** attachments; // damn
	int nAttachments;
};