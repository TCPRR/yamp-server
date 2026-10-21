#pragma once
#include <openssl/ssl.h>
#define YAMP_DM 0
#define YAMP_GC 1
#define YAMP_SPACE_TEXT 40
#define YAMP_SPACE_CATEGORY 41
#define YAMP_SPACE_ANNOUNCEMENT 42
#define YAMP_SPACE_INDEX 43
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
typedef struct {
	Connection con;
	char id[17];
	char *username;
	char* displayname;
	char* description;
	char* pfp;
	status status;
	int isTyping;
	char typingAt[34];
} user;
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
	char space[17];
	char parent[17];
} YampChannel;
typedef struct YampMessage {
	char id[16+1];
	char author[16+1];
	int type; // for later use
	uint64_t timestamp;
	char channel[16+1+16+1];
	char* content;
	struct YampMessage* reply;
} YampMessage;