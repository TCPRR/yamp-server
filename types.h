#pragma once
#include <openssl/ssl.h>
#define YAMP_GUILD 1
#define YAMP_DM 0
#define YAMP_GC 2

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
	char id[16+1+16+1];
	char* name;
	struct YampChannel* children;
	int nchildren;
	int pos;
	int npeople;
} YampChannel;