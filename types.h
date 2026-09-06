#pragma once
#define YAMP_GUILD 1
#define YAMP_DM 0

typedef struct {
	char type; // 0 = DM, 1 = Guild Channel
	char *where; // to be used in the APIs
	char *OtherGuy; // for DMs only, otherwise NULL.. CHECK AND DO NOT
	                // DEREFERENCE THAAT!
	char *GuildName; // Above but for guilds!
	char *ChannelName; // same same, but differeeeent :sob:
} chat;
typedef struct{
	char* status;
	char* RPCName;
	char* RPCDesc;
	char* RPCIcon;
} status;
typedef struct {
	int fd;
	char *username;
	char* displayname;
	char* description;
	char* pfp;
	status status;
} user;
