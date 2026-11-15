#pragma once
#define CHAINFILE_PATH "/etc/letsencrypt/live/yamp.root.sx/fullchain.pem"
#define PRIVKEY_PATH "/etc/letsencrypt/live/yamp.root.sx/privkey.pem"

#define GC_MAX_MEMBERS 25


typedef struct {
	char* http_base_url;
	unsigned long long maxupload;
	int gc_member_limit;
	char* cdn_root;
    unsigned long long max_clients;
    unsigned long long max_ipc_clients;
} YampConfig;
extern YampConfig config;