#pragma once
#define CONFIG_PATH "/etc/yampd"

typedef struct {
	char* hostname;
	char* http_base_url;
	unsigned long long maxupload;
	int gc_member_limit;
	char* cdn_root;
	char* fullchain_path; // we prefer certs issued by letsencrypt due to it being verifiable
	char* privkey_path;
} YampConfig;
extern YampConfig config;
int LoadConfig();