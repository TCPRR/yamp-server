#include "config.h"
#include "ext/toml.h"
YampConfig config;
#define CONFIG_PATH "/etc/yampd"


char* config_get_str_val(toml_table_t *t, const char *key) {
    toml_datum_t d = toml_string_in(t, key);
    if(!d.ok){
        return NULL;
    }
    return d.u.s;
}

// to be fair with you, toml-c99 is ass to use, neither do i like the datum and structure shit it uses
// just endure it, there isnt anything better, i dont want XML or JSON configs
int LoadConfig() {
    char errbuf[200];
    FILE *fp = fopen(CONFIG_PATH"/config.toml", "r");

    toml_table_t *root = toml_parse_file(fp, errbuf, sizeof errbuf);
    fclose(fp);
    if (!root) { fprintf(stderr, "toml: %s\n", errbuf); return 0; }

    config.http_base_url = config_get_str_val(root, "http_base_url");
    config.hostname = config_get_str_val(root, "hostname");
    config.cdn_root = config_get_str_val(root, "cdn_root");

    toml_datum_t d = toml_int_in(root, "max_upload_size");
    if (d.ok) config.maxupload = (unsigned long long)d.u.i; else config.maxupload = -1;

    d = toml_int_in(root, "gc_member_limit");
    if (d.ok) config.gc_member_limit = (unsigned long long)d.u.i; else config.gc_member_limit = -1;

    toml_table_t *tls = toml_table_in(root, "tls");
    if (tls) {
        config.fullchain_path = config_get_str_val(tls, "chainfile_path");
        config.privkey_path = config_get_str_val(tls, "privkey_path");
    }

    toml_free(root);
    return 1;
}