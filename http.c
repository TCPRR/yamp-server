#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <civetweb.h>
#include "handlers.h"
#include "override.h"
#include "toml.h"
#include "http.h"
#include "pthread.h"
#include <fcntl.h>

#define CDN_ROOT "/var/www/yamp-http"
#define PROXY_MAX_BYTES (8u * 1024 * 1024)
#define PROXY_TIMEOUT_S 10L

typedef struct {
	char* http_base_url;
	unsigned long long maxupload;
	int gc_member_limit;
	char* cdn_root;
} YampConfig;
YampConfig config;
UploadToken* UTStack = NULL;
pthread_mutex_t UTLock = PTHREAD_MUTEX_INITIALIZER;

UploadToken* RegisterUploadToken() {
	UploadToken* tok = calloc(1, sizeof(*tok));
	if (!tok)
		return NULL;
	GenerateUploadToken_Inline(tok->tok);

	pthread_mutex_lock(&UTLock);
	if (!UTStack) {
		UTStack = tok;
	} else {
		UploadToken* last = UTStack;
		while (last->after)
			last = last->after;
		last->after = tok;
		tok->before = last;
	}
	pthread_mutex_unlock(&UTLock);
	return tok;
}
int ConsumeUploadToken(const char* tok) {
	int found = 0;
	pthread_mutex_lock(&UTLock);
	for (UploadToken* c = UTStack; c; c = c->after) {
		if (strcmp(c->tok, tok) == 0) {
			if (c->before)
				c->before->after = c->after;
			else
				UTStack = c->after;
			if (c->after)
				c->after->before = c->before;
			free(c);
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&UTLock);
	return found;
}
void respond(struct mg_connection* conn, int status, const char* ctype,
			 const char* body) {
	mg_printf(
		conn,
		"HTTP/1.1 %d\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n%s",
		status, ctype, strlen(body), body);
}

void invite_fetch(const char* code) {
	// TODO for later bullshi
}

int Invite_Handler(struct mg_connection* conn, void* cbdata) {
	const struct mg_request_info* ri = mg_get_request_info(conn);

	const char* uri = ri->local_uri;

	if (strncmp(uri, "/invite/", 8) != 0)
		return 404;

	const char* code = uri + 8;
	char body[2048];

	snprintf(body, sizeof body,
			 "<h1>Unimplemented, this was an invite for %s</h1>", code);

	mg_printf(conn,
			  "HTTP/1.1 200 OK\r\n"
			  "Content-Type: text/html; charset=utf-8\r\n"
			  "Content-Length: %zu\r\n"
			  "\r\n"
			  "%s",
			  strlen(body), body);

	return 200;
}

const struct {
	const char *ext, *mime;
} MIMEList[] = {
	{".png", "image/png"},		 {".jpg", "image/jpeg"},
	{".jpeg", "image/jpeg"},	 {".gif", "image/gif"},
	{".webp", "image/webp"},	 {".avif", "image/avif"},
	{".mp4", "video/mp4"},		 {".webm", "video/webm"},
	{".mp3", "audio/mpeg"},		 {".ogg", "audio/ogg"},
	{".txt", "text/plain"},		 {".json", "application/json"},
	{".pdf", "application/pdf"},
};
const char* mime_for(const char* p) {
	const char* dot = strrchr(p, '.');
	if (!dot)
		return "application/octet-stream";
	for (size_t i = 0; i < sizeof MIMEList / sizeof *MIMEList; i++)
		if (strcasecmp(dot, MIMEList[i].ext) == 0)
			return MIMEList[i].mime;
	return "application/octet-stream";
}
const char* ext_for(const char* ct) {
	if (!ct)
		return "";
	size_t n = strcspn(ct, "; \t");
	for (size_t i = 0; i < sizeof MIMEList / sizeof *MIMEList; i++)
		if (strlen(MIMEList[i].mime) == n &&
			strncasecmp(ct, MIMEList[i].mime, n) == 0)
			return MIMEList[i].ext;
	return "";
}

int CDN_Handler(struct mg_connection* conn, void* cbdata) {
	const char* prefix = cbdata;
	size_t plen = strlen(prefix);
	const struct mg_request_info* ri = mg_get_request_info(conn);

	if (strncmp(ri->local_uri, prefix, plen) != 0)
		return 0;
	const char* rel = ri->local_uri + plen;

	if (!*rel || strstr(rel, "..") || strchr(rel, '%') || strchr(rel, '\\')) {
		mg_send_http_error(conn, 400, "Bad path");
		return 400;
	}

	char path[4096];
	if (snprintf(path, sizeof path, "%s/%s", CDN_ROOT, rel) >=
		(int)sizeof path) {
		mg_send_http_error(conn, 414, "Path too long");
		return 414;
	}

	struct stat st;
	if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)) {
		mg_send_http_error(conn, 404, "Not found");
		return 404;
	}

	mg_send_mime_file2(conn, path, mime_for(rel),
					   "Cache-Control: public, max-age=31536000, immutable\r\n"
					   "X-Content-Type-Options: nosniff\r\n");
	return 200;
}


typedef struct {
	unsigned char* data;
	size_t len, cap;
	char ctype[128];
} fetch_t;

size_t on_body(char* p, size_t sz, size_t n, void* ud) {
	fetch_t* f = ud;
	size_t total = sz * n;
	if (f->len + total > PROXY_MAX_BYTES)
		return 0;
	if (f->len + total > f->cap) {
		size_t ncap = f->cap ? f->cap * 2 : 65536;
		while (ncap < f->len + total)
			ncap *= 2;
		unsigned char* nd = realloc(f->data, ncap);
		if (!nd)
			return 0;
		f->data = nd;
		f->cap = ncap;
	}
	memcpy(f->data + f->len, p, total);
	f->len += total;
	return total;
}

size_t on_header(char* p, size_t sz, size_t n, void* ud) {
	fetch_t* f = ud;
	size_t total = sz * n;
	if (total >= 5 && strncasecmp(p, "HTTP/", 5) == 0) {
		f->ctype[0] = 0;
	} else if (total > 13 && strncasecmp(p, "Content-Type:", 13) == 0) {
		const char* v = p + 13;
		size_t l = total - 13;
		while (l && (*v == ' ' || *v == '\t')) {
			v++;
			l--;
		}
		while (l && (v[l - 1] == '\r' || v[l - 1] == '\n' || v[l - 1] == ' '))
			l--;
		if (l >= sizeof f->ctype)
			l = sizeof f->ctype - 1;
		memcpy(f->ctype, v, l);
		f->ctype[l] = 0;
	}
	return total;
}

int IPv4_IsBlocked(uint32_t ip) {
	unsigned a = ip >> 24, b = (ip >> 16) & 255;
	return a == 0 || a == 10 || a == 127 || a >= 224 ||
		   (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) ||
		   (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127);
}

int IsBlocked(const struct sockaddr* sa) {
	if (sa->sa_family == AF_INET)
		return IPv4_IsBlocked(
			ntohl(((const struct sockaddr_in*)sa)->sin_addr.s_addr));
	if (sa->sa_family == AF_INET6) {
		const struct in6_addr* a = &((const struct sockaddr_in6*)sa)->sin6_addr;
		if (IN6_IS_ADDR_LOOPBACK(a) || IN6_IS_ADDR_UNSPECIFIED(a) ||
			IN6_IS_ADDR_LINKLOCAL(a) || (a->s6_addr[0] & 0xfe) == 0xfc)
			return 1;
		if (IN6_IS_ADDR_V4MAPPED(a)) {
			uint32_t v4;
			memcpy(&v4, a->s6_addr + 12, 4);
			return IPv4_IsBlocked(ntohl(v4));
		}
		return 0;
	}
	return 1;
}

curl_socket_t open_cb(void* u, curlsocktype purpose, struct curl_sockaddr* a) {
	(void)u;
	(void)purpose;
	if (IsBlocked(&a->addr))
		return CURL_SOCKET_BAD;
	return socket(a->family, a->socktype, a->protocol);
}

int Proxy_Handler(struct mg_connection* conn, void* cbdata) {
	const struct mg_request_info* ri = mg_get_request_info(conn);
	char* enc = ri->query_string;
	if (!enc) {
		respond(conn, 400, "text/plain", "missing url\n");
		return 0;
	}

	int ulen = 0;
	char url[2048];
	mg_get_var(ri->query_string, strlen(ri->query_string), "url", url,
			   sizeof(url));
	fetch_t f = {0};
	CURL* curl = curl_easy_init();
	if (!curl) {
		respond(conn, 500, "text/plain", "curl init failed\n");
		return 0;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, PROXY_TIMEOUT_S);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "yamp-http/0.1");
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, open_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &f);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &f);

	CURLcode rc = curl_easy_perform(curl);
	long code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
	curl_easy_cleanup(curl);

	if (rc != CURLE_OK || code != 200) {
		respond(conn, 502, "text/plain", "Upstream fetch failed\n");
	} else if (strncasecmp(f.ctype, "image/", 6) != 0 ||
			   strncasecmp(f.ctype, "image/svg", 9) == 0) {
		respond(conn, 415, "text/plain", "Not a supported image\n");
	} else {
		mg_printf(conn,
				  "HTTP/1.1 200 OK\r\n"
				  "Content-Type: %s\r\n"
				  "Content-Length: %zu\r\n"
				  "Cache-Control: public, max-age=86400\r\n"
				  "X-Content-Type-Options: nosniff\r\n"
				  "Content-Security-Policy: default-src 'none'; sandbox\r\n"
				  "\r\n",
				  f.ctype, f.len);
		mg_write(conn, f.data, f.len);
	}
	free(f.data);
	return 1;
}
int Upload_Handler(struct mg_connection* conn, void* cbdata) {
	const char* prefix = cbdata;
	size_t plen = strlen(prefix);
	const struct mg_request_info* ri = mg_get_request_info(conn);

	if (strncmp(ri->local_uri, prefix, plen) != 0)
		return 0;
	if (strcmp(ri->request_method, "PUT") != 0 &&
		strcmp(ri->request_method, "POST") != 0) {
		mg_send_http_error(conn, 405, "Method not allowed");
		return 405;
	}
	const char* tok = ri->local_uri + plen;
	if (!ConsumeUploadToken(tok)) {
		mg_send_http_error(conn, 403, "Invalid upload token");
		return 403;
	}
	long long clen = mg_get_request_info(conn)->content_length;
	const char* ct = mg_get_header(conn, "Content-Type");
	const char* ext = ext_for(ct);

	char filename[17];
	GenerateID_Inline(filename);
	char path[strlen(CDN_ROOT) + 1 + 16 + 1 + 8 + 1];
	snprintf(path, sizeof path, "%s/%s%s", CDN_ROOT, filename, ext);

	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		mg_send_http_error(conn, 500, "open failed");
		return 500;
	}

	char chunk[16384];
	long long total = 0;
	int n;
	while ((n = mg_read(conn, chunk, sizeof chunk)) > 0) {
		total += n;
		if (total > config.maxupload) {
			close(fd);
			unlink(path);
			mg_send_http_error(conn, 413, "Too large");
			return 413;
		}
		for (int off = 0; off < n;) {
			ssize_t w = write(fd, chunk + off, n - off);
			if (w < 0) {
				close(fd);
				unlink(path);
				mg_send_http_error(conn, 500, "write failed");
				return 500;
			}
			off += w;
		}
	}
	close(fd);

	char body[128];
	int blen =
		snprintf(body, sizeof body, "{\"filename\":\"%s%s\"}", filename, ext);
	mg_printf(conn,
			  "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
			  "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
			  blen, body);
	return 201;
}
int InitYAMPHTTP(void) {
	config.http_base_url = "https://yamp.root.sx";
	config.maxupload = 512 * 1024 * 1024ull;
	InsertMainRespOverride("yamp-http", config.http_base_url);
	const char* options[] = {"listening_ports", "5226", NULL};

	struct mg_callbacks callbacks;
	memset(&callbacks, 0, sizeof(callbacks));

	struct mg_context* ctx = mg_start(&callbacks, NULL, options);

	mg_set_request_handler(ctx, "/invite/", Invite_Handler, NULL);
	mg_set_request_handler(ctx, "/cdn/content/", CDN_Handler, "/cdn/content/");
	mg_set_request_handler(ctx, "/cdn/upload/", Upload_Handler, "/cdn/upload/");
	mg_set_request_handler(ctx, "/cdn/proxy", Proxy_Handler, NULL);

	signal(SIGPIPE, SIG_IGN);
	curl_global_init(CURL_GLOBAL_DEFAULT);

	return 0;
}