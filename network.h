#include <stdint.h>
#include <openssl/ssl.h>
int YAMPSend(int fd, const char *buf, uint32_t len);
int YAMPRecv(int fd, char **payload, uint32_t *len);
int TLSYAMPSend(SSL* fd, void *payload, uint32_t size);
int TLSYAMPRecv(SSL* fd, char **payload, uint32_t *len);