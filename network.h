#include <stdint.h>
int YAMPSend(int fd, const char *buf, uint32_t len);
int YAMPRecv(int fd, char **payload, uint32_t *len);