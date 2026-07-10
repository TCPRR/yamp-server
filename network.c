#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
int YAMPSend(int fd, const char *buf, uint32_t len) {
	uint32_t netlen = htonl(len);
	if (send(fd, &netlen, sizeof(netlen), 0) != sizeof(netlen))
		return -1;
	send(fd, buf, len, 0);

	return 0;
}
