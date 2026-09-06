#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
int YAMPSend(int fd, void *payload, uint32_t size) {
	uint32_t NlSize = htonl(size);
	send(fd, &NlSize, 4, 0);
	send(fd, payload, size, 0);
}
int YAMPRecv(int fd, char **payload, uint32_t *len) {
	if (recv(fd, len, 4, 0) > 0) {
		*len = ntohl(*len);
		*payload = malloc(*len+1);
		int totalread=0;
		while (totalread < *len) {
			int r = recv(fd, *payload + totalread, *len, 0);
			totalread += r;
		}
		(*payload)[*len]='\0';
		return 1;
	}
	return 0; // server got busted by a segfault :sob:
}