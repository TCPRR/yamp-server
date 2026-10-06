#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#define YAMP_MAX_PAYLOAD (2 * 1024 * 1024) // 2 mbs, yamp is mostly text-only
int YAMPSend(int fd, void *payload, uint32_t size) {
	uint32_t NlSize = htonl(size);
	send(fd, &NlSize, 4, 0);
	return send(fd, payload, size, 0);
}
int YAMPRecv(int fd, char **payload, uint32_t *len) {
	if (recv(fd, len, 4, 0) > 0) {
		*len = ntohl(*len);
		if(*len>YAMP_MAX_PAYLOAD){
			return 0; // not slick
		}
		*payload = malloc(*len+1);
		int totalread=0;
		while (totalread < *len) {
			int r = recv(fd, *payload + totalread, *len, 0);
			totalread += r;
		}
		(*payload)[*len]='\0';
		return 1;
	}
	return 0;
}
int TLSYAMPSend(SSL* fd, void *payload, uint32_t size) {
	uint32_t NlSize = htonl(size);
	SSL_write(fd, &NlSize, 4);
	return SSL_write(fd, payload, size);
}
int TLSYAMPRecv(SSL* fd, char **payload, uint32_t *len) {
	if (SSL_read(fd, len, 4) > 0) {
		*len = ntohl(*len);
		*payload = malloc(*len+1);
		int totalread=0;
		while (totalread < *len) {
			int r = SSL_read(fd, *payload + totalread, *len);
			totalread += r;
		}
		(*payload)[*len]='\0';
		return 1;
	}
	return 0;
}
