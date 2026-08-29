#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PAYLOAD "FLAG:10.0.0.1:31337"

int soc = -1;

void* send_to_server(void* _) 
{
	struct sockaddr* saddr = (struct sockaddr*) _;
    if (sendto(soc, PAYLOAD, sizeof PAYLOAD, 0, saddr, sizeof *saddr) < 0) {
        perror("connect");
        return (void*) -1;
    }
	free(_);
    return 0;
}

int main(void)
{
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc < 0) {
        perror("socket");
		exit(1);
    }

	struct sockaddr_in mine = {
		.sin_port = htons(31337),
		.sin_addr = INADDR_ANY,
		.sin_family = AF_INET,
		.sin_zero = {0},
	};

	if (bind(soc, (struct sockaddr*) &mine, sizeof mine) < 0) {
		perror("bind");
		exit(1);
	}

	struct sockaddr_in saddr = {
		.sin_family = AF_INET,
	};
    if (inet_pton(AF_INET, "10.0.0.2", &saddr.sin_addr) != 1) {
        perror("inet_ptop");
        exit(1);
    }

    pthread_t thd;
    for (int i = 1; i < (1 << 16); i++)
    {
		struct sockaddr_in* arg = malloc(sizeof *arg);
		*arg = saddr;
		arg->sin_port = htons(i);

        pthread_create(&thd, NULL, send_to_server, (void*) arg);
        pthread_detach(thd);
    }

	char buf[1024];
	ssize_t rc;
	while ((rc = recvfrom(soc, buf, sizeof buf, MSG_DONTWAIT, NULL, NULL)) <= 0);
	buf[rc] = '\0';

	printf("OUT: %s| %d\n", buf, buf[0]);
}
