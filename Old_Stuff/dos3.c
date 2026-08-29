#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct sockaddr_in saddr = {
    .sin_family = AF_INET,
};

void* connect_to_server(void* _) 
{
    int cl;

START: 

    cl = socket(AF_INET, SOCK_STREAM, 0);
    if (cl < 0) {
        perror("socket");
        return (void*) -1;
    }

    if (connect(cl, (struct sockaddr*) &saddr, sizeof saddr) < 0) {
        perror("connect");
        return (void*) -1;
    }

    sleep(1);
    close(cl);

    goto START;

    return 0;
}

int main(void)
{
    saddr.sin_port = htons(31337);
    if (inet_pton(AF_INET, "10.0.0.2", &saddr.sin_addr) != 1) {
        perror("Inet_ptop");
        exit(1);
    }

    pthread_t thd;

    for (int i = 0; i < 1000; i++)
    {
        pthread_create(&thd, NULL, connect_to_server, 0);
        pthread_detach(thd);
    }

    pause();
}
