#include <string.h>

int read(int fd, char* buf, int n)
{
    memmove(buf, "test\n", 5);
	return n;
}
