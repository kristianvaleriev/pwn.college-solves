#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>


#define FNAME = "file"
#define FILE "/home/hacker/dir/file"

int main(int argc, char** argv)
{
    execl(argv[1], argv[1], FILE, NULL);
}
