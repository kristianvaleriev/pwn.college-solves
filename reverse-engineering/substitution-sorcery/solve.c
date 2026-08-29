#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

const char remap[] = "\x18uM$e&Ay Zz@*\x0e{5-Y>f\x1e)p\x12;\raBgkIh\x08j+,G\x03[.\x7fxR\x19""b\x10""C\x01""E]rW7H\x13!" 
                     "\x1d\x07J\"1K\x01/\x06\'~=oQnd\x1cU^vOqc|\x04\x14\x1b""04D%\n\x16\x1a\\\x15#i\x11""86Nt<?wPs`"
                     "\x1f\x05}TS_\x0cX:L2\x02m(3\tVF\x17""9\x0fl\x0b";

const char goal[] = "TAyQPEhmuteINaGd";

int main(void)
{
    char* payload = calloc(sizeof goal-1,1);

    for (size_t i = 0; i < sizeof goal-1; i++)
    {
        payload[i] = (char)(index(remap, goal[i])-remap);
        printf("%d %c for %c\n", payload[i], payload[i], goal[i]);
    }

    write(1, payload, sizeof goal-1);
}
