#ifndef __PROCESS_H__
#define __PROCESS_H__

#define DEF_COUNT 4096

int process(char*);

char* proc_read(char*, size_t);
#define pread(buf) proc_read(buf, DEF_COUNT)

int readuntil(char* str);
char* readline(char* buf, size_t count);
#define preadline(buf) readline(buf, DEF_COUNT)

int proc_write(void* buf, size_t count);

#endif
