#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <elf.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

#define MAGIC "cIMG"
#define COLOR_PIXEL_FMT     "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"
#define COLOR_PIXEL_START   "[38;2;"
#define COLOR_PIXEL_END     "[0m"
#define COLOR_PIXEL_DELIM   "\x1b"

typedef unsigned char uchar;
typedef short version_t;

void* mapped_elf;
struct Elf_pointers {
    Elf64_Ehdr* ehdr;
    Elf64_Shdr* shdr;
    char* strtab;
};


void header_gen(int fd, version_t version, uchar size)
{
    write(fd, MAGIC, sizeof MAGIC);
    write(fd, &version, sizeof version);

    write(fd, &(uchar) {1}, size);
    write(fd, &(uchar) {1}, size);
}

void header_set_resolution(int fd, void* width, void* height, uchar size)
{
    lseek(fd, sizeof MAGIC + sizeof (version_t), SEEK_SET);
    write(fd, width, size);
    write(fd, height, size);
}


int main(int argc, char** argv)
{
    if (argc != 2) {
        fputs("./prog [ELF File]\n", stderr);
        exit(1);
    }

    int elf_fd = open(argv[1], O_RDONLY);
    if (elf_fd < 0) {
        perror("open in main:");
        exit(2);
    }

    size_t file_len = lseek(elf_fd, 0, SEEK_END);
    lseek(elf_fd, 0, SEEK_SET);
    printf("File length: %zu\n", file_len);

    mapped_elf = mmap(NULL, file_len, PROT_READ, MAP_PRIVATE, elf_fd, 0);
    if (mapped_elf == MAP_FAILED) {
        perror("mmap in main:");
        exit(3);
    }

    struct Elf_pointers elfp;
    elfp.ehdr = mapped_elf;
    if (elfp.ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        elfp.ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        elfp.ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        elfp.ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        fputs("File given is not elf!", stderr);
        exit(4);
    }

    elfp.shdr = mapped_elf + elfp.ehdr->e_shoff;
    printf("Number of sections: %hu\n", elfp.ehdr->e_shnum);
    if (elfp.ehdr->e_shstrndx == SHN_UNDEF) {
        puts("ELF doesnt have a string table!");
        exit(6);
    }

    elfp.strtab = mapped_elf + elfp.shdr[elfp.ehdr->e_shstrndx].sh_offset;
    Elf64_Shdr* data_sec = NULL;
    for (size_t i = 0; i < elfp.ehdr->e_shnum; i++) 
    {
        if (elfp.shdr[i].sh_type == SHT_PROGBITS &&
            !strncmp(elfp.strtab + elfp.shdr[i].sh_name, ".data\0", 6)) {
            data_sec = &elfp.shdr[i];
            break;
        }
    }
    if (!data_sec) {
        puts("ELF doesn't have a data section!");
        exit(5);
    }

    char* data = calloc(data_sec->sh_size+1, 1);
    memcpy(data, mapped_elf + data_sec->sh_offset, data_sec->sh_size);
    while(strncmp(data, COLOR_PIXEL_START, sizeof COLOR_PIXEL_START - 1)) 
        data++;

    /*
    char* last_byte = data;
    do {
        last_byte = strrchr(last_byte, '[');
        if (last_byte[1] == '0' && last_byte[2] == 'm')
            break;
    } while(1);
    size_t pixel_len = last_byte - data;
    */
    // 
    // End of ELF handling
    //


    int out_fd = open("file.cimg", O_RDWR | O_CREAT | O_TRUNC, 0755);
    
    // Directives
    write(out_fd, &(unsigned) {1}, 4);
    write(out_fd, &(unsigned short){20169}, 2);

    size_t pixel_count = 0;
    char* result = strtok(data, COLOR_PIXEL_DELIM);
    do {
        if (strncmp(result, COLOR_PIXEL_START, sizeof COLOR_PIXEL_START - 1))
            continue;
        result += sizeof COLOR_PIXEL_START - 1;
        printf("%s @: %p = ", result, result);

        unsigned char val;
        unsigned char ascii_val = result[strlen(result)-1];
        for (int i = 0; i < 3; i++) 
        {
            val = strtol(result, NULL, 10);
            result = strchr(result, ';') + 1;
            printf("%u ", val);

            write(out_fd, &val, sizeof val);
        }
        printf("%c(%d)\n", ascii_val, ascii_val);
        write(out_fd, &ascii_val, sizeof ascii_val);

        pixel_count++;
    } while ((result = strtok(NULL, COLOR_PIXEL_DELIM)));

    printf("\n\nprint count: %zu\n", pixel_count);

    header_set_resolution(out_fd, &(uchar) {pixel_count / 12}, &(uchar) {12}, 
                          sizeof (uchar));
}
