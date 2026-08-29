#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "vm_code.h"
#include "colors.h"

#define print(str, ...)         printf(str "\n", __VA_ARGS__)
#define print0(str)             printf(str "\n")
#define print_std0(fmt)         printf("%s" "@%#hhx\t " fmt "\n", colors[color_idx], \
                                       register_value[I]-1) 
#define print_std(fmt, ...)     printf("%s" "@%#hhx\t " fmt "\n", colors[color_idx], \
                                       register_value[I]-1, __VA_ARGS__)
uint8_t register_value[] = {
    [A] = 0,
    [B] = 0,
    [C] = 0,
    [D] = 0,
    [S] = 0,
    [I] = 0,
    [F] = 0,
};

char get_reg_name(enum registers reg)
{
    if (register_names[reg] == 0)
        return '0';
    return register_names[reg];
}

char* describe_flags(uint8_t flags)
{
    static char ret[sizeof flag_chars+1];
    
    for (size_t i = 0; i < 6; i++)
    {
        if (flags & (1 << i) && flag_chars[1 << i]) {
            ret[i] = flag_chars[1 << i];
        }
        else 
            ret[i] = '-';
    }

    return ret;
}

void syscall_readcode(struct instruction instr);
void syscall_write(struct instruction instr);
void syscall_readmem(struct instruction instr);
void syscall_sleep(struct instruction instr);
void syscall_open(struct instruction instr);
void syscall_exit(struct instruction instr);

void (*syscall_actions[])(struct instruction) = {
    [READ_CODE] = syscall_readcode,
    [WRITE]     = syscall_write,
    [READ_MEM]  = syscall_readmem,
    [SLEEP]     = syscall_sleep,
    [OPEN]      = syscall_open,
    [EXIT]      = syscall_exit,
};

void interpret_imm(struct instruction instr);
void interpret_add(struct instruction instr);
void interpret_stk(struct instruction instr);
void interpret_stm(struct instruction instr);
void interpret_ldm(struct instruction instr);
void interpret_cmp(struct instruction instr);
void interpret_jmp(struct instruction instr);
void interpret_sys(struct instruction instr);

void (*interpritate_instr[])(struct instruction) = {
    [IMM] = interpret_imm,
    [ADD] = interpret_add,
    [STK] = interpret_stk,
    [STM] = interpret_stm,
    [LDM] = interpret_ldm,
    [CMP] = interpret_cmp,
    [JMP] = interpret_jmp,
    [SYS] = interpret_sys,
};


int main(int argc, char** argv)
{ 
    while (1)
    {
        uint8_t i = register_value[I];
        register_value[I]++;

        opcode_t opcode = vm_code[i].opcode;

        if (!interpritate_instr[opcode]) {
            //print("At iteration %hhu, opcode %hhu is not recognized", i, opcode);
            continue;
        }

        interpritate_instr[opcode](vm_code[i]);
        if (i != register_value[I]-1)
            next_color();
    }
}

void interpret_imm(struct instruction instr)
{
    print_std("IMM %c = %#hhx", register_names[instr.arg1], instr.arg2);
    register_value[instr.arg1] = instr.arg2;

    if (instr.arg1 == C)
        write(2, &instr.arg2, 1);
}

void interpret_add(struct instruction instr)
{
    print_std("ADD %c+= %c", register_names[instr.arg1],
                             register_names[instr.arg2]);
    uint8_t result = register_value[instr.arg1] + register_value[instr.arg2];

    print_std("... %c = %#hhx = %hhu + %hhu = %hhu", 
                                               register_names[instr.arg1], 
                                               result,
                                               register_value[instr.arg1], 
                                               register_value[instr.arg2],
                                               result);

    register_value[instr.arg1] = result;
}

void interpret_stk(struct instruction instr)
{
    print_std("STK (SP = %hhu)", register_value[sp]);

    if (instr.arg2) {
        print_std("... pushing %c (=%#hhx)", register_names[instr.arg2],
                                             register_value[instr.arg2]);
        uint8_t stk_idx = ++register_value[sp];
        memory[stk_idx] = register_value[instr.arg2];
    }

    if (instr.arg1) {
        register_value[instr.arg1] = memory[register_value[sp]];
        print_std("... popping %c (=%#hhx)", register_names[instr.arg1],
                                             register_value[instr.arg1]);
        register_value[sp]--;
    }
}

void interpret_stm(struct instruction instr)
{
    print_std("STM *%c = %c", register_names[instr.arg1],
                              register_names[instr.arg2]);
    print_std("... *%#hhx = %#hhx", register_value[instr.arg1],
                                    register_value[instr.arg2]);

    memory[register_value[instr.arg1]] = register_value[instr.arg2];
}

void interpret_ldm(struct instruction instr)
{
    print_std("LDM %c = *%c", register_names[instr.arg1],
                              register_names[instr.arg2]);
    print_std("... %c = %#hhx (at *%#hhx)", register_names[instr.arg1],
                                            memory[register_value[instr.arg2]],
                                            register_value[instr.arg2]);

    register_value[instr.arg1] = memory[register_value[instr.arg2]];
}

void interpret_cmp(struct instruction instr)
{
    print_std("CMP %c %c", register_names[instr.arg1], 
                           register_names[instr.arg2]);
    print_std("... %#hhx %#hhx", register_value[instr.arg1], 
                                 register_value[instr.arg2]);

    register_value[flags] = 0;
    uint8_t val1 = register_value[instr.arg1];
    uint8_t val2 = register_value[instr.arg2];

    if (val1 < val2) {
        register_value[flags] |= L;
    }
    else if (val1 > val2) {
        register_value[flags] |= G;
    }
    else {
        register_value[flags] |= E;
    }

    if (val1 != val2) {
        register_value[flags] |= N;
    }

    if (!val1 && !val2) {
        register_value[flags] |= Z;
    }

    //print_std("... %hhb", register_value[flags]);
}

void interpret_jmp(struct instruction instr)
{
    print_std("JMP if %s (%#hhx), to %c", describe_flags(instr.arg1),
                                          instr.arg1,
                                          register_names[instr.arg2]);
    print_std("... => %s, to %#hhx", describe_flags(register_value[flags]),
                                     register_value[instr.arg2]);

    if (instr.arg1 & register_value[flags]) {
        print_std("%s ... taken %s", F_UNDERLINED, NO_FORMAT);
        register_value[ip] = register_value[instr.arg2];
    }
    else {
        print_std("%s ... not taken %s", F_UNDERLINED, NO_FORMAT);
    }
}

void syscall_readcode(struct instruction instr) 
{
    int64_t count_1 = (0x100 - register_value[B]) * 3;
    int64_t count = register_value[C];
    
    if (count_1 <= count)
        count = count_1;

    print_std("... fd: %hhu, buf in vmcode at %#hhx, count: %#lx",
              register_value[A], register_value[B], count);

    register_value[instr.arg2] = read(register_value[A], 
                                      &vm_code[register_value[B]],
                                      count);
}

void syscall_write(struct instruction instr)
{
    int64_t count_1 = (0x100 - register_value[B]) * 3;
    int64_t count = register_value[C];
    
    if (count_1 <= count)
        count = count_1;

    print_std("... fd: %hhu, buf in mem at %#hhx, count: %#lx",
              register_value[A], register_value[B], count);

    register_value[instr.arg2] = write(register_value[A], 
                                       memory + register_value[B],  
                                       count);
}

void syscall_readmem(struct instruction instr) 
{
    int64_t count_1 = (0x100 - register_value[B]) * 3;
    int64_t count = register_value[C];
    
    if (count_1 <= count)
        count = count_1;

    print_std("... fd: %hhu, buf in mem at %#hhx, count: %#lx",
              register_value[A], register_value[B], count);

    register_value[instr.arg2] = read(register_value[A], 
                                      memory + register_value[B],
                                      count);
}

void syscall_sleep(struct instruction instr)
{
    print_std("... for %#hhx secs", register_value[A]);
    register_value[instr.arg2] = sleep(register_value[A]);
}

void syscall_open(struct instruction instr)
{
    print_std("... filename: %s, flags: %hhb", &memory[register_value[A]],  
                                               register_value[B]);
    register_value[instr.arg2] = open((char*) memory + register_value[A],
                                      register_value[B]);
}

void syscall_exit(struct instruction instr)
{
    exit(register_value[A]);
}

void interpret_sys(struct instruction instr)
{
    print_std("SYS %#hhx %c", instr.arg1, register_names[instr.arg2]);

    for (uint8_t i = 0; i < syscall_count; i++)
    {
        if (instr.arg1 & 1 << i) {
            print_std("... %s", syscall_map[1 << i]);
            syscall_actions[1 << i](instr);
            print_std("\t... ret %hhu\n", register_value[instr.arg2]);
        }
    }
}
