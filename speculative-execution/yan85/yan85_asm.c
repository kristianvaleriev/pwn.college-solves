#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "vm_instr.h"
#include "colors.h"

#define print(str, ...)         ;//printf(str "\n", __VA_ARGS__)
#define print0(str)             ;//printf(str "\n")
#define print_std0(fmt)         ;//printf("%s" "@%#hhx\t " fmt "\n", colors[color_idx], register_value[I]) 
#define print_std(fmt, ...)     ;//printf("%s" "@%#hhx\t " fmt "\n", colors[color_idx], register_value[I], __VA_ARGS__)

char memory[MEMSIZE];

uint8_t register_value[] = {
    [A] = 0,
    [B] = 0,
    [C] = 0,
    [D] = 0,
    [S] = 0,
    [I] = 0,
    [F] = 0,
    [DSR] = 0,
};

size_t output_idx = 0;

void (*syscall_actions[])(arg_t, arg_t) = {
//    [READ_CODE] = syscall_readcode,
    [WRITE]     = syscall_write,
    [READ_MEM]  = syscall_readmem,
    [SLEEP]     = syscall_sleep,
    [OPEN]      = syscall_open,
    [EXIT]      = syscall_exit,
};

void (*interpritate_instrs[])(arg_t,arg_t) = {
    [IMM] = interpret_imm,
    [ADD] = interpret_add,
    [STK] = interpret_stk,
    [STM] = interpret_stm,
    [LDM] = interpret_ldm,
    [CMP] = interpret_cmp,
    [JMP] = interpret_jmp,
    [SYS] = interpret_sys,
};

void imm(arg_t reg1, arg_t val) {
    interpret_imm(names_to_reg[reg1], val);
}
void add(arg_t reg1, arg_t reg2) {
    interpret_add(names_to_reg[reg1], names_to_reg[reg2]);
}
void stk(char reg1, char reg2) {
    interpret_stk(names_to_reg[reg1], names_to_reg[reg2]);
}
void stm(char reg1, char reg2) {
    interpret_stm(names_to_reg[reg1], names_to_reg[reg2]);
}
void ldm(char reg1, char reg2) {
    interpret_ldm(names_to_reg[reg1], names_to_reg[reg2]);
}
void cmp(char reg1, char reg2) {
    interpret_cmp(names_to_reg[reg1], names_to_reg[reg2]);
}
void jmp(arg_t val, char reg1) {
    interpret_jmp(val, names_to_reg[reg1]);
}

void sys(arg_t reg, char* syscalls, size_t size)
{
    uint8_t flags = 0;
    for (uint8_t i = 0; i < size; i++) 
    {
        flags |= syscall_names_map[syscalls[i]];
    }

    interpret_sys(flags, names_to_reg[reg]);
}

void yan_write(char reg) {
    interpret_sys(WRITE, names_to_reg[reg]);
}
void yan_readmem(arg_t reg) {
    interpret_sys(READ_MEM, names_to_reg[reg]);
}
void yan_sleep(char reg) {
    interpret_sys(SLEEP, names_to_reg[reg]);
}
void yan_open(char reg) {
    interpret_sys(OPEN, names_to_reg[reg]);
}
void yan_exit(char reg) {
    interpret_sys(EXIT, names_to_reg[reg]);
}

void send_code(int fd, char* pad) 
{
    char buf[0xFF * 2] = {0};
    if (pad != 0) {
        size_t len = strlen(pad);
        memcpy(buf, pad, len);
        memcpy(buf+len, output, output_idx * 3);
        write(fd, buf, len + (output_idx+1) * 3);
    }
    else 
        write(fd, output, (output_idx+1) * 3);
}

void set_output_idx(arg_t val) {
    output_idx = val;
}

size_t set_output(opcode_t opcode, arg_t arg1, arg_t arg2)
{
    output[output_idx].opcode = opcode;
    output[output_idx].arg1 = arg1;
    output[output_idx].arg2 = arg2;

    return ++output_idx;
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

void interpret_imm(arg_t arg1, arg_t arg2)
{
    print_std("IMM %c = %#hhx", register_names[arg1], arg2);
    register_value[arg1] = arg2;

    set_output(IMM, arg1, arg2);
}

void interpret_add(arg_t arg1, arg_t arg2)
{
    print_std("ADD %c+= %c", register_names[arg1],
                             register_names[arg2]);
    uint8_t result = register_value[arg1] + register_value[arg2];

    print_std("... %c = %#hhx = %hhu + %hhu = %hhu", 
                                               register_names[arg1], 
                                               result,
                                               register_value[arg1], 
                                               register_value[arg2],
                                               result);

    register_value[arg1] = result;

    set_output(ADD, arg1, arg2);
}

void interpret_stk(arg_t arg1, arg_t arg2)
{
    print_std("STK (SP = %hhu)", register_value[spr]);

    if (arg2) {
        print_std("... pushing %c (=%#hhx)", register_names[arg2],
                                             register_value[arg2]);
        uint8_t stk_idx = ++register_value[spr];
        memory[stk_idx] = register_value[arg2];
    }

    if (arg1) {
        register_value[arg1] = memory[register_value[spr]];
        print_std("... popping %c (=%#hhx)", register_names[arg1],
                                             register_value[arg1]);
        register_value[spr]--;
    }
    
    set_output(STK, arg1, arg2);
}

void interpret_stm(arg_t arg1, arg_t arg2)
{
    print_std("STM *%c = %c", register_names[arg1],
                              register_names[arg2]);
    print_std("... *%#hhx = %#hhx", register_value[arg1],
                                    register_value[arg2]);

    memory[register_value[arg1]] = register_value[arg2];

    set_output(STM, arg1, arg2);
}

void interpret_ldm(arg_t arg1, arg_t arg2)
{
    print_std("LDM %c = *%c", register_names[arg1],
                              register_names[arg2]);
    print_std("... %c = %#hhx (at *%#hhx)", register_names[arg1],
                                            memory[register_value[arg2]],
                                            register_value[arg2]);

    register_value[arg1] = memory[register_value[arg2]];

    set_output(LDM, arg1, arg2);
}

void interpret_cmp(arg_t arg1, arg_t arg2)
{
    print_std("CMP %c %c", register_names[arg1], 
                           register_names[arg2]);
    print_std("... %#hhx %#hhx", register_value[arg1], 
                                 register_value[arg2]);

    register_value[flags] = 0;
    uint8_t val1 = register_value[arg1];
    uint8_t val2 = register_value[arg2];

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

    set_output(CMP, arg1, arg2);
}

void interpret_jmp(arg_t arg1, arg_t arg2)
{
    print_std("JMP if %s (%#hhx), to %c", describe_flags(arg1),
                                          arg1,
                                          register_names[arg2]);
    print_std("... => %s, to %#hhx", describe_flags(register_value[flags]),
                                     register_value[arg2]);

    if (arg1 & register_value[flags]) {
        print_std("%s ... taken %s", F_UNDERLINED, NO_FORMAT);
        register_value[ipr] = register_value[arg2];
    }
    else {
        print_std("%s ... not taken %s", F_UNDERLINED, NO_FORMAT);
    }

    set_output(JMP, arg1, arg2);
}

/*
void syscall_readcode(arg_t arg1, arg_t arg2) 
{
    int64_t count_1 = (0x100 - register_value[B]) * 3;
    int64_t count = register_value[C];
    
    if (count_1 <= count)
        count = count_1;

    print_std("... fd: %hhu, buf in vmcode at %#hhx, count: %#lx",
              register_value[A], register_value[B], count);

    register_value[arg2] = read(register_value[A], 
                                      &vm_code[register_value[B]],
                                      count);
}
*/

void syscall_write(arg_t arg1, arg_t arg2)
{
    int64_t count = register_value[C];
    /*
    int64_t count_1 = (0x100 - register_value[B]) * 3;
    
    if (count_1 <= count)
        count = count_1;
    */

    print_std("... fd: %hhu, buf in mem at %#hhx, count: %#lx",
              register_value[A], register_value[B], count);

    register_value[arg2] = count;
}

void syscall_readmem(arg_t arg1, arg_t arg2) 
{
    int64_t count_1 = (0x100 - register_value[B]) * 3;
    int64_t count = register_value[C];
    
    if (count_1 <= count)
        count = count_1;

    print_std("... fd: %hhu, buf in mem at %#hhx, count: %#lx",
              register_value[A], register_value[B], count);

    /*
    register_value[arg2] = read(register_value[A], 
                                memory + register_value[B],
                                count);
    */
    register_value[arg2] = count;
}

void syscall_sleep(arg_t arg1, arg_t arg2)
{
    print_std("... for %#hhx secs", register_value[A]);
    register_value[arg2] = sleep(register_value[A]);
}

void syscall_open(arg_t arg1, arg_t arg2)
{
    print_std("... filename: %s, flags: %hhb", &memory[register_value[A]],  
                                               register_value[B]);
    register_value[arg2] = 0;
}

void syscall_exit(arg_t arg1, arg_t arg2)
{
    if (arg2)
        set_output_idx(0);
    return;
}

void interpret_sys(arg_t arg1, arg_t arg2)
{
    print_std("SYS %#hhx %c", arg1, register_names[arg2]);
    set_output(SYS, arg1, arg2);

    for (uint8_t i = 0; i < syscall_count; i++)
    {
        if (arg1 & 1 << i) {
            print_std("... %s", syscall_map[1 << i]);
            syscall_actions[1 << i](arg1, arg2);
            print_std("\t... ret %hhu\n", register_value[arg2]);
        }
    }
}
