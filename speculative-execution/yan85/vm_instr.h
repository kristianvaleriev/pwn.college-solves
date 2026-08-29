#ifndef _VM_INSTR_H_
#define _VM_INSTR_H_

#define MEMSIZE 388

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t opcode_t;
typedef uint8_t arg_t;

struct instruction {
    opcode_t  opcode;
    arg_t     arg1;
    arg_t     arg2;
};

enum opcodes {
    IMM = 0x20,
    ADD = 0x1,
    STK = 0x40,
    STM = 0x8,
    LDM = 0x80,
    CMP = 0x2,
    JMP = 0x10,
    SYS = 0x4,
};

static const char* opcode_names[] = {
   [IMM] = "imm",
   [ADD] = "add",
   [SYS] = "sys",
   [STK] = "stk",
   [STM] = "stm",
   [LDM] = "ldm",
   [CMP] = "cmp",
   [JMP] = "jmp",
};

enum syscall_nums {
    OPEN        = 0x8,
    READ_CODE   = 0x0,
    READ_MEM    = 0x20, 
    WRITE       = 0x0,
    SLEEP       = 0x0, 
    EXIT        = 0x10,
    EXEC        = 0x40,
};

static const char* syscall_map[] = {
    [READ_CODE] = "read code",
    [WRITE]     = "write",
    [READ_MEM]  = "read mem",
    [SLEEP]     = "sleep",
    [OPEN]      = "open",
    [EXIT]      = "exit",
    [EXEC]      = "exec",
};

static const char syscall_names_map[] = {
    [ 0 ] = 0,
    ['O'] = OPEN,
    ['R'] = READ_MEM,
    ['W'] = WRITE,
    ['E'] = EXIT,
    ['X'] = EXEC,
};

static const uint8_t syscall_count = 6;

enum flags {
    L = 1,
    G = 12, 
    E = 4,
    N = 8,
    Z = 2,
};

static const char flag_chars[] = {
    [0] = '*',
    [L] = 'L',
    [G] = 'G',
    [E] = 'E',
    [N] = 'N',
    [Z] = 'Z',
};

enum registers {
    A = 0x20,
    B = 0x40,
    C = 0x8,
    D = 0x2,
    S = 0x4,
    I = 0x1,
    F = 0x10,
    DSR = 0x80,
};
static enum registers ipr = I;
static enum registers spr = S;
static enum registers flags = F;

static const char register_names[] = {
    [A] = 'A',
    [B] = 'B',
    [C] = 'C',
    [D] = 'D',
    [S] = 'S',
    [I] = 'I',
    [F] = 'F',
    [DSR] = 'Z',
};

static const arg_t names_to_reg[] = {
    [ 0 ] = 0,
    ['A'] = A,
    ['B'] = B,
    ['C'] = C,
    ['D'] = D,
    ['S'] = S,
    ['I'] = I,
    ['F'] = F,
    ['Z'] = DSR,
};

void syscall_readcode(arg_t arg1, arg_t arg2);
void syscall_write(arg_t arg1, arg_t arg2);
void syscall_readmem(arg_t arg1, arg_t arg2);
void syscall_sleep(arg_t arg1, arg_t arg2);
void syscall_open(arg_t arg1, arg_t arg2);
void syscall_exit(arg_t arg1, arg_t arg2);

void interpret_imm(arg_t arg1, arg_t arg2);
void interpret_add(arg_t arg1, arg_t arg2);
void interpret_stk(arg_t arg1, arg_t arg2);
void interpret_stm(arg_t arg1, arg_t arg2);
void interpret_ldm(arg_t arg1, arg_t arg2);
void interpret_cmp(arg_t arg1, arg_t arg2);
void interpret_jmp(arg_t arg1, arg_t arg2);
void interpret_sys(arg_t arg1, arg_t arg2);

void set_output_idx(arg_t val);

extern struct instruction* output;

#endif
