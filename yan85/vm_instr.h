#ifndef _VM_INSTR_H_
#define _VM_INSTR_H_

#define MEMSIZE 388

#include <stdint.h>

typedef uint8_t opcode_t;
typedef uint8_t arg_t;

struct instruction {
    opcode_t  opcode;
    arg_t     arg1;
    arg_t     arg2;
};

enum opcodes {
    IMM = 0x4,
    ADD = 0x2,
    STK = 0x8,
    STM = 0x20,
    LDM = 0x80,
    CMP = 0x40,
    JMP = 0x10,
    SYS = 0x1,
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
    OPEN        = 0x10,
    READ_CODE   = 0x0,
    READ_MEM    = 0x1, 
    WRITE       = 0x20,
    SLEEP       = 0x8, 
    EXIT        = 0x4,
};

static const char* syscall_map[] = {
    [READ_CODE] = "read code",
    [WRITE]     = "write",
    [READ_MEM]  = "read mem",
    [SLEEP]     = "sleep",
    [OPEN]      = "open",
    [EXIT]      = "exit",
};

static const char syscall_names_map[] = {
    [ 0 ] = 0,
    ['O'] = OPEN,
    ['R'] = READ_MEM,
    ['W'] = WRITE,
    ['E'] = EXIT,
};

static const uint8_t syscall_count = 6;

enum flags {
    L = 1,
    G = 16, 
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
    A = 0x4,
    B = 0x40,
    C = 0x10,
    D = 0x20,
    S = 0x1,
    I = 0x0,
    F = 0x0,
};
static enum registers ip = I;
static enum registers sp = S;
static enum registers flags = F;

static const char register_names[] = {
    [A] = 'A',
    [B] = 'B',
    [C] = 'C',
    [D] = 'D',
    [S] = 'S',
    [I] = 'I',
    [F] = 'F',
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
};


#endif
