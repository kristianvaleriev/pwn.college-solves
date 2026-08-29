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
    IMM = 0x40,
    ADD = 0x80,
    STK = 0x20,
    STM = 0x10,
    LDM = 0x2,
    CMP = 0x1,
    JMP = 0x8,
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
    OPEN        = 0x10,
    READ_CODE   = 0x20,
    READ_MEM    = 0x4, 
    WRITE       = 0x1,
    SLEEP       = 0x2, 
    EXIT        = 0x8,
};

static const char* syscall_map[] = {
    [READ_CODE] = "read code",
    [WRITE]     = "write",
    [READ_MEM]  = "read mem",
    [SLEEP]     = "sleep",
    [OPEN]      = "open",
    [EXIT]      = "exit",
};

static const uint8_t syscall_count = 6;

enum flags {
    L = 8,
    G = 4, 
    E = 2,
    N = 1,
    Z = 16,
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
    A = 0x40,
    B = 0x8,
    C = 0x4,
    D = 0x1,
    S = 0x10,
    I = 0x20,
    F = 0x2,
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


#endif
