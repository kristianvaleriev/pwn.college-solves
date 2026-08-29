#ifndef _COLORS_H_
#define _COLORS_H_

#define NO_FORMAT "\033[0m"
#define F_BOLD "\033[1m"
#define F_UNDERLINED "\033[4m"

#define C_SILVER         "\033[38;5;7m"
#define C_AQUA           "\033[38;5;14m"
#define C_MAROON         "\033[38;5;1m"
#define C_YELLOW         "\033[38;5;11m"
#define C_DODGERBLUE2    "\033[38;5;27m"
#define C_RED            "\033[38;5;9m"

static const char* colors[] = {
    "",
    C_SILVER     ,
    C_AQUA       ,
    C_MAROON     ,
    C_YELLOW     ,
    C_DODGERBLUE2,
    C_RED        ,
};
static unsigned long color_idx = 0;

static inline void next_color() {
    color_idx = (color_idx + 1) % (sizeof colors / 8 -1);
}

#endif // !_COLORS_H_
