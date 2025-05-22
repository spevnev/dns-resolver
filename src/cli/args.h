#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>

bool *option_bool(char short_name, const char *name, const char *description, bool show_default, bool default_value);
long *option_long(char short_name, const char *name, const char *description, bool show_default, long default_value);
const char **option_str(char short_name, const char *name, const char *description, bool show_default,
                        const char *default_value);
void print_options(void);

char *parse_args(int argc, char **argv);
bool has_next_arg(void);
char *next_arg(void);

#endif  // ARGS_H
