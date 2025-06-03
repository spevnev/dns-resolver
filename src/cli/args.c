#include "args.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "error.h"
#include "vector.h"

typedef enum {
    OPT_BOOL,
    OPT_LONG,
    OPT_STRING,
} OptionType;

typedef union {
    bool bool_;
    long long_;
    const char *string;
} OptionValue;

typedef struct {
    bool show_default;
    char short_name;
    const char *name;
    const char *description;
    OptionType type;
    OptionValue default_value;
    OptionValue value;
} Option;

typedef struct {
    uint32_t args_length;
    char **args;
    const char *program;
    uint32_t capacity;
    uint32_t length;
    Option *data;
} Options;

static Options options = {0};

#define SHIFT_ARGS() (assert(argc > 0), argc--, *(argv++))

static void parse_arg(Option *option, char *arg_value) {
    switch (option->type) {
        case OPT_BOOL:
            if (strcasecmp(arg_value, "true") == 0) {
                option->value.bool_ = true;
            } else if (strcasecmp(arg_value, "false") == 0) {
                option->value.bool_ = false;
            } else {
                FATAL("Invalid option value, expected a boolean but found \"%s\"", arg_value);
            }
            break;
        case OPT_LONG: {
            char *end = NULL;
            errno = 0;
            option->value.long_ = strtol(arg_value, &end, 10);
            if (errno == ERANGE) {
                if (option->value.long_ == LONG_MAX) {
                    FATAL("Option value overflow: %s is greater than %ld", arg_value, LONG_MAX);
                }
                if (option->value.long_ == LONG_MIN) {
                    FATAL("Option value underflow: %s is less than %ld", arg_value, LONG_MIN);
                }
            }
            if (*end != '\0') FATAL("Invalid option value, expected a number but found \"%s\"", arg_value);
        } break;
        case OPT_STRING: option->value.string = arg_value; break;
    }
}

static Option *new_option(char short_name, const char *name, const char *description, bool show_default) {
    Option option = {
        .show_default = show_default,
        .short_name = short_name,
        .name = name,
        .description = description,
    };
    VECTOR_PUSH(&options, option);
    return VECTOR_TOP(&options);
}

bool *option_bool(char short_name, const char *name, const char *description, bool show_default, bool default_value) {
    Option *option = new_option(short_name, name, description, show_default);
    option->type = OPT_BOOL;
    option->default_value.bool_ = option->value.bool_ = default_value;
    return &option->value.bool_;
}

long *option_long(char short_name, const char *name, const char *description, bool show_default, long default_value) {
    Option *option = new_option(short_name, name, description, show_default);
    option->type = OPT_LONG;
    option->default_value.long_ = option->value.long_ = default_value;
    return &option->value.long_;
}

const char **option_str(char short_name, const char *name, const char *description, bool show_default,
                        const char *default_value) {
    Option *option = new_option(short_name, name, description, show_default);
    option->type = OPT_STRING;
    option->default_value.string = option->value.string = default_value;
    return &option->value.string;
}

void print_options(void) {
    size_t max_name_len = 0;
    for (uint32_t i = 0; i < options.length; i++) {
        size_t name_length = strlen(options.data[i].name);
        if (name_length > max_name_len) max_name_len = name_length;
    }

    for (uint32_t i = 0; i < options.length; i++) {
        Option *option = &options.data[i];

        if (option->short_name == '\0') {
            printf("     ");
        } else {
            printf("  -%c,", option->short_name);
        }

        printf(" --%-*s  %s", (int) max_name_len, option->name, option->description);

        if (!option->show_default) {
            printf("\n");
            continue;
        }

        printf(", default=");
        switch (option->type) {
            case OPT_BOOL:   printf(option->default_value.bool_ ? "true" : "false"); break;
            case OPT_LONG:   printf("%ld", option->default_value.long_); break;
            case OPT_STRING: printf("%s", option->default_value.string); break;
        }
        printf("\n");
    }
}

char *parse_args(int argc, char **argv) {
    options.args = argv;

    if (argc == 0) FATAL("Invalid arguments");
    char *program = SHIFT_ARGS();

    while (argc > 0) {
        char *arg = SHIFT_ARGS();
        size_t arg_len = strlen(arg);

        if (arg_len >= 2 && arg[0] == '-' && arg[1] != '-') {
            bool found = false;
            for (uint32_t i = 0; i < options.length; i++) {
                Option *option = &options.data[i];
                if (arg[1] != option->short_name) continue;

                // -O=v or -Ov
                if (arg[2] != '\0') {
                    if (arg[2] == '=') arg++;
                    parse_arg(option, arg + 2);
                    found = true;
                    break;
                }

                // -O v
                if (option->type != OPT_BOOL) {
                    if (argc == 0) FATAL("Option \"%s\" requires argument", arg);
                    parse_arg(option, SHIFT_ARGS());
                    found = true;
                    break;
                }

                if (argc > 0 && (strcasecmp(argv[0], "false") == 0 || strcasecmp(argv[0], "true") == 0)) {
                    // -O false or -O true
                    parse_arg(option, SHIFT_ARGS());
                } else {
                    // -O
                    option->value.bool_ = true;
                }
                found = true;
                break;
            }
            if (!found) FATAL("Invalid option \"%s\"", arg);
        } else if (arg_len >= 3 && arg[0] == '-' && arg[1] == '-') {
            char *arg_name = arg + 2;
            size_t arg_name_len = arg_len - 2;
            bool found = false;
            for (uint32_t i = 0; i < options.length; i++) {
                Option *option = &options.data[i];
                size_t name_len = strlen(option->name);

                // --no-opt
                if (option->type == OPT_BOOL && arg_name_len > 3 && strncmp(arg_name, "no-", 3) == 0
                    && strcmp(arg_name + 3, option->name) == 0) {
                    option->value.bool_ = false;
                    found = true;
                    break;
                }

                // Argument does not match option name.
                if (arg_name_len < name_len || strncmp(arg_name, option->name, name_len) != 0) continue;

                // --opt=v
                if (arg_name[name_len] == '=') {
                    parse_arg(option, arg_name + name_len + 1);
                    found = true;
                    break;
                }

                // Different option with same prefix or invalid option.
                if (arg_name[name_len] != '\0') continue;

                // --opt v
                if (option->type != OPT_BOOL) {
                    if (argc == 0) FATAL("Option \"%s\" requires argument", arg);
                    parse_arg(option, SHIFT_ARGS());
                    found = true;
                    break;
                }

                if (argc > 0 && (strcasecmp(argv[0], "false") == 0 || strcasecmp(argv[0], "true") == 0)) {
                    // --opt false or --opt true
                    parse_arg(option, SHIFT_ARGS());
                } else {
                    // --opt
                    option->value.bool_ = true;
                }
                found = true;
                break;
            }
            if (!found) FATAL("Invalid option \"%s\"", arg);
        } else {
            // Move all non-option arguments towards beginning of argv.
            options.args[options.args_length++] = arg;
        }
    }

    return program;
}

bool has_next_arg(void) { return options.args_length > 0; }

char *next_arg(void) {
    assert(options.args_length > 0);
    options.args_length--;
    return *(options.args++);
}
