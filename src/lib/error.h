#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>
#include <stdlib.h>

#define FATAL(...)                    \
    do {                              \
        fprintf(stderr, "[ERROR] ");  \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, ".\n");       \
        exit(EXIT_FAILURE);           \
    } while (0)

#define OUT_OF_MEMORY() FATAL("Process ran out of memory");

#endif  // ERROR_H
