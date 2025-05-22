#ifndef ERROR_H
#define ERROR_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FATAL(...)                    \
    do {                              \
        fprintf(stderr, "[ERROR] ");  \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, ".\n");       \
        exit(EXIT_FAILURE);           \
    } while (0)

#define FATAL_ERRNO(function) FATAL("Error in " function ": %s", strerror(errno))
#define OUT_OF_MEMORY() FATAL("Process ran out of memory");

#endif  // ERROR_H
