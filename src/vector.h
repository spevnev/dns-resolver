#ifndef VECTOR_H
#define VECTOR_H

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include "error.h"

#define INITIAL_VECTOR_CAPACITY 16

#define VECTOR_TYPEDEF(name, type) \
    typedef struct {               \
        uint32_t capacity;         \
        uint32_t length;           \
        type *data;                \
    } name

#define VECTOR_PUSH(vec, element)                                                                   \
    do {                                                                                            \
        if ((vec)->length >= (vec)->capacity) {                                                     \
            (vec)->capacity = (vec)->capacity == 0 ? INITIAL_VECTOR_CAPACITY : (vec)->capacity * 2; \
            (vec)->data = realloc((vec)->data, (vec)->capacity * sizeof(*(vec)->data));             \
            if ((vec)->data == NULL) OUT_OF_MEMORY();                                               \
        }                                                                                           \
        (vec)->data[(vec)->length++] = (element);                                                   \
    } while (0)

#define VECTOR_TOP(vec) (assert((vec)->length > 0), &(vec)->data[(vec)->length - 1])
#define VECTOR_POP(vec) (assert((vec)->length > 0), (vec)->data[--(vec)->length])

#define VECTOR_FREE(vec) free((vec)->data)

VECTOR_TYPEDEF(CstrVec, const char *);

#endif  // VECTOR_H
