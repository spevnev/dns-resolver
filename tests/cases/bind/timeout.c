#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    RRVec result = {0};
    bool found = resolve(TEST_DOMAIN, TYPE_A, "127.0.0.2", 65535, 1, TEST_FLAGS, &result);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
