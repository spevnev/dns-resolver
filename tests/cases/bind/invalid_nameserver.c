#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    RRVec result = {0};
    bool found = resolve(TEST_DOMAIN, TYPE_A, "1.2.3.4.5", TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
