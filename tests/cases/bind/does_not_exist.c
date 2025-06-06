#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    RRVec result = {0};
    bool found = resolve("does.not.exist." TEST_DOMAIN, TYPE_A, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(found);
    ASSERT(result.length == 0);

    free_rr_vec(result);
    return EXIT_SUCCESS;
}
