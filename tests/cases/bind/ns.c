#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    RRVec result = {0};
    bool found = resolve(TEST_DOMAIN, TYPE_NS, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(found);

    ASSERT(result.length == 2);
    ASSERT(result.data[0]->type == TYPE_NS);
    ASSERT(result.data[1]->type == TYPE_NS);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
