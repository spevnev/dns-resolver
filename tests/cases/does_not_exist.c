#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    RRVec result = {0};
    bool found = resolve(&result, "does.not.exist." TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(found);
    ASSERT(result.length == 0);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
