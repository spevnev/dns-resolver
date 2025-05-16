#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    RRVec result = {0};
    bool found = resolve(&result, TEST_DOMAIN, TYPE_NS, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(found);

    ASSERT(result.length == 2);
    ASSERT(result.data[0]->type == TYPE_NS);
    ASSERT(result.data[1]->type == TYPE_NS);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
