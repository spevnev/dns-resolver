#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    RRVec result = {0};
    bool found = resolve(".", TYPE_NS, "1.1.1.1", DNS_PORT, TEST_TIMEOUT, 0, &result);
    ASSERT(found);

    ASSERT(result.length == ROOT_NAMESERVER_COUNT);
    for (uint32_t i = 0; i < result.length; i++) {
        RR *rr = result.data[i];
        ASSERT(rr->type == TYPE_NS);
        ASSERT(strcmp(rr->data.domain + 1, ".root-servers.net") == 0);
    }

    free_rr_vec(result);
    return EXIT_SUCCESS;
}
