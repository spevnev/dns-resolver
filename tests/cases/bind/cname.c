#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// cname CNAME result.cname
    RRVec result = {0};
    bool found = resolve("cname." TEST_DOMAIN, TYPE_CNAME, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(found);

    ASSERT(result.length == 1);
    RR *rr = result.data[0];
    ASSERT(rr->type == TYPE_CNAME);
    ASSERT(strcmp(rr->data.domain, "result.cname." TEST_DOMAIN) == 0);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
