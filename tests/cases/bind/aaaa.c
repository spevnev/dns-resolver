#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// aaaa AAAA 1:2:3:4::
    RRVec result = {0};
    bool found = resolve("aaaa." TEST_DOMAIN, TYPE_AAAA, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(found);

    ASSERT(result.length == 1);
    RR *rr = result.data[0];
    ASSERT(rr->type == TYPE_AAAA);

    struct in6_addr addr = get_ip6("1:2:3:4::");
    ASSERT(memcmp(&rr->data.ip6_addr, &addr, sizeof(struct in6_addr)) == 0);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
