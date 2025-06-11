#include "common.h"
#include "config.h"
#include "resolve.h"
#include "root_ns.h"

int main(void) {
    RRVec result = {0};
    bool found = resolve(".", TYPE_NS, "1.1.1.1", DNS_PORT, TEST_TIMEOUT, RESOLVE_NO_ROOT_NS | RESOLVE_DISABLE_COOKIE,
                         &result);
    ASSERT(found);

    ASSERT(result.length == sizeof(ROOT_IP_ADDRS) / sizeof(*ROOT_IP_ADDRS));
    for (uint32_t i = 0; i < result.length; i++) {
        RR *rr = result.data[i];
        ASSERT(rr->type == TYPE_NS);
        ASSERT(strcmp(rr->data.domain + 1, ".root-servers.net") == 0);
    }

    free_rr_vec(result);
    return EXIT_SUCCESS;
}
