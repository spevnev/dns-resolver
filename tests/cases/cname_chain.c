#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// chain.cname CNAME chain2.cname
    /// chain2.cname CNAME chain1.cname
    /// chain1.cname CNAME result.chain.cname
    /// result.chain.cname A 1.1.1.1
    RRVec result = {0};
    bool found = resolve(&result, "chain.cname." TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(found);

    ASSERT(result.length == 1);
    ResourceRecord *rr = result.data[0];
    ASSERT(rr->type == TYPE_A);
    ASSERT(rr->data.ip4_address == get_ip4("1.1.1.1"));

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
