#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// invalid.ttl 2147483648 A 1.2.3.4
    RRVec result = {0};
    bool found = resolve(&result, "invalid.ttl." TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(found);

    ASSERT(result.length == 1);
    ResourceRecord *rr = result.data[0];
    ASSERT(rr->type == TYPE_A);
    ASSERT(rr->data.ip4_address == get_ip4("1.2.3.4"));
    ASSERT(rr->ttl == 0);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
