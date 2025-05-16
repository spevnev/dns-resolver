#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// aaaa AAAA 1:2:3:4::
    RRVec result = {0};
    bool found = resolve(&result, "aaaa." TEST_DOMAIN, TYPE_AAAA, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(found);

    ASSERT(result.length == 1);
    ResourceRecord *rr = result.data[0];
    ASSERT(rr->type == TYPE_AAAA);

    struct in6_addr ip = get_ip6("1:2:3:4::");
    ASSERT(memcmp(&rr->data.ip6_address, &ip, sizeof(struct in6_addr)) == 0);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
