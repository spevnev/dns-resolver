#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// mult.a A 1.1.1.1
    /// mult.a A 2.2.2.2
    /// mult.a A 3.3.3.3
    RRVec result = {0};
    bool found = resolve(&result, "mult.a." TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(found);
    ASSERT(result.length == 3);

    bool found1 = false;
    bool found2 = false;
    bool found3 = false;
    for (uint32_t i = 0; i < result.length; i++) {
        ResourceRecord *rr = result.data[i];
        ASSERT(rr->type == TYPE_A);
        if (rr->data.ip4_address == get_ip4("1.1.1.1")) found1 = true;
        if (rr->data.ip4_address == get_ip4("2.2.2.2")) found2 = true;
        if (rr->data.ip4_address == get_ip4("3.3.3.3")) found3 = true;
    }
    ASSERT(found1 && found2 && found3);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
