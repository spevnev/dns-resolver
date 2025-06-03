#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// a A 1.2.3.4
    RRVec result = {0};
    bool found = resolve("a." TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0, &result);
    ASSERT(found);

    ASSERT(result.length == 1);
    RR *rr = result.data[0];
    ASSERT(rr->type == TYPE_A);
    ASSERT(rr->data.ip4_addr == get_ip4("1.2.3.4"));

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
