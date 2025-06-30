#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// nsec NSEC next (A DS TYPE1000)
    RRVec result = {0};
    bool found = resolve("nsec." TEST_DOMAIN, TYPE_NSEC, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(found);

    ASSERT(result.length == 1);
    RR *rr = result.data[0];
    ASSERT(rr->type == TYPE_NSEC);
    ASSERT(strcmp(rr->data.nsec.next_domain, "next." TEST_DOMAIN) == 0);
    ASSERT(rr->data.nsec.types.length == 3);
    ASSERT(rr->data.nsec.types.data[0] == TYPE_A);
    ASSERT(rr->data.nsec.types.data[1] == TYPE_DS);
    ASSERT(rr->data.nsec.types.data[2] == 1000);

    free_rr_vec(result);
    return EXIT_SUCCESS;
}
