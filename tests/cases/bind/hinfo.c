#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// hinfo HINFO cpu os
    RRVec result = {0};
    bool found = resolve("hinfo." TEST_DOMAIN, TYPE_HINFO, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0, &result);
    ASSERT(found);

    ASSERT(result.length == 1);
    RR *rr = result.data[0];
    ASSERT(rr->type == TYPE_HINFO);
    ASSERT(strcmp(rr->data.hinfo.cpu, "cpu") == 0);
    ASSERT(strcmp(rr->data.hinfo.os, "os") == 0);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
