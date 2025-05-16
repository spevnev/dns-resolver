#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// cname CNAME result.cname
    RRVec result = {0};
    bool found = resolve(&result, "cname." TEST_DOMAIN, TYPE_CNAME, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(found);

    ASSERT(result.length == 1);
    ResourceRecord *rr = result.data[0];
    ASSERT(rr->type == TYPE_CNAME);
    ASSERT(strcmp(rr->data.domain, "result.cname." TEST_DOMAIN) == 0);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
