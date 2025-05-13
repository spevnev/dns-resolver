#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// cname CNAME result.cname
    RRVec result = resolve("cname." TEST_DOMAIN, TYPE_CNAME, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(result.length == 1);

    ResourceRecord rr = result.data[0];
    ASSERT(rr.type == TYPE_CNAME);
    ASSERT(strcmp(result.data[0].data.domain, "result.cname." TEST_DOMAIN) == 0);

    VECTOR_FREE(&result);
    return EXIT_SUCCESS;
}
