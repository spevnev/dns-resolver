#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// a A 1.2.3.4
    RRVec result = resolve("a." TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    assert(result.length == 1);

    ResourceRecord rr = result.data[0];
    assert(rr.type == TYPE_A);
    assert(result.data[0].data.ip4_address == get_ip4("1.2.3.4"));

    VECTOR_FREE(&result);
    return EXIT_SUCCESS;
}
