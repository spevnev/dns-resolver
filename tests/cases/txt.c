#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// txt TXT result
    RRVec result = resolve("txt." TEST_DOMAIN, TYPE_TXT, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    assert(result.length == 1);

    ResourceRecord rr = result.data[0];
    assert(rr.type == TYPE_TXT);

    TXT txt = result.data[0].data.txt;
    assert(txt.length == 1);
    assert(strcmp(txt.data[0], "result") == 0);

    VECTOR_FREE(&result);
    return EXIT_SUCCESS;
}
