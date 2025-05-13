#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// txt TXT result
    RRVec result = resolve("txt." TEST_DOMAIN, TYPE_TXT, NAMESERVER_IP, NAMESERVER_PORT, 1000, 0);
    ASSERT(result.length == 1);

    ResourceRecord rr = result.data[0];
    ASSERT(rr.type == TYPE_TXT);

    TXT txt = result.data[0].data.txt;
    ASSERT(txt.length == 1);
    ASSERT(strcmp(txt.data[0], "result") == 0);

    VECTOR_FREE(&result);
    return EXIT_SUCCESS;
}
