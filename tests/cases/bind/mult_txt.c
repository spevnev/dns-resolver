#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// mult.txt TXT a b c d e
    RRVec result = {0};
    bool found = resolve("mult.txt." TEST_DOMAIN, TYPE_TXT, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(found);

    ASSERT(result.length == 1);
    RR *rr = result.data[0];
    ASSERT(rr->type == TYPE_TXT);

    TXT txt = rr->data.txt;
    ASSERT(txt.length == 5);
    ASSERT(strcmp(txt.data[0], "a") == 0);
    ASSERT(strcmp(txt.data[1], "b") == 0);
    ASSERT(strcmp(txt.data[2], "c") == 0);
    ASSERT(strcmp(txt.data[3], "d") == 0);
    ASSERT(strcmp(txt.data[4], "e") == 0);

    free_rr_vec(result);
    return EXIT_SUCCESS;
}
