#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    /// any A 1.1.1.1
    /// any A 2.2.2.2
    /// any TXT result
    RRVec result = {0};
    bool found = resolve("any." TEST_DOMAIN, QTYPE_ANY, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(found);
    ASSERT(result.length == 3);

    bool found1 = false;
    bool found2 = false;
    bool found3 = false;
    for (uint32_t i = 0; i < result.length; i++) {
        RR *rr = result.data[i];

        if (rr->type == TYPE_A) {
            if (rr->data.ip4_addr == get_ip4("1.1.1.1")) found1 = true;
            if (rr->data.ip4_addr == get_ip4("2.2.2.2")) found2 = true;
        } else if (rr->type == TYPE_TXT) {
            TXT txt = rr->data.txt;
            if (txt.length == 1 && strcmp(txt.data[0], "result") == 0) found3 = true;
        }
    }
    ASSERT(found1 && found2 && found3);

    free_rr_vec(&result);
    return EXIT_SUCCESS;
}
