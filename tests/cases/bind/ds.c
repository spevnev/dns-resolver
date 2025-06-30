#include "common.h"
#include "config.h"
#include "resolve.h"

int main(void) {
    // DS can only be specified for the delegation point, which is marked by NS record.
    /// ds NS ns.ds
    /// ds DS 12345 8 1 2923F6FA36614586EA09B4424B438915CC1B9B67
    const uint8_t ds_digest[] = {0x29, 0x23, 0xf6, 0xfa, 0x36, 0x61, 0x45, 0x86, 0xea, 0x09,
                                 0xb4, 0x42, 0x4b, 0x43, 0x89, 0x15, 0xcc, 0x1b, 0x9b, 0x67};

    RRVec result = {0};
    bool found = resolve("ds." TEST_DOMAIN, TYPE_DS, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(found);

    ASSERT(result.length == 1);
    RR *rr = result.data[0];
    ASSERT(rr->type == TYPE_DS);
    ASSERT(rr->data.ds.key_tag == 12345);
    ASSERT(rr->data.ds.signing_algorithm == 8);
    ASSERT(rr->data.ds.digest_algorithm == 1);
    ASSERT(rr->data.ds.digest_size == sizeof(ds_digest));
    ASSERT(memcmp(rr->data.ds.digest, ds_digest, rr->data.ds.digest_size) == 0);

    free_rr_vec(result);
    return EXIT_SUCCESS;
}
