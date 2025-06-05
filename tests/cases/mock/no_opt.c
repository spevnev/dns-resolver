#include "common.h"
#include "config.h"
#include "mock_config.h"
#include "resolve.h"

static const uint8_t authority[]
    = {0x4, 0x74, 0x65, 0x73, 0x74, 0x3,  0x63, 0x6f, 0x6d, 0x0,  0x0, 0x2,  0x0,  0x1,  0x0, 0x0,
       0x0, 0x0,  0x0,  0xb,  0x5,  0x6f, 0x74, 0x68, 0x65, 0x72, 0x3, 0x63, 0x6f, 0x6d, 0x0};

MockResponse mock_response = {
    .disable_copy_opt = true,
    .authority = authority,
    .authority_length = sizeof(authority),
    .authority_count = 1,
};

int main(void) {
    RRVec result = {0};
    bool found = resolve(TEST_DOMAIN, TYPE_A, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
