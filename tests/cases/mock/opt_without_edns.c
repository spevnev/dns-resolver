#include "common.h"
#include "config.h"
#include "mock_config.h"
#include "resolve.h"

static const uint8_t answers[] = {0x4, 0x74, 0x65, 0x73, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1,
                                  0x0, 0x1,  0x0,  0x0,  0x0,  0x0, 0x0,  0x4,  0x1,  0x2, 0x3, 0x4};

static const uint8_t additional[] = {0x0, 0x0, 0x29, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

MockResponse mock_response = {
    .answers = answers,
    .answers_length = sizeof(answers),
    .answers_count = 1,
    .additional = additional,
    .additional_length = sizeof(additional),
    .additional_count = 1,
};

int main(void) {
    RRVec result = {0};
    bool found
        = resolve(TEST_DOMAIN, TYPE_A, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS | RESOLVE_DISABLE_EDNS, &result);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
