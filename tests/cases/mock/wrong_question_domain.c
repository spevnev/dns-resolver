#include "common.h"
#include "config.h"
#include "mock_config.h"
#include "resolve.h"

static const uint8_t questions[]
    = {0x1, 0x61, 0x4, 0x74, 0x65, 0x73, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1};

MockResponse mock_response = {
    .questions = questions,
    .questions_length = sizeof(questions),
    .questions_count = 1,
};

int main(void) {
    RRVec result = {0};
    bool found = resolve(TEST_DOMAIN, TYPE_A, TEST_IP, TEST_PORT, TEST_TIMEOUT, TEST_FLAGS, &result);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
