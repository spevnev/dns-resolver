#include "common.h"
#include "config.h"
#include "mock_config.h"
#include "resolve.h"

static const uint8_t answers[] = {0x4, 0x74, 0x65, 0x73, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1,
                                  0x0, 0x1,  0x0,  0x0,  0x0,  0x0, 0x0,  0x4,  0x1,  0x2, 0x3, 0x4};

MockResponse mock_response = {
    .set_wrong_id = true,
    .answers = answers,
    .answers_length = sizeof(answers),
    .answers_count = 1,
};

int main(void) {
    RRVec result = {0};
    bool found = resolve(&result, TEST_DOMAIN, TYPE_A, NAMESERVER_IP, NAMESERVER_PORT, 1000, RESOLVE_NO_ROOT_NS);
    ASSERT(!found);
    return EXIT_SUCCESS;
}
