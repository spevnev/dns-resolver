#include "common.hh"
#include "config.hh"
#include "mock_config.hh"
#include "resolve.hh"

MockResponse mock_response = {
    .set_wrong_id = true,
    .answers = {0x4, 0x74, 0x65, 0x73, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1,
                0x0, 0x1,  0x0,  0x0,  0x0,  0x0, 0x0,  0x4,  0x1,  0x2, 0x3, 0x4},
    .answers_count = 1,
};

int main() {
    Resolver resolver{MOCK_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve(MOCK_DOMAIN, RRType::A);
    ASSERT(!opt_rrset.has_value());
    return EXIT_SUCCESS;
}
