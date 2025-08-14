#include "common.hh"
#include "config.hh"
#include "mock_config.hh"
#include "resolve.hh"

// Response without OPT indicates that the nameserver doesn't support EDNS.

MockResponse mock_response = {
    .copy_opt = false,
    .answers = {0x4, 0x74, 0x65, 0x73, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1,
                0x0, 0x1,  0x0,  0x0,  0x0,  0x0, 0x0,  0x4,  0x1,  0x2, 0x3, 0x4},
    .answers_count = 1,
};

int main() {
    auto config = MOCK_RESOLVER_CONFIG;
    config.edns = FeatureState::Require;

    Resolver resolver{config};
    auto response = resolver.resolve(MOCK_DOMAIN, RRType::A);
    ASSERT(!response.has_value());
    return EXIT_SUCCESS;
}
