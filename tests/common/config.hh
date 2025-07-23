#include "resolve.hh"

#define TEST_DOMAIN "test.com."

static const ResolverConfig TEST_RESOLVER_CONFIG{
    .timeout_ms = 1000,
    .nameserver = "127.0.0.1",
    .use_root_nameservers = false,
    .use_resolve_config = false,
    .port = 1053,
    .dnssec = FeatureState::Disable,
};
