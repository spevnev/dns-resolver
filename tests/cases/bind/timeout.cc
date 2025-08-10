#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main() {
    auto config{UNSIGNED_RESOLVER_CONFIG};
    config.timeout_ms = 100;
    config.nameserver = NameserverConfig{.address = "127.0.0.10"};
    config.port = 65535;

    Resolver resolver{config};
    auto response = resolver.resolve(UNSIGNED_DOMAIN, RRType::A);
    ASSERT(!response.has_value());

    return EXIT_SUCCESS;
}
