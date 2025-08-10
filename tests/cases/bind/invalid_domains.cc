#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main() {
    Resolver resolver{UNSIGNED_RESOLVER_CONFIG};
    auto response = resolver.resolve("test.com..", RRType::A);
    ASSERT(!response.has_value());

    response = resolver.resolve("test..com", RRType::A);
    ASSERT(!response.has_value());

    response = resolver.resolve(".test.com", RRType::A);
    ASSERT(!response.has_value());

    // Label is too long (>63)
    response = resolver.resolve("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", RRType::A);
    ASSERT(!response.has_value());

    // Domain is too long (>254)
    response = resolver.resolve(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
        RRType::A);
    ASSERT(!response.has_value());

    return EXIT_SUCCESS;
}
