#include "common.hh"
#include "config.hh"
#include "resolve.hh"

// Custom RR type without any data.
/// type1234 TYPE1234 \# 1 00

int main() {
    auto custom_type = static_cast<RRType>(1234);

    Resolver resolver{UNSIGNED_RESOLVER_CONFIG};
    auto response = resolver.resolve("type1234." UNSIGNED_DOMAIN, custom_type);
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == custom_type);

    return EXIT_SUCCESS;
}
