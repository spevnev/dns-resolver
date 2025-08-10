#include "common.hh"
#include "config.hh"
#include "resolve.hh"

// TODO: rename name error. unsigned, nsec, nsec3
// TODO: wildcards, mention RFCs
// TODO: no data error (unsigned, nsec, nsec3)
// TODO: successful wildcard case
int main() {
    Resolver resolver{UNSIGNED_RESOLVER_CONFIG};
    auto response = resolver.resolve("does.not.exist." UNSIGNED_DOMAIN, RRType::A);
    ASSERT(response.has_value());

    auto &rrset = response.value();
    ASSERT(rrset.empty());

    return EXIT_SUCCESS;
}
