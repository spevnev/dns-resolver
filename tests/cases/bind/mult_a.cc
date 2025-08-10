#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// a.mult A 1.1.1.1
/// a.mult A 2.2.2.2
/// a.mult A 3.3.3.3

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 3);

    bool found1 = false;
    bool found2 = false;
    bool found3 = false;
    for (const auto &rr : rrset) {
        ASSERT(rr.type == RRType::A);
        auto address = std::get<A>(rr.data).address;
        if (address == get_ip4("1.1.1.1")) found1 = true;
        if (address == get_ip4("2.2.2.2")) found2 = true;
        if (address == get_ip4("3.3.3.3")) found3 = true;
    }
    ASSERT(found1 && found2 && found3);
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("a.mult." UNSIGNED_DOMAIN, RRType::A));
    check_response(signed_resolver.resolve("a.mult." SIGNED_DOMAIN, RRType::A));
    return EXIT_SUCCESS;
}
