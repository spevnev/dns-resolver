#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// txt TXT result

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::TXT);
    const auto &strings = std::get<TXT>(rr.data).strings;

    ASSERT(strings.size() == 1);
    ASSERT(strings[0] == "result");
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("txt." UNSIGNED_DOMAIN, RRType::TXT));
    check_response(signed_resolver.resolve("txt." SIGNED_DOMAIN, RRType::TXT));
    return EXIT_SUCCESS;
}
