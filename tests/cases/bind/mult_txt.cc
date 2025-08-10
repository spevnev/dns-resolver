#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// txt.mult TXT a b c d e

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::TXT);
    const auto &strings = std::get<TXT>(rr.data).strings;

    ASSERT(strings.size() == 5);
    ASSERT(strings[0] == "a");
    ASSERT(strings[1] == "b");
    ASSERT(strings[2] == "c");
    ASSERT(strings[3] == "d");
    ASSERT(strings[4] == "e");
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("txt.mult." UNSIGNED_DOMAIN, RRType::TXT));
    check_response(signed_resolver.resolve("txt.mult." SIGNED_DOMAIN, RRType::TXT));
    return EXIT_SUCCESS;
}
