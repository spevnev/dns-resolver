#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// hinfo HINFO cpu os

namespace {
void check_response(const std::optional<std::vector<RR>> &response) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::HINFO);
    const auto &hinfo = std::get<HINFO>(rr.data);

    ASSERT(hinfo.cpu == "cpu");
    ASSERT(hinfo.os == "os");
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("hinfo." UNSIGNED_DOMAIN, RRType::HINFO));
    check_response(signed_resolver.resolve("hinfo." SIGNED_DOMAIN, RRType::HINFO));
    return EXIT_SUCCESS;
}
