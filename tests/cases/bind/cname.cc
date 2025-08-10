#include "common.hh"
#include "config.hh"
#include "resolve.hh"

/// cname CNAME result.cname

namespace {
void check_response(const std::optional<std::vector<RR>> &response, const std::string &zone_domain) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::CNAME);
    ASSERT(std::get<CNAME>(rr.data).domain == "result.cname." + zone_domain);
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve("cname." UNSIGNED_DOMAIN, RRType::CNAME), UNSIGNED_DOMAIN);
    check_response(signed_resolver.resolve("cname." SIGNED_DOMAIN, RRType::CNAME), SIGNED_DOMAIN);
    return EXIT_SUCCESS;
}
