#include "common.hh"
#include "config.hh"
#include "resolve.hh"

namespace {
void check_response(const std::optional<std::vector<RR>> &response, const std::string &zone_domain) {
    ASSERT(response.has_value());

    const auto &rrset = response.value();
    ASSERT(rrset.size() == 1);

    const auto &rr = rrset[0];
    ASSERT(rr.type == RRType::SOA);
    const auto &soa = std::get<SOA>(rr.data);

    ASSERT(soa.master_name == "mname." + zone_domain);
    ASSERT(soa.rname == "rname." + zone_domain);
    ASSERT(soa.refresh == 200);
    ASSERT(soa.retry == 300);
    ASSERT(soa.expire == 400);
    ASSERT(soa.negative_ttl == 500);
}
}  // namespace

int main() {
    Resolver unsigned_resolver{UNSIGNED_RESOLVER_CONFIG};
    Resolver signed_resolver{SIGNED_RESOLVER_CONFIG};
    check_response(unsigned_resolver.resolve(UNSIGNED_DOMAIN, RRType::SOA), UNSIGNED_DOMAIN);
    check_response(signed_resolver.resolve(SIGNED_DOMAIN, RRType::SOA), SIGNED_DOMAIN);
    return EXIT_SUCCESS;
}
