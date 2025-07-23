#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    /// txt TXT result
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("txt." TEST_DOMAIN, RRType::TXT);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);

    auto &rr = rrset[0];
    ASSERT(rr.type == RRType::TXT);
    auto &strings = std::get<TXT>(rr.data).strings;

    ASSERT(strings.size() == 1);
    ASSERT(strings[0] == "result");

    return EXIT_SUCCESS;
}
