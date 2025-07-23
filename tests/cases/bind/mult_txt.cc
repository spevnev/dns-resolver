#include "common.hh"
#include "config.hh"
#include "resolve.hh"

int main(void) {
    /// mult.txt TXT a b c d e
    Resolver resolver{TEST_RESOLVER_CONFIG};
    auto opt_rrset = resolver.resolve("mult.txt." TEST_DOMAIN, RRType::TXT);
    ASSERT(opt_rrset.has_value());

    auto &rrset = opt_rrset.value();
    ASSERT(rrset.size() == 1);

    auto &rr = rrset[0];
    ASSERT(rr.type == RRType::TXT);
    auto &strings = std::get<TXT>(rr.data).strings;

    ASSERT(strings.size() == 5);
    ASSERT(strings[0] == "a");
    ASSERT(strings[1] == "b");
    ASSERT(strings[2] == "c");
    ASSERT(strings[3] == "d");
    ASSERT(strings[4] == "e");

    return EXIT_SUCCESS;
}
