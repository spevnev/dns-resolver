#include <cstdint>
#include <cstdlib>
#include <optional>
#include <print>
#include <string>
#include "args.h"
#include "dns.hh"
#include "resolve.hh"

namespace {
const char *RR_TYPES[] = {
    "A", "NS", "CNAME", "SOA", "HINFO", "TXT", "AAAA", "DS", "NSEC", "DNSKEY", "NSEC3", "ANY", nullptr,
};
const char *FEATURE_STATES[] = {"off", "disable", "on", "enable", "require", nullptr};

std::optional<RRType> parse_rr_type(const std::string &str) {
    if (str == "A") return RRType::A;
    if (str == "NS") return RRType::NS;
    if (str == "CNAME") return RRType::CNAME;
    if (str == "SOA") return RRType::SOA;
    if (str == "HINFO") return RRType::HINFO;
    if (str == "TXT") return RRType::TXT;
    if (str == "AAAA") return RRType::AAAA;
    if (str == "DS") return RRType::DS;
    if (str == "NSEC") return RRType::NSEC;
    if (str == "DNSKEY") return RRType::DNSKEY;
    if (str == "NSEC3") return RRType::NSEC3;
    if (str == "ANY") return RRType::ANY;
    return std::nullopt;
}

std::optional<FeatureState> parse_feature_state(const std::string &str) {
    if (str == "off" || str == "disable") return FeatureState::Disable;
    if (str == "on" || str == "enable") return FeatureState::Enable;
    if (str == "require") return FeatureState::Require;
    return std::nullopt;
}
};  // namespace

int main(int argc, char **argv) {
    ArgsCpp args;

    args.option_help([](ArgsCpp &args, const char *program_name) {
        std::println("{} - Iterative DNS Resolver CLI", program_name);
        std::println();
        std::println("Usage:");
        std::println("  {} [options] <domain>", program_name);
        std::println("  {} completion <bash|zsh|fish>", program_name);
        std::println();
        args.print_options();
    });

    const auto &server = args.option_string("server", "Nameserver domain or address").short_name('s');
    const auto &port = args.option_long("port", "Nameserver port").short_name('p').default_value(53);
    const auto &type = args.option_enum_string("type", "Query type", RR_TYPES).short_name('t').default_value("A");
    const auto &timeout = args.option_long("timeout", "Timeout in seconds").short_name('T').default_value(10);
    const auto &verbose = args.option_flag("verbose", "Verbose output").short_name('v');
    const auto &rdflag = args.option_flag("rdflag", "Set recursion desired flag");
    const auto &tcp
        = args.option_enum_string("tcp", "on = fallback, require = TCP-only", FEATURE_STATES).default_value("on");
    const auto &edns = args.option_enum_string("edns", "EDNS", FEATURE_STATES).default_value("on");
    const auto &dnssec = args.option_enum_string("dnssec", "DNSSEC", FEATURE_STATES).default_value("on");
    const auto &cookies = args.option_enum_string("cookies", "DNS Cookies", FEATURE_STATES).default_value("on");
    const auto &no_root = args.option_flag("no-root", "Don't use root nameservers");
    const auto &use_config = args.option_flag("use-config", "Use nameservers from /etc/resolv.conf");

    char **pos_args;
    int pos_args_len = args.parse_args(argc, argv, pos_args);

    if (pos_args_len != 1) {
        std::println(stderr, "Invalid arguments: expected domain but found {} arguments", pos_args_len);
        return EXIT_FAILURE;
    }

    if (!(1 <= port && port <= UINT16_MAX)) {
        std::println(stderr, "Invalid port {}", port.value());
        return EXIT_FAILURE;
    }

    auto qtype = parse_rr_type(type);
    if (qtype == std::nullopt) {
        std::println(stderr, "Invalid query type \"{}\"", type.value());
        return EXIT_FAILURE;
    }

    auto tcp_state = parse_feature_state(tcp);
    if (tcp_state == std::nullopt) {
        std::println(stderr, "Invalid TCP state \"{}\"", tcp.value());
        return EXIT_FAILURE;
    }

    auto edns_state = parse_feature_state(edns);
    if (edns_state == std::nullopt) {
        std::println(stderr, "Invalid EDNS state \"{}\"", edns.value());
        return EXIT_FAILURE;
    }

    auto dnssec_state = parse_feature_state(dnssec);
    if (dnssec_state == std::nullopt) {
        std::println(stderr, "Invalid DNSSEC state \"{}\"", dnssec.value());
        return EXIT_FAILURE;
    }

    auto cookies_state = parse_feature_state(cookies);
    if (cookies_state == std::nullopt) {
        std::println(stderr, "Invalid DNS Cookies state \"{}\"", cookies.value());
        return EXIT_FAILURE;
    }

    std::optional<NameserverConfig> nameserver = std::nullopt;
    if (server != nullptr) nameserver = NameserverConfig{.address = server};

    Resolver resolver{{
        .timeout_ms = static_cast<uint64_t>(timeout) * 1000,
        .nameserver = nameserver,
        .use_root_nameservers = !no_root,
        .use_resolve_config = use_config,
        .port = static_cast<uint16_t>(port),
        .verbose = verbose,
        .enable_rd = rdflag,
        .tcp = tcp_state.value(),
        .edns = edns_state.value(),
        .dnssec = dnssec_state.value(),
        .cookies = cookies_state.value(),
    }};

    auto response = resolver.resolve(pos_args[0], qtype.value());
    if (!response.has_value()) {
        std::println(stderr, "Failed to resolve the domain.");
        return EXIT_FAILURE;
    }

    const auto &rrset = response.value();
    if (rrset.empty()) {
        std::println("Domain name does not exist.");
    } else {
        std::println("Answer:");
        for (const auto &rr : rrset) std::println("{}", rr);
    }

    return EXIT_SUCCESS;
}
