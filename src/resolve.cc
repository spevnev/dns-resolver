#include "resolve.hh"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <memory>
#include <optional>
#include <print>
#include <queue>
#include <string>
#include <variant>
#include <vector>
#include "dns.hh"
#include "dnssec.hh"

struct Nameserver {
    std::variant<in_addr_t, std::string> address;
    std::optional<uint16_t> udp_payload_size{std::nullopt};
    bool sent_bad_cookie{false};
    DNSCookies cookies{};

    Nameserver(in_addr_t address) : address(address) {}
    Nameserver(const std::string &address) : address(address) {}
    Nameserver(std::string &&address) : address(std::move(address)) {}
};

struct Zone {
    // Do not use the zone whose nameserver is being resolved.
    bool is_being_resolved{false};
    std::string domain;
    bool enable_edns;
    bool enable_dnssec;
    bool enable_cookies;
    std::vector<std::shared_ptr<Nameserver>> nameservers;
    std::vector<DS> dss;
    std::vector<DNSKEY> dnskeys;

    Zone(std::string domain, bool enable_edns, bool enable_dnssec, bool enable_cookies)
        : domain(std::move(domain)),
          enable_edns(enable_edns),
          enable_dnssec(enable_dnssec),
          enable_cookies(enable_cookies) {}

    void add_nameserver(in_addr_t address) { nameservers.push_back(std::make_shared<Nameserver>(address)); }
    void add_nameserver(const std::string &domain) { nameservers.push_back(std::make_shared<Nameserver>(domain)); }
    void add_nameserver(std::string &&domain) {
        nameservers.push_back(std::make_shared<Nameserver>(std::move(domain)));
    }
};

namespace {
const constexpr uint64_t MIN_QUERY_TIMEOUT_MS = 300;
const constexpr int MAX_QUERY_DEPTH = 20;

// https://www.iana.org/domains/root/servers
const char *const ROOT_IP[] = {
    "198.41.0.4",    "170.247.170.2", "192.33.4.12",   "199.7.91.13",  "192.203.230.10", "192.5.5.241",  "192.112.36.4",
    "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",    "202.12.27.33",
};

// https://data.iana.org/root-anchors/root-anchors.xml
const DS ROOT_DS[]
    = {{
           .key_tag = 20326,
           .signing_algorithm = SigningAlgorithm::RSASHA256,
           .digest_algorithm = DigestAlgorithm::SHA256,
           .digest = {0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
                      0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D},
           .data = {},
       },
       {
           .key_tag = 38696,
           .signing_algorithm = SigningAlgorithm::RSASHA256,
           .digest_algorithm = DigestAlgorithm::SHA256,
           .digest = {0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74, 0x12, 0x19,
                      0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4, 0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16},
           .data = {},
       }};

class query_timeout_error : std::runtime_error {
public:
    query_timeout_error() : std::runtime_error("Query timed out") {}
};

class bad_cookie_error : std::runtime_error {
public:
    bad_cookie_error() : std::runtime_error("Bad server cookie") {}
};

// Check domain length, convert it to lowercase and fully qualify.
std::string fully_qualify_domain(const std::string &domain) {
    std::string fqd;
    fqd.reserve(domain.size() + 1);

    size_t label_index = 0;
    for (size_t i = 0; i < domain.size(); i++) {
        if (domain[i] == '.') {
            if (i == 0 && domain != ".") throw std::runtime_error("Domain starts with a dot");
            if (i > 0 && domain[i - 1] == '.') throw std::runtime_error("Domain has an empty label");
            if (i - label_index > MAX_LABEL_LENGTH) throw std::runtime_error("Label is too long");
            label_index = i + 1;
        }

        fqd.push_back(tolower(domain[i]));
    }
    if (!domain.ends_with('.')) fqd.push_back('.');

    if (fqd.size() > MAX_DOMAIN_LENGTH) throw std::runtime_error("Domain is too long");
    return fqd;
}

int count_matching_labels(const std::string &a, const std::string &b) {
    assert(!a.empty() && !b.empty());

    int count = 0;
    auto a_it = a.crbegin() + 1;
    auto b_it = b.crbegin() + 1;
    while (a_it != a.crend() && b_it != b.crend()) {
        if (*a_it != *b_it) return count;
        if (*a_it == '.') count++;
        ++a_it, ++b_it;
    }
    if ((a_it == a.crend() || *a_it == '.') && (b_it == b.crend() || *b_it == '.')) count++;
    return count;
}

std::shared_ptr<Zone> get_next_zone(std::queue<std::shared_ptr<Zone>> &zones) {
    while (!zones.empty()) {
        auto zone = std::move(zones.front());
        zones.pop();
        if (zone != nullptr && !zone->is_being_resolved) return zone;
    }
    return nullptr;
}

bool address_equals(struct sockaddr_in a, struct sockaddr_in b) {
    return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}
}  // namespace

Resolver::Resolver(ResolverConfig config)
    : query_timeout_ms(std::max(config.timeout_ms, MIN_QUERY_TIMEOUT_MS)),
      udp_timeout_ms(query_timeout_ms / 3),
      port(config.port),
      verbose(config.verbose),
      enable_rd(config.enable_rd),
      edns(config.edns),
      dnssec(config.dnssec),
      cookies(config.cookies),
      rng(std::chrono::system_clock::now().time_since_epoch().count()) {
    if (edns == FeatureState::Disable) {
        if (dnssec == FeatureState::Require) throw std::runtime_error("DNSSEC requires EDNS to be enabled");
        dnssec = FeatureState::Disable;

        if (cookies == FeatureState::Require) throw std::runtime_error("Cookies require EDNS to be enabled");
        cookies = FeatureState::Disable;
    }
    if (dnssec == FeatureState::Require || cookies == FeatureState::Require) edns = FeatureState::Require;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) throw std::runtime_error("Failed to create UDP socket");

    if (dnssec != FeatureState::Require) {
        // Only the root zone can be used with DNSSEC because it is the only trust anchor.
        if (config.nameserver.has_value()) safe_zones.push(new_zone_from_nameserver(config.nameserver.value()));
        if (config.use_resolve_config) safe_zones.push(load_resolve_config());
    }
    if (config.use_root_nameservers) safe_zones.push(new_root_zone());
    if (safe_zones.empty()) throw std::runtime_error("No nameserver is specified");
}

Resolver::~Resolver() { close(fd); }

std::optional<std::vector<RR>> Resolver::resolve(const std::string &domain, RRType rr_type) {
    // DNSSEC is disabled for queries of type ANY.
    if (dnssec == FeatureState::Require && rr_type == RRType::ANY) return std::nullopt;

    // RRSIG and OPT RRs cannot be queried.
    if (rr_type == RRType::RRSIG || rr_type == RRType::OPT) return std::nullopt;

    try {
        query_start = std::chrono::steady_clock::now();
        set_socket_timeout(udp_timeout_ms);
        return resolve_rec(fully_qualify_domain(domain), rr_type, 0);
    } catch (const std::exception &e) {
        if (verbose) std::println(stderr, "Failed to resolve the domain: {}", e.what());
        return std::nullopt;
    }
}

std::shared_ptr<Zone> Resolver::new_zone(const std::string &domain, bool enable_dnssec) const {
    return std::make_shared<Zone>(domain, edns != FeatureState::Disable,
                                  enable_dnssec && dnssec != FeatureState::Disable, cookies != FeatureState::Disable);
}

std::shared_ptr<Zone> Resolver::new_root_zone() const {
    auto zone = new_zone(".");
    in_addr_t ip_address;
    for (const auto *ip : ROOT_IP) {
        if (inet_pton(AF_INET, ip, &ip_address) != 1) throw std::runtime_error("Failed to add root nameservers");
        zone->add_nameserver(ip_address);
    }
    zone->dss.assign_range(ROOT_DS);
    return zone;
}

std::shared_ptr<Zone> Resolver::load_resolve_config() const {
    auto zone = new_zone(".", false);
    std::ifstream is{"/etc/resolv.conf"};
    in_addr_t ip_address;
    std::string line;
    while (std::getline(is, line)) {
        auto start_idx = line.find_first_not_of(" \t");
        if (start_idx == std::string::npos) continue;

        if (line.compare(start_idx, 10, "nameserver") != 0) continue;
        start_idx += 10;

        auto address_start_idx = line.find_first_not_of(" \t", start_idx);
        if (address_start_idx == std::string::npos) continue;

        auto address_end_idx = line.find_last_not_of(" \t");
        if (address_end_idx == std::string::npos) continue;

        auto *ip_str = line.data() + address_start_idx;
        line[address_end_idx + 1] = '\0';

        if (inet_pton(AF_INET, ip_str, &ip_address) == 1) zone->add_nameserver(ip_address);
    }

    // If no nameserver entries are present, the default is to use the local nameserver.
    if (zone->nameservers.empty()) {
        auto result = inet_pton(AF_INET, "127.0.0.1", &ip_address);
        assert(result == 1);
        zone->add_nameserver(ip_address);
    }
    return zone;
}

std::shared_ptr<Zone> Resolver::new_zone_from_nameserver(const std::string &address_or_domain) const {
    auto zone = new_zone(".", false);
    in_addr_t ip_address;
    if (inet_pton(AF_INET, address_or_domain.c_str(), &ip_address) == 1) {
        zone->add_nameserver(ip_address);
    } else {
        zone->add_nameserver(address_or_domain);
    }
    return zone;
}

std::shared_ptr<Zone> Resolver::find_zone(const std::string &domain) const {
    std::string_view current{domain};
    for (;;) {
        auto zone_it = zones.find(current);
        if (zone_it != zones.cend()) {
            const auto &zone = zone_it->second;
            if (!zone->is_being_resolved) return zone;
        }

        auto next_label_index = current.find('.');
        assert(next_label_index != std::string::npos);
        if (next_label_index == current.size() - 1) return nullptr;
        current.remove_prefix(next_label_index + 1);
    }
}

void Resolver::zone_disable_dnssec(Zone &zone) const {
    // If there is no secure delegation, the zone is unsigned and does not support DNSSEC.
    // Don't throw because disabling DNSSEC is the only way to access the zone.
    if (!zone.dss.empty() && dnssec == FeatureState::Require) {
        throw std::runtime_error("Nameserver does not support DNSSEC");
    }
    zone.enable_dnssec = false;
}

void Resolver::set_socket_timeout(uint64_t timeout_ms) const {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||  //
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        throw std::runtime_error("Failed to set receive/send timeout");
    }
}

void Resolver::update_timeout() {
    auto duration = std::chrono::steady_clock::now() - query_start;
    auto duration_ms = std::chrono::duration_cast<std::chrono::duration<uint64_t, std::milli>>(duration).count();
    if (duration_ms >= query_timeout_ms) throw query_timeout_error();

    auto time_left_ms = query_timeout_ms - duration_ms;
    if (time_left_ms < udp_timeout_ms) set_socket_timeout(time_left_ms);
}

void Resolver::udp_send(const std::vector<uint8_t> &buffer, struct sockaddr_in address) {
    auto *socket_address = reinterpret_cast<struct sockaddr *>(&address);
    auto result = sendto(fd, buffer.data(), buffer.size(), 0, socket_address, sizeof(address));
    update_timeout();
    if (result == -1 && errno == EAGAIN) throw std::runtime_error("Request timed out");
    if (result != static_cast<ssize_t>(buffer.size())) throw std::runtime_error("Failed to send the request");
}

void Resolver::udp_receive(std::vector<uint8_t> &buffer, struct sockaddr_in request_address) {
    struct sockaddr_in address;
    auto *socket_address = reinterpret_cast<struct sockaddr *>(&address);
    socklen_t address_length;
    ssize_t result;
    // Read responses until we find the one from the same address and port as in request.
    do {
        address_length = sizeof(address);
        result = recvfrom(fd, buffer.data(), buffer.size(), 0, socket_address, &address_length);
        update_timeout();
        if (result == -1) {
            if (errno == EAGAIN) throw std::runtime_error("Response timed out");
            throw std::runtime_error("Failed to receive the response");
        }
    } while (address_length != sizeof(address) || !address_equals(address, request_address));
    buffer.resize(result);
}

bool Resolver::authenticate_rrset(const std::vector<RR> &rrset, const std::vector<RRSIG> &rrsigs, RRType rr_type,
                                  const Zone &zone) const {
    if (rrset.empty()) return true;

    if (rr_type != RRType::DNSKEY) {
        return dnssec::authenticate_rrset(rrset, rrsigs, zone.dnskeys, zone.domain);
    }

    if (!zone.dss.empty()) {
        return dnssec::authenticate_delegation(rrset, zone.dss, rrsigs, zone.domain);
    }

    // There is no secure delegation, so just verify that the RRSIG was signed with one of these DNSKEYs.
    auto dnskeys = rrset_to_data<DNSKEY>(rrset);
    return dnssec::authenticate_rrset(rrset, rrsigs, dnskeys, zone.domain);
}

std::vector<RR> Resolver::get_rrset(std::vector<RR> &rrset, RRType rr_type, const Zone &zone, bool authenticate) const {
    if (rr_type == RRType::ANY) {
        assert(!authenticate);
        return rrset;
    }

    std::vector<RR> result;
    std::vector<RR> current_rrset;
    std::vector<RRSIG> current_rrsigs;
    std::ranges::sort(rrset, {}, &RR::domain);
    for (auto it = rrset.begin(); it != rrset.end(); ++it) {
        // Check the condition before the iterator gets invalidated.
        auto is_end_of_group = it + 1 == rrset.end() || it->domain != (it + 1)->domain;

        if (it->type == rr_type) {
            current_rrset.push_back(std::move(*it));
            it = rrset.erase(it) - 1;
        } else if (authenticate && it->type == RRType::RRSIG) {
            auto &rrsig = std::get<RRSIG>(it->data);
            if (rrsig.type_covered != rr_type) continue;

            current_rrsigs.push_back(std::move(rrsig));
            it = rrset.erase(it) - 1;
        }

        if (is_end_of_group) {
            if (authenticate && zone.enable_dnssec
                && !authenticate_rrset(current_rrset, current_rrsigs, rr_type, zone)) {
                throw std::runtime_error("Failed to authenticate RRset");
            }
            result.append_range(std::move(current_rrset));
            current_rrset.clear();
            current_rrsigs.clear();
        }
    }
    return result;
}

std::vector<RR> Resolver::get_rrset(std::vector<RR> &rrset, RRType rr_type, const std::string &domain, const Zone &zone,
                                    bool authenticate) const {
    if (rr_type == RRType::ANY) {
        assert(!authenticate);
        return rrset;
    }

    std::vector<RR> result;
    std::vector<RRSIG> rrsigs;
    for (auto it = rrset.begin(); it != rrset.end(); ++it) {
        if (it->domain != domain) continue;

        if (it->type == rr_type) {
            result.push_back(std::move(*it));
            it = rrset.erase(it) - 1;
        } else if (authenticate && it->type == RRType::RRSIG) {
            auto &rrsig = std::get<RRSIG>(it->data);
            if (rrsig.type_covered != rr_type) continue;

            rrsigs.push_back(std::move(rrsig));
            it = rrset.erase(it) - 1;
        }
    }

    if (authenticate && zone.enable_dnssec && !authenticate_rrset(result, rrsigs, rr_type, zone)) {
        throw std::runtime_error("Failed to authenticate RRset");
    }

    return result;
}

std::optional<std::vector<RR>> Resolver::resolve_rec(const std::string &domain, RRType rr_type, int depth,
                                                     std::shared_ptr<Zone> search_zone) {
    if (depth >= MAX_QUERY_DEPTH) throw std::runtime_error("Query is too deep");

    std::vector<uint8_t> buffer;
    std::string sname{domain};
    std::queue<std::shared_ptr<Zone>> current_safe_zones{safe_zones};

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    // Choose the initial zone.
    std::shared_ptr<Zone> next_zone;
    if (search_zone != nullptr) {
        next_zone = std::move(search_zone);
    } else {
        next_zone = find_zone(sname);
        if (next_zone == nullptr) next_zone = get_next_zone(current_safe_zones);
    }

    while (next_zone != nullptr) {
        std::shared_ptr<Zone> zone = std::move(next_zone);
        next_zone = nullptr;

        // Get zone's DNSKEYs.
        if (zone->enable_dnssec && zone->dnskeys.empty() && rr_type != RRType::DNSKEY) {
            auto dnskey_rrset = resolve_rec(zone->domain, RRType::DNSKEY, depth + 1, zone);
            if (dnskey_rrset.has_value() && !dnskey_rrset->empty()) {
                zone->dnskeys = rrset_to_data<DNSKEY>(std::move(dnskey_rrset.value()));
            } else {
                zone_disable_dnssec(*zone);
            }
        }

        // Try asking every nameserver in random order.
        std::ranges::shuffle(zone->nameservers, rng);
        for (size_t i = 0; i < zone->nameservers.size(); i++) {
            auto nameserver = zone->nameservers[i];
            try {
                // If nameserver has only the domain, get the address.
                if (std::holds_alternative<std::string>(nameserver->address)) {
                    const auto &nameserver_domain = std::get<std::string>(nameserver->address);

                    // Do not use this zone while it is being resolver to avoid infinite recursion.
                    zone->is_being_resolved = true;
                    auto opt_a_rrset = resolve_rec(nameserver_domain, RRType::A, depth + 1);
                    zone->is_being_resolved = false;

                    if (!opt_a_rrset.has_value() || opt_a_rrset->empty()) {
                        throw std::runtime_error("Failed to get nameserver's address");
                    }

                    auto a_rrset = rrset_to_data<A>(std::move(opt_a_rrset.value()));
                    std::ranges::shuffle(a_rrset, rng);

                    nameserver->address = a_rrset[0].address;
                    for (size_t j = 1; j < a_rrset.size(); j++) zone->add_nameserver(a_rrset[j].address);
                }
                address.sin_addr.s_addr = std::get<in_addr_t>(nameserver->address);

                if (verbose) {
                    char ip_addr_buf[INET_ADDRSTRLEN];
                    const auto *address_str = inet_ntop(AF_INET, &address.sin_addr, ip_addr_buf, sizeof(ip_addr_buf));
                    if (address_str == nullptr) address_str = "invalid address";
                    std::println("Resolving \"{}\" using {} ({})", sname, address_str, zone->domain);
                }

                auto payload_size = nameserver->udp_payload_size.value_or(
                    zone->enable_edns ? EDNS_UDP_PAYLOAD_SIZE : STANDARD_UDP_PAYLOAD_SIZE);

                // Write and send the request.
                buffer.reserve(payload_size);
                buffer.clear();
                auto id = write_request(buffer, payload_size, sname, rr_type, enable_rd, zone->enable_edns,
                                        zone->enable_dnssec, zone->enable_cookies, nameserver->cookies);
                udp_send(buffer, address);

                // Ensure buffer is big enough to receive the response.
                buffer.resize(payload_size);
                udp_receive(buffer, address);
                auto response = read_response(buffer, id, sname, rr_type);
                auto rcode = response.rcode;

                // Handle OPT record.
                if (zone->enable_edns) {
                    std::vector<RR> opt_rrset = get_rrset(response.additional, RRType::OPT, *zone, false);
                    if (opt_rrset.size() == 1) {
                        auto &opt = std::get<OPT>(opt_rrset[0].data);

                        rcode = static_cast<RCode>((static_cast<uint16_t>(opt.upper_extended_rcode) << 4)
                                                   | std::to_underlying(rcode));
                        nameserver->udp_payload_size = opt.udp_payload_size;

                        if (!opt.dnssec_ok) zone_disable_dnssec(*zone);

                        if (zone->enable_cookies) {
                            if (opt.cookies.has_value()) {
                                if (opt.cookies->client != nameserver->cookies.client) {
                                    throw std::runtime_error("Wrong client cookie");
                                }
                                nameserver->cookies.server = std::move(opt.cookies->server);
                            } else {
                                if (cookies == FeatureState::Require) {
                                    throw std::runtime_error("Nameserver does not support Cookies");
                                }
                                zone->enable_cookies = false;
                            }
                        }
                    } else {
                        if (edns == FeatureState::Require) throw std::runtime_error("Nameserver does not support EDNS");
                        zone->enable_edns = false;
                        zone->enable_dnssec = false;
                        zone->enable_cookies = false;
                    }
                }

                if (verbose) {
                    if (!response.answers.empty()) std::println("Answer:");
                    for (const auto &rr : response.answers) std::println("{}", rr);

                    if (!response.authority.empty()) std::println("Authority:");
                    for (const auto &rr : response.authority) std::println("{}", rr);

                    if (!response.additional.empty()) std::println("Additional:");
                    for (const auto &rr : response.additional) std::println("{}", rr);
                    std::println();
                }

                switch (rcode) {
                    case RCode::Success:     break;
                    case RCode::FormatError: throw std::runtime_error("Nameserver is unable to interpret query"); break;
                    case RCode::ServerError: throw std::runtime_error("Nameserver error"); break;
                    case RCode::NameError:
                        if (zone->enable_dnssec) {
                            auto nsec3_rrset = get_rrset(response.authority, RRType::NSEC3, *zone);
                            auto nsec_rrset = get_rrset(response.authority, RRType::NSEC, *zone);
                            if (dnssec::authenticate_name_error(sname, nsec3_rrset, nsec_rrset, zone->domain)) {
                                return std::vector<RR>{};
                            }
                            throw std::runtime_error("Failed to authenticate the denial of existence");
                        }

                        if (!response.is_authoritative) {
                            throw std::runtime_error("Non-authoritative nameserver cannot deny the existence");
                        }
                        return std::vector<RR>{};
                    case RCode::NotImplemented:
                        throw std::runtime_error("Nameserver does not support this query");
                        break;
                    case RCode::Refused:    throw std::runtime_error("Nameserver refused to answer"); break;
                    case RCode::BadVersion: throw std::runtime_error("Nameserver does not support EDNS"); break;
                    case RCode::BadCookie:  throw bad_cookie_error(); break;
                    default:                throw std::runtime_error("Unknown response code");
                }

                // Follow the CNAMEs before looking for the answer.
                bool followed_cname = false;
                auto cname_rrset = get_rrset(response.answers, RRType::CNAME, *zone);
                for (;;) {
                    auto cname_rr = std::ranges::find(cname_rrset, sname, &RR::domain);
                    if (cname_rr == cname_rrset.end()) break;

                    // If the query type is CNAME, return it instead of following.
                    if (rr_type == RRType::CNAME) return std::vector<RR>{std::move(*cname_rr)};

                    sname = std::get<CNAME>(cname_rr->data).domain;
                    followed_cname = true;
                }

                // Look for the answer.
                if (rr_type == RRType::ANY) return response.answers;
                auto result = get_rrset(response.answers, rr_type, sname, *zone);
                if (!result.empty()) return result;

                // Look for the referral.
                std::shared_ptr<Zone> referral_zone = nullptr;
                auto ns_rrset = get_rrset(response.authority, RRType::NS, *zone, false);
                for (auto &ns_rr : ns_rrset) {
                    if (referral_zone == nullptr) {
                        if (count_matching_labels(sname, ns_rr.domain) <= count_matching_labels(sname, zone->domain)) {
                            throw std::runtime_error("Referral must be closer to the search name");
                        }
                        referral_zone = new_zone(ns_rr.domain);
                    } else if (ns_rr.domain != referral_zone->domain) {
                        throw std::runtime_error(std::format("Authority contains multiple referrals: {} and {}",
                                                             ns_rr.domain, referral_zone->domain));
                    }

                    // Check if the additional section has nameservers' addresses.
                    auto &ns_domain = std::get<NS>(ns_rr.data).domain;
                    auto a_rrset = rrset_to_data<A>(get_rrset(response.additional, RRType::A, ns_domain, *zone, false));
                    if (a_rrset.empty()) {
                        referral_zone->add_nameserver(std::move(ns_domain));
                    } else {
                        for (auto &a_rr : a_rrset) referral_zone->add_nameserver(a_rr.address);
                    }
                }

                if (referral_zone != nullptr) {
                    // Follow the referral.
                    if (zone->enable_dnssec) {
                        auto ds_rrset = get_rrset(response.authority, RRType::DS, referral_zone->domain, *zone);
                        if (!ds_rrset.empty()) {
                            referral_zone->dss = rrset_to_data<DS>(ds_rrset);
                        } else {
                            auto nsec3_rrset = get_rrset(response.authority, RRType::NSEC3, *zone);
                            auto nsec_rrset = get_rrset(response.authority, RRType::NSEC, referral_zone->domain, *zone);
                            auto nsec_rr = nsec_rrset.empty() ? std::nullopt : std::optional<RR>{nsec_rrset[0]};
                            if (!dnssec::authenticate_no_ds(referral_zone->domain, nsec3_rrset, nsec_rr,
                                                            zone->domain)) {
                                throw std::runtime_error("Failed to authenticate the denial of existence");
                            }
                        }
                    }

                    zones[referral_zone->domain] = referral_zone;
                    next_zone = std::move(referral_zone);
                    break;
                }

                if (followed_cname) {
                    // There is no referral and no answer, follow the CNAME.
                    return resolve_rec(sname, rr_type, depth);
                }

                // Look for the authenticated denial of existence.
                if (zone->enable_dnssec && rr_type != RRType::DNSKEY) {
                    auto nsec3_rrset = get_rrset(response.authority, RRType::NSEC3, *zone);
                    auto nsec_rrset = get_rrset(response.authority, RRType::NSEC, sname, *zone);
                    auto nsec_rr = nsec_rrset.empty() ? std::nullopt : std::optional<RR>{nsec_rrset[0]};
                    if (!dnssec::authenticate_no_rrset(rr_type, sname, nsec3_rrset, nsec_rr, zone->domain)) {
                        throw std::runtime_error("Failed to authenticate the denial of existence");
                    }
                    return std::vector<RR>{};
                }

                // No referral and no answer from an authoritative nameserver indicate No Data.
                if (response.is_authoritative) return std::vector<RR>{};

                // If the nameserver isn't authoritative, try one of the safe zones.
                next_zone = get_next_zone(current_safe_zones);
                if (next_zone == nullptr) return std::nullopt;
                break;
            } catch (const query_timeout_error &) {
                if (verbose) std::println(stderr, "Query timed out");
                return std::nullopt;
            } catch (const bad_cookie_error &) {
                if (!nameserver->sent_bad_cookie) {
                    // Retry the same nameserver with the new server cookie once.
                    i--;
                    nameserver->sent_bad_cookie = true;
                } else {
                    // Try a different nameserver.
                }
            } catch (const std::exception &e) {
                // Nameserver error, try asking the different nameserver if there are any left.
                if (verbose) std::println(stderr, "Failed to resolve the domain: {}", e.what());
            }
        }
    }
    return std::nullopt;
}
