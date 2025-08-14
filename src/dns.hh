#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>
#include "encode.hh"

static const constexpr uint16_t DNS_PORT = 53;

static const constexpr uint16_t STANDARD_UDP_PAYLOAD_SIZE = 512;  // RFC1035
static const constexpr uint16_t EDNS_UDP_PAYLOAD_SIZE = 4096;     // RFC6891

static const constexpr size_t MAX_DOMAIN_LENGTH = 254;
static const constexpr size_t MAX_LABEL_LENGTH = 63;

static const constexpr uint32_t MAX_TTL = 2147483647;  // RFC2181

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
enum class DNSClass : uint16_t {
    Internet = 1,
};

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
enum class OpCode : uint16_t {
    Query = 0,
};

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
enum class RRType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    HINFO = 13,
    TXT = 16,
    AAAA = 28,
    DNAME = 39,
    OPT = 41,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    ANY = 255,
};

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
enum class RCode : uint8_t {
    Success = 0,
    FormatError = 1,
    ServerError = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    BadVersion = 16,
    BadCookie = 23,
};

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
static const constexpr uint8_t EDNS_VERSION = 0;

static const constexpr uint8_t DNSKEY_PROTOCOL = 3;  // RFC4034

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
enum class OptionCode : uint16_t {
    Cookies = 10,
};

// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
enum class SigningAlgorithm : uint8_t {
    RSASHA1 = 5,
    RSASHA256 = 8,
    RSASHA512 = 10,
    ECDSAP256SHA256 = 13,
    ECDSAP384SHA384 = 14,
    ED25519 = 15,
    ED448 = 16,
};

// https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
enum class DigestAlgorithm : uint8_t {
    SHA1 = 1,
    SHA256 = 2,
    SHA384 = 4,
};

// https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml
enum class HashAlgorithm : uint8_t {
    SHA1 = 1,
};

struct A {
    in_addr_t address;
};

struct NS {
    std::string domain;
};

struct CNAME {
    std::string domain;
};

struct SOA {
    std::string master_name;
    std::string rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t negative_ttl;
};

struct HINFO {
    std::string cpu;
    std::string os;
};

struct TXT {
    std::vector<std::string> strings;
};

struct AAAA {
    struct in6_addr address;
};

struct DNSCookies {
    std::optional<uint64_t> client;
    std::vector<uint8_t> server;
};

struct OPT {
    uint16_t udp_payload_size;
    uint8_t upper_extended_rcode;
    std::optional<DNSCookies> cookies;
    bool dnssec_ok;
};

struct DS {
    uint16_t key_tag;
    SigningAlgorithm signing_algorithm;
    DigestAlgorithm digest_algorithm;
    std::vector<uint8_t> digest;
    std::vector<uint8_t> data;
};

struct RRSIG {
    RRType type_covered;
    SigningAlgorithm algorithm;
    uint8_t labels;
    uint32_t original_ttl;
    uint32_t expiration_time;
    uint32_t inception_time;
    uint16_t key_tag;
    std::string signer_name;
    std::vector<uint8_t> signature;
    // Data does not include the signature since it is only used to authenticate it.
    std::vector<uint8_t> data;
};

struct NSEC {
    std::string next_domain;
    std::unordered_set<RRType> types;
    std::vector<uint8_t> data;
};

struct DNSKEY {
    uint16_t flags;
    bool is_zone_key;
    bool is_secure_entry;
    uint8_t protocol;
    SigningAlgorithm algorithm;
    std::vector<uint8_t> key;
    std::vector<uint8_t> data;
    uint16_t key_tag;
};

struct NSEC3 {
    HashAlgorithm algorithm;
    uint8_t flags;
    bool opt_out;
    uint16_t iterations;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> next_domain_hash;
    std::unordered_set<RRType> types;
    std::vector<uint8_t> data;
};

struct RR {
    std::string domain;
    RRType type;
    uint32_t ttl;
    std::variant<A, NS, CNAME, SOA, HINFO, TXT, AAAA, OPT, DS, RRSIG, NSEC, DNSKEY, NSEC3> data;
};

template <>
class std::formatter<RRType> : public std::formatter<string_view> {
public:
    auto format(const RRType &rr_type, std::format_context &ctx) const {
        std::string output;
        switch (rr_type) {
            case RRType::A:      output = "A"; break;
            case RRType::NS:     output = "NS"; break;
            case RRType::CNAME:  output = "CNAME"; break;
            case RRType::SOA:    output = "SOA"; break;
            case RRType::HINFO:  output = "HINFO"; break;
            case RRType::TXT:    output = "TXT"; break;
            case RRType::AAAA:   output = "AAAA"; break;
            case RRType::OPT:    output = "OPT"; break;
            case RRType::DS:     output = "DS"; break;
            case RRType::RRSIG:  output = "RRSIG"; break;
            case RRType::NSEC:   output = "NSEC"; break;
            case RRType::DNSKEY: output = "DNSKEY"; break;
            case RRType::NSEC3:  output = "NSEC3"; break;
            case RRType::ANY:    output = "ANY"; break;
            default:             output = std::format("TYPE{}", std::to_underlying(rr_type)); break;
        }
        return std::formatter<string_view>::format(output, ctx);
    }
};

template <>
class std::formatter<RR> : public std::formatter<string_view> {
public:
    auto format(const RR &rr, std::format_context &ctx) const {
        std::string output_string;
        auto out = std::back_inserter(output_string);

        std::format_to(out, "{:<24} {:<8} {:<6} ", rr.domain, rr.ttl, rr.type);
        switch (rr.type) {
            case RRType::A: {
                char addr_buffer[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &std::get<A>(rr.data).address, addr_buffer, sizeof(addr_buffer)) == nullptr) {
                    std::format_to(out, "invalid address");
                } else {
                    std::format_to(out, "{}", addr_buffer);
                }
            } break;
            case RRType::NS:    std::format_to(out, "{}", std::get<NS>(rr.data).domain); break;
            case RRType::CNAME: std::format_to(out, "{}", std::get<CNAME>(rr.data).domain); break;
            case RRType::SOA:   {
                const auto &soa = std::get<SOA>(rr.data);
                std::format_to(out, "{} {} {} {} {} {} {}", soa.master_name, soa.rname, soa.serial, soa.refresh,
                               soa.retry, soa.expire, soa.negative_ttl);
            } break;
            case RRType::HINFO: {
                const auto &hinfo = std::get<HINFO>(rr.data);
                std::format_to(out, "{} {}", hinfo.cpu, hinfo.os);
            } break;
            case RRType::TXT: {
                const auto &txt = std::get<TXT>(rr.data);
                for (const auto &string : txt.strings) std::format_to(out, " \"{}\"", string);
            } break;
            case RRType::AAAA: {
                char addr_buffer[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &std::get<AAAA>(rr.data).address, addr_buffer, sizeof(addr_buffer))
                    == nullptr) {
                    std::format_to(out, "invalid address");
                } else {
                    std::format_to(out, "{}", addr_buffer);
                }
            } break;
            case RRType::DS: {
                const auto &ds = std::get<DS>(rr.data);
                std::format_to(out, "{} {} {} {}", ds.key_tag, std::to_underlying(ds.signing_algorithm),
                               std::to_underlying(ds.digest_algorithm), hex_encode(ds.digest));
            } break;
            case RRType::RRSIG: {
                const auto &rrsig = std::get<RRSIG>(rr.data);
                std::format_to(out, "{} {} {} {} {} {} {} {} {}", rrsig.type_covered,
                               std::to_underlying(rrsig.algorithm), rrsig.labels, rrsig.original_ttl,
                               rrsig.expiration_time, rrsig.inception_time, rrsig.key_tag, rrsig.signer_name,
                               base64_encode(rrsig.signature));
            } break;
            case RRType::NSEC: {
                const auto &nsec = std::get<NSEC>(rr.data);
                std::format_to(out, "{} (", nsec.next_domain);
                print_types(out, nsec.types);
                std::format_to(out, ")");
            } break;
            case RRType::DNSKEY: {
                const auto &dnskey = std::get<DNSKEY>(rr.data);
                std::format_to(out, "{} {} {} {}", dnskey.flags, dnskey.protocol, std::to_underlying(dnskey.algorithm),
                               base64_encode(dnskey.key));
            } break;
            case RRType::NSEC3: {
                const auto &nsec3 = std::get<NSEC3>(rr.data);
                std::format_to(out, "{} {} {} {} {} (", std::to_underlying(nsec3.algorithm), nsec3.flags,
                               nsec3.iterations, nsec3.salt.empty() ? "-" : hex_encode(nsec3.salt),
                               base32hex_encode(nsec3.next_domain_hash));
                print_types(out, nsec3.types);
                std::format_to(out, ")");
            } break;
            default: break;
        }
        return std::formatter<string_view>::format(output_string, ctx);
    }

private:
    // Print set of RR types in ascending order.
    static void print_types(std::back_insert_iterator<std::string> &out, const std::unordered_set<RRType> &type_set) {
        std::vector<RRType> types{type_set.cbegin(), type_set.cend()};
        std::ranges::sort(types, std::less<>{});

        bool is_first = true;
        for (auto type : types) {
            if (!is_first) std::format_to(out, " ");
            is_first = false;
            std::format_to(out, "{}", type);
        }
    }
};

struct Response {
    bool is_authoritative;
    RCode rcode;
    std::vector<RR> answers;
    std::vector<RR> authority;
    std::vector<RR> additional;
    uint16_t udp_payload_size;
    std::optional<DNSCookies> cookies;
};

uint16_t write_request(std::vector<uint8_t> &buffer, uint16_t payload_size, const std::string &qname, RRType qtype,
                       bool enable_rd, bool enable_edns, bool enable_dnssec, bool enable_cookies, DNSCookies &cookies);
Response read_response(const std::vector<uint8_t> &buffer, uint16_t request_id, const std::string &qname, RRType qtype);

inline bool pop_label(std::string_view &domain) {
    if (domain == ".") return false;
    auto next_label_index = domain.find('.');
    assert(next_label_index != std::string::npos);
    if (next_label_index != domain.length() - 1) next_label_index++;
    domain.remove_prefix(next_label_index);
    return true;
}
