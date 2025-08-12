#include "dnssec.hh"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>
#include "dns.hh"
#include "encode.hh"
#include "write.hh"

namespace {
using EVP_PKEY_unique_ptr = std::unique_ptr<EVP_PKEY, decltype([](auto *pkey) { EVP_PKEY_free(pkey); })>;
using BIGNUM_unique_ptr = std::unique_ptr<BIGNUM, decltype([](auto *bn) { BN_free(bn); })>;
using OSSL_PARAM_BLD_unique_ptr
    = std::unique_ptr<OSSL_PARAM_BLD, decltype([](auto *param_bld) { OSSL_PARAM_BLD_free(param_bld); })>;
using OSSL_PARAM_unique_ptr = std::unique_ptr<OSSL_PARAM, decltype([](auto *params) { OSSL_PARAM_free(params); })>;
using EVP_PKEY_CTX_unique_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype([](auto *ctx) { EVP_PKEY_CTX_free(ctx); })>;
using ECDSA_SIG_unique_ptr = std::unique_ptr<ECDSA_SIG, decltype([](auto *sig) { ECDSA_SIG_free(sig); })>;
using EVP_MD_CTX_unique_ptr = std::unique_ptr<EVP_MD_CTX, decltype([](auto *ctx) { EVP_MD_CTX_free(ctx); })>;

EVP_PKEY_unique_ptr load_rsa_key(const std::vector<uint8_t> &dnskey) {
    // If the first byte is non-zero, then it is the length,
    // if it is zero, then the length is encoded in the next two bytes.
    int exponent_size;
    uint16_t exponent_length;
    if (dnskey[0] != 0) {
        exponent_length = dnskey[0];
        exponent_size = 1;
    } else {
        exponent_length = (static_cast<uint16_t>(dnskey[1]) << 8) | dnskey[2];
        exponent_size = 3;
    }
    if (dnskey.size() - exponent_size <= exponent_length) throw std::runtime_error("Invalid RSA key length");

    BIGNUM_unique_ptr e{BN_bin2bn(dnskey.data() + exponent_size, exponent_length, nullptr)};
    BIGNUM_unique_ptr n{BN_bin2bn(dnskey.data() + exponent_size + exponent_length,
                                  dnskey.size() - exponent_size - exponent_length, nullptr)};
    if (e == nullptr || n == nullptr) throw std::runtime_error("Failed to load RSA parameters");

    OSSL_PARAM_BLD_unique_ptr param_bld{OSSL_PARAM_BLD_new()};
    if (param_bld == nullptr ||                                        //
        OSSL_PARAM_BLD_push_BN(param_bld.get(), "e", e.get()) != 1 ||  //
        OSSL_PARAM_BLD_push_BN(param_bld.get(), "n", n.get()) != 1) {
        throw std::runtime_error("Failed to build RSA parameters");
    }

    OSSL_PARAM_unique_ptr params{OSSL_PARAM_BLD_to_param(param_bld.get())};
    if (params == nullptr) throw std::runtime_error("Failed to build RSA parameters");

    EVP_PKEY_CTX_unique_ptr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)};
    if (ctx == nullptr) throw std::runtime_error("Failed to create RSA context");
    if (EVP_PKEY_fromdata_init(ctx.get()) != 1) throw std::runtime_error("Failed to init RSA PKEY");

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
        throw std::runtime_error("Failed to construct RSA key");
    }
    return EVP_PKEY_unique_ptr{pkey};
}

EVP_PKEY_unique_ptr load_ecdsa_key(const std::vector<uint8_t> &dnskey, const std::string &curve) {
    // DNSSEC stores key in uncompressed format and OpenSSL needs it to be
    // specified in the first byte of the key data.
    std::vector<uint8_t> key;
    key.reserve(dnskey.size() + 1);
    key.push_back(POINT_CONVERSION_UNCOMPRESSED);
    key.append_range(dnskey);

    auto curve_copy{curve};
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", curve_copy.data(), 0),
        OSSL_PARAM_construct_octet_string("pub", key.data(), key.size()),
        OSSL_PARAM_construct_end(),
    };

    EVP_PKEY_CTX_unique_ptr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
    if (ctx == nullptr) throw std::runtime_error("Failed to create RSA context");
    if (EVP_PKEY_fromdata_init(ctx.get()) != 1) throw std::runtime_error("Failed to init RSA PKEY");

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        throw std::runtime_error("Failed to construct ECDSA key");
    }
    return EVP_PKEY_unique_ptr{pkey};
}

EVP_PKEY_unique_ptr load_eddsa_key(const std::vector<uint8_t> &dnskey, int type) {
    auto *pkey = EVP_PKEY_new_raw_public_key(type, nullptr, dnskey.data(), dnskey.size());
    if (pkey == nullptr) throw std::runtime_error("Failed to load EdDSA key");
    return EVP_PKEY_unique_ptr{pkey};
}

// Converts public key from the format used by DNSSEC into the format used by OpenSSL.
EVP_PKEY_unique_ptr load_dnskey(const DNSKEY &dnskey) {
    switch (dnskey.algorithm) {
        case SigningAlgorithm::RSASHA1:
        case SigningAlgorithm::RSASHA256:
        case SigningAlgorithm::RSASHA512: return load_rsa_key(dnskey.key);
        case SigningAlgorithm::ECDSAP256SHA256:
            if (dnskey.key.size() != 64) throw std::runtime_error("Invalid key length");
            return load_ecdsa_key(dnskey.key, "prime256v1");
        case SigningAlgorithm::ECDSAP384SHA384:
            if (dnskey.key.size() != 96) throw std::runtime_error("Invalid key length");
            return load_ecdsa_key(dnskey.key, "secp384r1");
        case SigningAlgorithm::ED25519: return load_eddsa_key(dnskey.key, EVP_PKEY_ED25519);
        case SigningAlgorithm::ED448:   return load_eddsa_key(dnskey.key, EVP_PKEY_ED448);
        default:                        throw std::runtime_error("Unknown signing algorithm");
    }
}

std::vector<uint8_t> load_ecdsa_signature(const std::vector<uint8_t> &rrsig) {
    ECDSA_SIG_unique_ptr sig{ECDSA_SIG_new()};
    int component_size = rrsig.size() / 2;
    BIGNUM *r = BN_bin2bn(rrsig.data(), component_size, nullptr);
    BIGNUM *s = BN_bin2bn(rrsig.data() + component_size, component_size, nullptr);
    if (sig == nullptr || r == nullptr || s == nullptr || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
        BN_free(r);
        BN_free(s);
        throw std::runtime_error("Failed to load ECDSA signature");
    }

    auto der_length = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (der_length <= 0) throw std::runtime_error("Failed to get DER signature length");

    // i2d_ECDSA_SIG modifies the second argument so pass it a copy of `der`.
    std::vector<uint8_t> der(der_length);
    auto *tmp = der.data();
    if (i2d_ECDSA_SIG(sig.get(), &tmp) != der_length) {
        throw std::runtime_error("Failed to convert ECDSA signature to DER");
    }
    return der;
}

// Converts signature from the format used by DNSSEC into the format used by OpenSSL (when needed).
std::vector<uint8_t> load_signature(const RRSIG &rrsig) {
    switch (rrsig.algorithm) {
        case SigningAlgorithm::RSASHA1:
        case SigningAlgorithm::RSASHA256:
        case SigningAlgorithm::RSASHA512:
        case SigningAlgorithm::ED25519:
        case SigningAlgorithm::ED448:     return rrsig.signature;
        case SigningAlgorithm::ECDSAP256SHA256:
            if (rrsig.signature.size() != 64) throw std::runtime_error("Invalid RRSIG size");
            return load_ecdsa_signature(rrsig.signature);
        case SigningAlgorithm::ECDSAP384SHA384:
            if (rrsig.signature.size() != 96) throw std::runtime_error("Invalid RRSIG size");
            return load_ecdsa_signature(rrsig.signature);
        default: throw std::runtime_error("Unknown signing algorithm");
    }
}

const EVP_MD *get_ds_digest_algorithm(DigestAlgorithm algorithm) {
    switch (algorithm) {
        case DigestAlgorithm::SHA1:   return EVP_sha1();
        case DigestAlgorithm::SHA256: return EVP_sha256();
        case DigestAlgorithm::SHA384: return EVP_sha384();
        default:                      throw std::runtime_error("Unknown digest algorithm");
    }
}

const EVP_MD *get_rrsig_digest_algorithm(SigningAlgorithm algorithm) {
    switch (algorithm) {
        case SigningAlgorithm::RSASHA1:
        case SigningAlgorithm::RSASHA256:
        case SigningAlgorithm::ECDSAP256SHA256: return EVP_sha256();
        case SigningAlgorithm::ECDSAP384SHA384: return EVP_sha384();
        case SigningAlgorithm::RSASHA512:       return EVP_sha512();
        case SigningAlgorithm::ED25519:
        case SigningAlgorithm::ED448:           return nullptr;
        default:                                throw std::runtime_error("Unknown digest algorithm");
    }
}

const EVP_MD *get_nsec3_hash_algorithm(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::SHA1: return EVP_sha1();
        default:                  throw std::runtime_error("Unknown digest algorithm");
    }
}

std::vector<std::string_view> domain_to_labels(const std::string_view &domain) {
    assert(!domain.empty());
    std::vector<std::string_view> labels;
    auto pos = domain.length() - 1;
    while (pos > 0) {
        auto next_pos = domain.find_last_of('.', pos - 1);
        if (next_pos == std::string::npos) {
            labels.emplace_back(domain.cbegin(), domain.cbegin() + pos);
            break;
        }

        labels.emplace_back(domain.cbegin() + next_pos + 1, domain.cbegin() + pos);
        pos = next_pos;
    }
    return labels;
}

std::string join_labels(const std::vector<std::string_view> &labels, size_t n) {
    assert(n <= labels.size());
    std::string result;
    auto last_n_labels = labels | std::views::take(n) | std::views::reverse;
    for (const auto &label : last_n_labels) {
        result += label;
        result += '.';
    }
    return result;
}

struct RRWithData {
    std::reference_wrapper<const RR> rr;
    std::vector<std::string_view> labels;
    std::vector<uint8_t> data;

    RRWithData(const RR &rr, std::vector<std::string_view> &&labels) : rr(rr), labels(labels) {}
};

std::vector<RRWithData> add_data_to_rrset(const std::vector<RR> &rrset) {
    std::vector<RRWithData> result;
    result.reserve(rrset.size());
    for (const auto &rr : rrset) {
        RRWithData rr_with_data{rr, domain_to_labels(rr.domain)};
        switch (rr.type) {
            case RRType::A: {
                auto address = std::get<A>(rr.data).address;
                const auto *address_ptr = reinterpret_cast<const uint8_t *>(&address);
                rr_with_data.data.assign(address_ptr, address_ptr + sizeof(address));
            } break;
            case RRType::NS:    write_domain(rr_with_data.data, std::get<NS>(rr.data).domain); break;
            case RRType::CNAME: write_domain(rr_with_data.data, std::get<CNAME>(rr.data).domain); break;
            case RRType::SOA:   {
                const auto &soa = std::get<SOA>(rr.data);
                write_domain(rr_with_data.data, soa.master_name);
                write_domain(rr_with_data.data, soa.rname);
                write_u32(rr_with_data.data, soa.serial);
                write_u32(rr_with_data.data, soa.refresh);
                write_u32(rr_with_data.data, soa.retry);
                write_u32(rr_with_data.data, soa.expire);
                write_u32(rr_with_data.data, soa.negative_ttl);
            } break;
            case RRType::HINFO: {
                const auto &hinfo = std::get<HINFO>(rr.data);
                write_char_string(rr_with_data.data, hinfo.cpu);
                write_char_string(rr_with_data.data, hinfo.os);
            } break;
            case RRType::TXT: {
                const auto &strings = std::get<TXT>(rr.data).strings;
                for (const auto &string : strings) write_char_string(rr_with_data.data, string);
            } break;
            case RRType::AAAA: {
                auto address = std::get<AAAA>(rr.data).address;
                const auto *address_ptr = reinterpret_cast<const uint8_t *>(&address);
                rr_with_data.data.assign(address_ptr, address_ptr + sizeof(address));
            } break;
            case RRType::DS:     rr_with_data.data = std::get<DS>(rr.data).data; break;
            case RRType::NSEC:   rr_with_data.data = std::get<NSEC>(rr.data).data; break;
            case RRType::DNSKEY: rr_with_data.data = std::get<DNSKEY>(rr.data).data; break;
            case RRType::NSEC3:  rr_with_data.data = std::get<NSEC3>(rr.data).data; break;
            case RRType::OPT:    throw std::runtime_error("OPT RR cannot have RRSIG");
            case RRType::RRSIG:  throw std::runtime_error("RRSIG RR cannot have RRSIG");
            default:             throw std::runtime_error("Unknown RR type");
        }
        result.push_back(rr_with_data);
    }
    return result;
}

class RRSIGDigest {
public:
    RRSIGDigest(EVP_MD_CTX *ctx, const EVP_MD *algorithm, EVP_PKEY *pkey) : ctx(ctx) {
        if (EVP_DigestVerifyInit(ctx, nullptr, algorithm, nullptr, pkey) != 1) {
            throw std::runtime_error("Failed to initialize RRSIG digest");
        }
    }
    virtual ~RRSIGDigest() = default;

    virtual void update(const std::vector<uint8_t> &data) = 0;
    virtual void update(uint16_t value) = 0;
    virtual void update(uint32_t value) = 0;
    virtual bool verify(const std::vector<uint8_t> &signature) = 0;

    void update(CastableEnum<uint16_t> auto value) { update(std::to_underlying(value)); }

protected:
    EVP_MD_CTX *ctx;
};

class RRSIGStreamDigest : public RRSIGDigest {
public:
    RRSIGStreamDigest(EVP_MD_CTX *ctx, const EVP_MD *algorithm, EVP_PKEY *pkey) : RRSIGDigest(ctx, algorithm, pkey) {}

    void update(const std::vector<uint8_t> &data) override {
        if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) != 1) {
            throw std::runtime_error("Failed to update RRSIG digest");
        }
    }

    void update(uint16_t value) override {
        auto value_net = htons(value);
        if (EVP_DigestVerifyUpdate(ctx, &value_net, sizeof(value_net)) != 1) {
            throw std::runtime_error("Failed to update RRSIG digest");
        }
    }

    void update(uint32_t value) override {
        auto value_net = htonl(value);
        if (EVP_DigestVerifyUpdate(ctx, &value_net, sizeof(value_net)) != 1) {
            throw std::runtime_error("Failed to update RRSIG digest");
        }
    }

    bool verify(const std::vector<uint8_t> &signature) override {
        return EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1;
    }
};

class RRSIGOneShotDigest : public RRSIGDigest {
public:
    RRSIGOneShotDigest(EVP_MD_CTX *ctx, const EVP_MD *algorithm, EVP_PKEY *pkey) : RRSIGDigest(ctx, algorithm, pkey) {}

    void update(const std::vector<uint8_t> &data) override { buffer.append_range(data); }
    void update(uint16_t value) override { write_u16(buffer, value); }
    void update(uint32_t value) override { write_u32(buffer, value); }

    bool verify(const std::vector<uint8_t> &signature) override {
        return EVP_DigestVerify(ctx, signature.data(), signature.size(), buffer.data(), buffer.size()) == 1;
    }

private:
    std::vector<uint8_t> buffer;
};

std::unique_ptr<RRSIGDigest> new_rrsig_digest(EVP_MD_CTX *ctx, const DNSKEY &dnskey) {
    const auto *algorithm = get_rrsig_digest_algorithm(dnskey.algorithm);
    auto pkey = load_dnskey(dnskey);

    switch (dnskey.algorithm) {
        case SigningAlgorithm::RSASHA1:
        case SigningAlgorithm::RSASHA256:
        case SigningAlgorithm::ECDSAP256SHA256:
        case SigningAlgorithm::ECDSAP384SHA384:
        case SigningAlgorithm::RSASHA512:       return std::make_unique<RRSIGStreamDigest>(ctx, algorithm, pkey.get());
        case SigningAlgorithm::ED25519:
        case SigningAlgorithm::ED448:           return std::make_unique<RRSIGOneShotDigest>(ctx, algorithm, pkey.get());
        default:                                throw std::runtime_error("Unknown digest algorithm");
    }
}

int compare_domains(const std::vector<std::string_view> &a, const std::vector<std::string_view> &b) {
    auto a_it = a.cbegin();
    auto b_it = b.cbegin();
    while (a_it != a.cend() && b_it != b.cend()) {
        auto result = a_it->compare(*b_it);
        if (result != 0) return result;
        ++a_it, ++b_it;
    }
    if (a_it != a.cend()) return +1;
    if (b_it != b.cend()) return -1;
    return 0;
}

bool is_domain_covered(const std::string &domain, const std::string &owner, const std::string &next_domain) {
    auto domain_labels = domain_to_labels(domain);
    auto owner_labels = domain_to_labels(owner);
    auto next_domain_labels = domain_to_labels(next_domain);

    // If the next domain comes before the owner name, it means that this is the last NSEC
    // and its next domain wrap back to the first RR.
    if (compare_domains(next_domain_labels, owner_labels) < 0) {
        // Domain must be either before or after both the owner and the next domain.
        auto result1 = compare_domains(domain_labels, owner_labels);
        auto result2 = compare_domains(domain_labels, next_domain_labels);
        return (result1 < 0 && result2 < 0) || (result1 > 0 && result2 > 0);
    }

    // Otherwise, the order is normal, domain must be between the owner and the next domain.
    return compare_domains(owner_labels, domain_labels) < 0 && compare_domains(domain_labels, next_domain_labels) < 0;
}

bool find_covering_nsec(const std::vector<RR> &nsec_rrset, const std::string &domain) {
    return std::ranges::any_of(nsec_rrset, [&](const auto &nsec_rr) {
        const auto &nsec = std::get<NSEC>(nsec_rr.data);
        return is_domain_covered(domain, nsec_rr.domain, nsec.next_domain);
    });
}

std::optional<NSEC> find_matching_nsec(const std::vector<RR> &nsec_rrset, const std::string &domain) {
    const auto &nsec_rr = std::ranges::find(nsec_rrset, domain, &RR::domain);
    if (nsec_rr == nsec_rrset.end()) return std::nullopt;
    return std::get<NSEC>(nsec_rr->data);
}

std::string get_nsec3_domain(const NSEC3 &nsec3, const std::string_view &domain, const std::string &zone_domain) {
    EVP_MD_CTX_unique_ptr ctx{EVP_MD_CTX_new()};
    if (ctx == nullptr) throw std::runtime_error("Failed to create digest context");

    const auto *hash_algorithm = get_nsec3_hash_algorithm(nsec3.algorithm);
    auto digest_size = EVP_MD_get_size(hash_algorithm);
    if (digest_size <= 0) throw std::runtime_error("Failed to get digest size");

    std::vector<uint8_t> canonical_domain;
    write_domain(canonical_domain, domain);

    std::vector<uint8_t> digest(digest_size);
    if (EVP_DigestInit(ctx.get(), hash_algorithm) != 1 ||                                      //
        EVP_DigestUpdate(ctx.get(), canonical_domain.data(), canonical_domain.size()) != 1 ||  //
        EVP_DigestUpdate(ctx.get(), nsec3.salt.data(), nsec3.salt.size()) != 1 ||              //
        EVP_DigestFinal(ctx.get(), digest.data(), nullptr) != 1) {
        throw std::runtime_error("Failed to calculate NSEC3 digest");
    }

    for (uint16_t i = 0; i < nsec3.iterations; i++) {
        if (EVP_DigestInit(ctx.get(), hash_algorithm) != 1 ||                          //
            EVP_DigestUpdate(ctx.get(), digest.data(), digest.size()) != 1 ||          //
            EVP_DigestUpdate(ctx.get(), nsec3.salt.data(), nsec3.salt.size()) != 1 ||  //
            EVP_DigestFinal(ctx.get(), digest.data(), nullptr) != 1) {
            throw std::runtime_error("Failed to calculate NSEC3 digest");
        }
    }

    return base32hex_encode(digest) + "." + zone_domain;
}

std::optional<NSEC3> find_covering_nsec3(const std::vector<RR> &nsec3_rrset, const std::string_view &domain,
                                         const std::string &zone_domain) {
    if (nsec3_rrset.empty()) return std::nullopt;
    const auto &nsec3 = std::get<NSEC3>(nsec3_rrset[0].data);

    auto covered_domain = get_nsec3_domain(nsec3, domain, zone_domain);
    for (const auto &nsec3_rr : nsec3_rrset) {
        const auto &nsec3 = std::get<NSEC3>(nsec3_rr.data);
        auto next_domain = base32hex_encode(nsec3.next_domain_hash) + "." + zone_domain;
        if (is_domain_covered(covered_domain, nsec3_rr.domain, next_domain)) return std::get<NSEC3>(nsec3_rr.data);
    }
    return std::nullopt;
}

std::optional<NSEC3> find_matching_nsec3(const std::vector<RR> &nsec3_rrset, const std::string_view &domain,
                                         const std::string &zone_domain) {
    if (nsec3_rrset.empty()) return std::nullopt;
    const auto &nsec3 = std::get<NSEC3>(nsec3_rrset[0].data);

    auto matching_domain = get_nsec3_domain(nsec3, domain, zone_domain);
    auto nsec3_rr = std::ranges::find(nsec3_rrset, matching_domain, &RR::domain);
    if (nsec3_rr == nsec3_rrset.end()) return std::nullopt;
    return std::get<NSEC3>(nsec3_rr->data);
}

struct EncloserProof {
    std::string closest_encloser_domain;
    bool next_closer_opt_out;
};

std::optional<EncloserProof> verify_closest_encloser_proof(const std::vector<RR> &nsec3_rrset,
                                                           const std::string &domain, const std::string &zone_domain) {
    if (nsec3_rrset.empty()) return std::nullopt;

    std::optional<NSEC3> next_closer;
    std::string_view sname{domain};
    for (;;) {
        auto nsec3 = find_matching_nsec3(nsec3_rrset, sname, zone_domain);
        if (nsec3.has_value()) {
            if (!next_closer.has_value()) return std::nullopt;
            if (nsec3->types.contains(RRType::DNAME)) return std::nullopt;
            if (nsec3->types.contains(RRType::NS) && !nsec3->types.contains(RRType::SOA)) return std::nullopt;
            return EncloserProof{
                .closest_encloser_domain = std::string{sname},
                .next_closer_opt_out = next_closer->opt_out,
            };
        }

        next_closer = find_covering_nsec3(nsec3_rrset, sname, zone_domain);

        if (sname == ".") return std::nullopt;
        auto next_label_index = sname.find('.');
        assert(next_label_index != std::string::npos);
        if (next_label_index != sname.length() - 1) next_label_index++;
        sname.remove_prefix(next_label_index);
    }
}
}  // namespace

namespace dnssec {
int get_ds_digest_size(DigestAlgorithm algorithm) {
    auto digest_size = EVP_MD_get_size(get_ds_digest_algorithm(algorithm));
    if (digest_size <= 0) throw std::runtime_error("Failed to get digest size");
    return digest_size;
}

uint16_t compute_key_tag(const std::vector<uint8_t> &data) {
    uint64_t ac = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i & 1) {
            ac += data[i];
        } else {
            ac += static_cast<uint64_t>(data[i]) << 8;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    return ac & 0xFFFF;
}

bool authenticate_rrset(const std::vector<RR> &rrset, const std::vector<RRSIG> &rrsigs,
                        const std::vector<DNSKEY> &dnskeys, const std::vector<RR> &nsec3_rrset,
                        const std::vector<RR> &nsec_rrset, const std::string &zone_domain) {
    if (rrset.empty()) return true;
    if (rrsigs.empty() || dnskeys.empty()) return false;

    try {
        auto rrs_with_data = add_data_to_rrset(rrset);
        std::ranges::sort(rrs_with_data, [](const auto &a, const auto &b) {
            int result = compare_domains(a.labels, b.labels);
            if (result != 0) return result < 0;

            result = std::memcmp(a.data.data(), b.data.data(), std::min(a.data.size(), b.data.size()));
            if (result != 0) return result < 0;

            return a.data.size() > b.data.size() ? false : true;
        });

        EVP_MD_CTX_unique_ptr ctx{EVP_MD_CTX_new()};
        if (ctx == nullptr) return false;

        const auto &rrset_labels = rrs_with_data[0].labels;
        auto time_now = time(nullptr);
        std::vector<uint8_t> canonical_domain;
        for (const auto &rrsig : rrsigs) {
            try {
                if (rrsig.type_covered != rrset[0].type) continue;
                if (!(rrsig.inception_time <= time_now && time_now <= rrsig.expiration_time)) continue;
                if (rrsig.signer_name != zone_domain) continue;
                if (rrsig.labels > rrset_labels.size()) continue;

                canonical_domain.clear();
                if (rrsig.labels < rrset_labels.size()) {
                    if (rrset[0].type != RRType::NSEC3 && rrset[0].type != RRType::NSEC) {
                        // Response is expanded from a wildcard, verify the non-existence of the exact match.
                        if (!nsec3_rrset.empty()) {
                            // RFC5155 Section 8.8.
                            // The closest encloser is the immediate ancestor to the wildcard,
                            // so the next closer is one label longer.
                            std::string next_closer = join_labels(rrset_labels, rrsig.labels + 1);
                            if (!find_covering_nsec3(nsec3_rrset, next_closer, zone_domain).has_value()) continue;
                        } else {
                            if (!find_covering_nsec(nsec_rrset, rrset[0].domain)) continue;
                        }
                    }

                    std::string wildcard_domain = "*." + join_labels(rrset_labels, rrsig.labels);
                    write_domain(canonical_domain, wildcard_domain);
                } else {
                    write_domain(canonical_domain, rrset[0].domain);
                }

                auto signature = load_signature(rrsig);
                for (const auto &dnskey : dnskeys) {
                    try {
                        if (rrsig.key_tag != dnskey.key_tag) continue;
                        if (rrsig.algorithm != dnskey.algorithm) continue;

                        auto digest = new_rrsig_digest(ctx.get(), dnskey);
                        digest->update(rrsig.data);
                        for (const auto &rr_with_data : rrs_with_data) {
                            digest->update(canonical_domain);
                            digest->update(rr_with_data.rr.get().type);
                            digest->update(DNSClass::Internet);
                            digest->update(rrsig.original_ttl);
                            digest->update(static_cast<uint16_t>(rr_with_data.data.size()));
                            digest->update(rr_with_data.data);
                        }
                        if (digest->verify(signature)) return true;
                    } catch (...) {
                        // Try different DNSKEY.
                        continue;
                    }
                }
            } catch (...) {
                // Try different RRSIG.
                continue;
            }
        }
    } catch (...) {
    }
    return false;
}

bool authenticate_delegation(const std::vector<RR> &dnskey_rrset, const std::vector<DS> &dss,
                             const std::vector<RRSIG> &rrsigs, const std::vector<RR> &nsec3_rrset,
                             const std::vector<RR> &nsec_rrset, const std::string &zone_domain) {
    if (dnskey_rrset.empty() || dss.empty()) return false;

    EVP_MD_CTX_unique_ptr ctx{EVP_MD_CTX_new()};
    if (ctx == nullptr) return false;

    std::vector<uint8_t> canonical_domain;
    std::vector<uint8_t> digest;
    std::vector<DNSKEY> verified_dnskeys;
    for (const auto &ds : dss) {
        try {
            const auto *digest_algorithm = get_ds_digest_algorithm(ds.digest_algorithm);
            auto digest_size = EVP_MD_get_size(digest_algorithm);
            if (digest_size <= 0) continue;

            for (const auto &dnskey_rr : dnskey_rrset) {
                if (dnskey_rr.type != RRType::DNSKEY) return false;
                const auto &dnskey = std::get<DNSKEY>(dnskey_rr.data);

                if (dnskey.algorithm != ds.signing_algorithm) continue;
                if (dnskey.key_tag != ds.key_tag) continue;

                canonical_domain.clear();
                write_domain(canonical_domain, dnskey_rr.domain);

                digest.resize(digest_size);
                if (EVP_DigestInit(ctx.get(), digest_algorithm) != 1 ||                                    //
                    EVP_DigestUpdate(ctx.get(), canonical_domain.data(), canonical_domain.size()) != 1 ||  //
                    EVP_DigestUpdate(ctx.get(), dnskey.data.data(), dnskey.data.size()) != 1 ||            //
                    EVP_DigestFinal(ctx.get(), digest.data(), nullptr) != 1) {
                    continue;
                }

                if (digest == ds.digest) {
                    verified_dnskeys.push_back(dnskey);
                    break;
                }
            }
        } catch (...) {
            // Try different DS.
            continue;
        }
    }
    return authenticate_rrset(dnskey_rrset, rrsigs, verified_dnskeys, nsec3_rrset, nsec_rrset, zone_domain);
}

bool authenticate_name_error(const std::string &domain, const std::vector<RR> &nsec3_rrset,
                             const std::vector<RR> &nsec_rrset, const std::string &zone_domain) {
    try {
        if (!nsec3_rrset.empty()) {
            // RFC5155 Section 8.4.
            // Verify the closest encloser proof and find the NSEC3 covering the wildcard at the closest encloser.
            auto encloser_proof = verify_closest_encloser_proof(nsec3_rrset, domain, zone_domain);
            if (!encloser_proof.has_value()) return false;

            auto wildcard_domain = "*." + encloser_proof->closest_encloser_domain;
            return find_covering_nsec3(nsec3_rrset, wildcard_domain, zone_domain).has_value();
        }

        // RFC4035 Section 5.4.
        // Find the NSEC covering the domain, which proves the non-existence of the exact match.
        if (!find_covering_nsec(nsec_rrset, domain)) return false;

        // Find the NSEC covering a wildcard, which proves that the answer couldn't have been generated.
        auto labels = domain_to_labels(domain);
        auto zone_labels_num = domain_to_labels(zone_domain).size();
        for (size_t i = labels.size(); i > zone_labels_num; i--) {
            auto wildcard_domain = "*." + join_labels(labels, i - 1);
            if (find_covering_nsec(nsec_rrset, wildcard_domain)) return true;
        }
    } catch (...) {
    }
    return false;
}

bool authenticate_no_ds(const std::string &domain, const std::vector<RR> &nsec3_rrset,
                        const std::vector<RR> &nsec_rrset, const std::string &zone_domain) {
    try {
        // RFC6840 Section 4.4.
        // Insecure delegation requires the absence of DS and SOA, and presence of NS.
        auto check_types = [](const std::unordered_set<RRType> &types) {
            return !types.contains(RRType::DS) && !types.contains(RRType::SOA) && types.contains(RRType::NS);
        };

        if (!nsec3_rrset.empty()) {
            // RFC5155 Section 8.6.
            // Find the matching NSEC3 and check its types.
            auto nsec3 = find_matching_nsec3(nsec3_rrset, domain, zone_domain);
            if (nsec3.has_value()) return check_types(nsec3->types);

            // If no NSEC3 matches the name, the next closer NSEC3 must have opt-out flag set.
            auto encloser_proof = verify_closest_encloser_proof(nsec3_rrset, domain, zone_domain);
            return encloser_proof.has_value() && encloser_proof->next_closer_opt_out;
        }

        // RFC4035 Section 5.4.
        // Find the matching NSEC and check its types.
        auto nsec = find_matching_nsec(nsec_rrset, domain);
        if (!nsec.has_value()) return false;

        return check_types(nsec->types);
    } catch (...) {
        return false;
    }
}

bool authenticate_no_rrset(RRType rr_type, const std::string &domain, const std::vector<RR> &nsec3_rrset,
                           const std::vector<RR> &nsec_rrset, const std::string &zone_domain) {
    try {
        // RFC6840 Section 4.3.
        // Validating a no data response requires the absence of both the query type and the CNAME.
        auto check_types = [rr_type](const std::unordered_set<RRType> &types) {
            return !types.contains(rr_type) && !types.contains(RRType::CNAME);
        };

        if (!nsec3_rrset.empty()) {
            // RFC5155 Section 8.5.
            // Find the matching NSEC3 and check its types.
            auto nsec3 = find_matching_nsec3(nsec3_rrset, domain, zone_domain);
            if (nsec3.has_value()) return check_types(nsec3->types);

            // RFC5155 Section 8.7.
            // Verify the closest encloser proof, find the NSEC3 matching
            // the wildcard at the closest encloser, and check its types.
            auto encloser_proof = verify_closest_encloser_proof(nsec3_rrset, domain, zone_domain);
            if (!encloser_proof.has_value()) return false;

            auto wildcard_domain = "*." + encloser_proof->closest_encloser_domain;
            auto wildcard_nsec3 = find_matching_nsec3(nsec3_rrset, wildcard_domain, zone_domain);
            return wildcard_nsec3.has_value() && check_types(wildcard_nsec3->types);
        }

        // RFC4035 Section 5.4.
        // If there is a matching NSEC, verify that both the QTYPE and the CNAME are not present.
        auto nsec = find_matching_nsec(nsec_rrset, domain);
        if (nsec.has_value()) return check_types(nsec->types);

        // Otherwise, find the NSEC covering the domain, which proves the non-existence of the domain.
        return find_covering_nsec(nsec_rrset, domain);
    } catch (...) {
        return false;
    }
}
};  // namespace dnssec
