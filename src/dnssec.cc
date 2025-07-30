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
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>
#include "dns.hh"
#include "encode.hh"
#include "write.hh"

struct RRWithData {
    std::reference_wrapper<const RR> rr;
    std::vector<std::string_view> labels;
    std::vector<uint8_t> data;

    RRWithData(const RR &rr, std::vector<std::string_view> &&labels) : rr(rr), labels(labels) {}
};

using EVP_PKEY_unique_ptr = std::unique_ptr<EVP_PKEY, decltype([](auto *pkey) { EVP_PKEY_free(pkey); })>;
using BIGNUM_unique_ptr = std::unique_ptr<BIGNUM, decltype([](auto *bn) { BN_free(bn); })>;
using OSSL_PARAM_BLD_unique_ptr
    = std::unique_ptr<OSSL_PARAM_BLD, decltype([](auto *param_bld) { OSSL_PARAM_BLD_free(param_bld); })>;
using OSSL_PARAM_unique_ptr = std::unique_ptr<OSSL_PARAM, decltype([](auto *params) { OSSL_PARAM_free(params); })>;
using EVP_PKEY_CTX_unique_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype([](auto *ctx) { EVP_PKEY_CTX_free(ctx); })>;
using ECDSA_SIG_unique_ptr = std::unique_ptr<ECDSA_SIG, decltype([](auto *sig) { ECDSA_SIG_free(sig); })>;
using EVP_MD_CTX_unique_ptr = std::unique_ptr<EVP_MD_CTX, decltype([](auto *ctx) { EVP_MD_CTX_free(ctx); })>;

static EVP_PKEY_unique_ptr load_rsa_key(const std::vector<uint8_t> &dnskey) {
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

static EVP_PKEY_unique_ptr load_ecdsa_key(const std::vector<uint8_t> &dnskey, const std::string &curve) {
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

static EVP_PKEY_unique_ptr load_eddsa_key(const std::vector<uint8_t> &dnskey, int type) {
    auto pkey = EVP_PKEY_new_raw_public_key(type, NULL, dnskey.data(), dnskey.size());
    if (pkey == nullptr) throw std::runtime_error("Failed to load EdDSA key");
    return EVP_PKEY_unique_ptr{pkey};
}

// Converts public key from the format used by DNSSEC into the format used by OpenSSL.
static EVP_PKEY_unique_ptr load_dnskey(const DNSKEY &dnskey) {
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

static std::vector<uint8_t> load_ecdsa_signature(const std::vector<uint8_t> &rrsig) {
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
    auto tmp = der.data();
    if (i2d_ECDSA_SIG(sig.get(), &tmp) != der_length) {
        throw std::runtime_error("Failed to convert ECDSA signature to DER");
    }
    return der;
}

// Converts signature from the format used by DNSSEC into the format used by OpenSSL (when needed).
static std::vector<uint8_t> load_signature(const RRSIG &rrsig) {
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

static const EVP_MD *get_ds_digest_algorithm(DigestAlgorithm algorithm) {
    switch (algorithm) {
        case DigestAlgorithm::SHA1:   return EVP_sha1();
        case DigestAlgorithm::SHA256: return EVP_sha256();
        case DigestAlgorithm::SHA384: return EVP_sha384();
        default:                      throw std::runtime_error("Unknown digest algorithm");
    }
}

static const EVP_MD *get_rrsig_digest_algorithm(SigningAlgorithm algorithm) {
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

static const EVP_MD *get_nsec3_hash_algorithm(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::SHA1: return EVP_sha1();
        default:                  throw std::runtime_error("Unknown digest algorithm");
    }
}

static std::vector<std::string_view> domain_to_labels(const std::string_view &domain) {
    std::vector<std::string_view> labels;
    auto pos = domain.size() - 1;
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

static std::vector<RRWithData> add_data_to_rrset(const std::vector<RR> &rrset) {
    std::vector<RRWithData> result;
    result.reserve(rrset.size());

    for (const auto &rr : rrset) {
        RRWithData rr_with_data{rr, domain_to_labels(rr.domain)};
        switch (rr.type) {
            case RRType::A: {
                auto address = std::get<A>(rr.data).address;
                auto address_ptr = reinterpret_cast<const uint8_t *>(&address);
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
                auto address_ptr = reinterpret_cast<const uint8_t *>(&address);
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

    virtual void update(const std::vector<uint8_t> &data) {
        if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) != 1) {
            throw std::runtime_error("Failed to update RRSIG digest");
        }
    }

    virtual void update(uint16_t value) {
        auto value_net = htons(value);
        if (EVP_DigestVerifyUpdate(ctx, &value_net, sizeof(value_net)) != 1) {
            throw std::runtime_error("Failed to update RRSIG digest");
        }
    }

    virtual void update(uint32_t value) {
        auto value_net = htonl(value);
        if (EVP_DigestVerifyUpdate(ctx, &value_net, sizeof(value_net)) != 1) {
            throw std::runtime_error("Failed to update RRSIG digest");
        }
    }

    virtual bool verify(const std::vector<uint8_t> &signature) {
        return EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1;
    }
};

class RRSIGOneShotDigest : public RRSIGDigest {
public:
    RRSIGOneShotDigest(EVP_MD_CTX *ctx, const EVP_MD *algorithm, EVP_PKEY *pkey)
        : RRSIGDigest(ctx, algorithm, pkey), buffer() {}

    virtual void update(const std::vector<uint8_t> &data) { buffer.append_range(data); }
    virtual void update(uint16_t value) { write_u16(buffer, value); }
    virtual void update(uint32_t value) { write_u32(buffer, value); }

    virtual bool verify(const std::vector<uint8_t> &signature) {
        return EVP_DigestVerify(ctx, signature.data(), signature.size(), buffer.data(), buffer.size()) == 1;
    }

private:
    std::vector<uint8_t> buffer;
};

static std::unique_ptr<RRSIGDigest> new_rrsig_digest(EVP_MD_CTX *ctx, const DNSKEY &dnskey) {
    auto algorithm = get_rrsig_digest_algorithm(dnskey.algorithm);
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

static int compare_domains(const std::vector<std::string_view> &a, const std::vector<std::string_view> &b) {
    auto a_it = a.cbegin(), b_it = b.cbegin();
    while (a_it != a.cend() && b_it != b.cend()) {
        auto result = a_it->compare(*b_it);
        if (result != 0) return result;
        ++a_it, ++b_it;
    }
    if (a_it != a.cend()) return +1;
    if (b_it != b.cend()) return -1;
    return 0;
}

static bool is_domain_between(const std::string_view &domain, const std::string_view &before,
                              const std::string_view &after) {
    auto before_labels = domain_to_labels(before);
    auto after_labels = domain_to_labels(after);
    auto domain_labels = domain_to_labels(domain);
    return compare_domains(before_labels, domain_labels) < 0 && compare_domains(domain_labels, after_labels) < 0;
}

static std::string get_nsec3_domain(const NSEC3 &nsec3, const std::string_view &domain,
                                    const std::string &zone_domain) {
    EVP_MD_CTX_unique_ptr ctx{EVP_MD_CTX_new()};
    if (ctx == nullptr) throw std::runtime_error("Failed to create digest context");

    auto hash_algorithm = get_nsec3_hash_algorithm(nsec3.algorithm);
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

    return base32_encode(digest) + "." + zone_domain;
}

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

std::vector<DNSKEY> verify_dnskeys(const std::vector<RR> &dnskey_rrset, const std::vector<DS> &dss) {
    if (dnskey_rrset.empty() || dss.empty()) return {};

    EVP_MD_CTX_unique_ptr ctx{EVP_MD_CTX_new()};
    if (ctx == nullptr) return {};

    std::vector<uint8_t> canonical_domain, digest;
    std::vector<DNSKEY> verified_dnskeys;
    for (const auto &ds : dss) {
        try {
            auto digest_algorithm = get_ds_digest_algorithm(ds.digest_algorithm);
            auto digest_size = EVP_MD_get_size(digest_algorithm);
            if (digest_size <= 0) continue;

            for (const auto &dnskey_rr : dnskey_rrset) {
                const auto &dnskey = std::get<DNSKEY>(dnskey_rr.data);
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
    return verified_dnskeys;
}

bool verify_rrsig(const std::vector<RR> &rrset, const std::vector<RRSIG> &rrsigs, const std::vector<DNSKEY> &dnskeys,
                  const std::string &zone_domain) {
    if (rrset.empty()) return true;
    if (rrsigs.empty() || dnskeys.empty()) return false;

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

    auto time_now = time(nullptr);
    std::vector<uint8_t> canonical_domain;
    for (const auto &rrsig : rrsigs) {
        try {
            if (rrsig.type_covered != rrset[0].type) continue;
            if (!(rrsig.inception_time <= time_now && time_now <= rrsig.expiration_time)) continue;
            if (rrsig.signer_name != zone_domain) continue;
            if (rrsig.labels > rrs_with_data[0].labels.size()) continue;

            auto signature = load_signature(rrsig);
            for (const auto &dnskey : dnskeys) {
                try {
                    if (rrsig.key_tag != dnskey.key_tag) continue;
                    if (rrsig.algorithm != dnskey.algorithm) continue;
                    if (rrsig.signer_name != zone_domain) continue;

                    auto digest = new_rrsig_digest(ctx.get(), dnskey);
                    digest->update(rrsig.data);
                    for (const auto &rr_with_data : rrs_with_data) {
                        const RR &rr = rr_with_data.rr;

                        canonical_domain.clear();
                        write_domain(canonical_domain, rr.domain);

                        digest->update(canonical_domain);
                        digest->update(rr.type);
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
    return false;
}

bool nsec_covers_domain(const RR &nsec_rr, const std::string &domain) {
    auto &nsec = std::get<NSEC>(nsec_rr.data);
    return is_domain_between(domain, nsec_rr.domain, nsec.next_domain);
}

std::optional<NSEC3> find_covering_nsec3(const std::vector<RR> &nsec3_rrset, const std::string_view &domain,
                                         const std::string &zone_domain) {
    try {
        if (nsec3_rrset.empty()) return std::nullopt;
        auto &nsec3 = std::get<NSEC3>(nsec3_rrset[0].data);

        auto covered_domain = get_nsec3_domain(nsec3, domain, zone_domain);
        for (auto &nsec3_rr : nsec3_rrset) {
            auto &nsec3 = std::get<NSEC3>(nsec3_rr.data);
            auto next_domain = base32_encode(nsec3.next_domain_hash) + "." + zone_domain;
            if (is_domain_between(covered_domain, nsec3_rr.domain, next_domain)) return std::get<NSEC3>(nsec3_rr.data);
        }
    } catch (...) {
    }
    return std::nullopt;
}

std::optional<NSEC3> find_matching_nsec3(const std::vector<RR> &nsec3_rrset, const std::string_view &domain,
                                         const std::string &zone_domain) {
    try {
        if (nsec3_rrset.empty()) return std::nullopt;
        auto &nsec3 = std::get<NSEC3>(nsec3_rrset[0].data);

        auto matching_domain = get_nsec3_domain(nsec3, domain, zone_domain);
        for (auto &nsec3_rr : nsec3_rrset) {
            if (nsec3_rr.domain == matching_domain) return std::get<NSEC3>(nsec3_rr.data);
        }
    } catch (...) {
    }
    return std::nullopt;
}

std::optional<std::pair<std::string, NSEC3>> verify_closest_encloser_proof(const std::vector<RR> &nsec3_rrset,
                                                                           const std::string &domain,
                                                                           const std::string &zone_domain) {
    if (nsec3_rrset.empty()) return std::nullopt;

    std::optional<NSEC3> next_closer;
    std::string_view sname{domain};
    for (;;) {
        auto nsec3 = find_matching_nsec3(nsec3_rrset, sname, zone_domain);
        if (nsec3.has_value()) {
            if (!next_closer.has_value()) return std::nullopt;
            if (nsec3->types.contains(RRType::DNAME)) return std::nullopt;
            if (nsec3->types.contains(RRType::NS) && !nsec3->types.contains(RRType::SOA)) return std::nullopt;
            return std::pair<std::string, NSEC3>{std::string{sname}, std::move(next_closer.value())};
        }

        next_closer = find_covering_nsec3(nsec3_rrset, sname, zone_domain);

        if (sname == ".") return std::nullopt;
        auto next_label_index = sname.find('.');
        if (next_label_index != sname.size() - 1) next_label_index++;
        sname.remove_prefix(next_label_index);
    }
}
