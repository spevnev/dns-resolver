#define _POSIX_C_SOURCE 200809L
#include "dnssec.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"

typedef struct {
    RR *rr;
    StrVec labels;
} RRWithLabels;

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static EVP_PKEY *load_rsa_key(const uint8_t *dnssec_key, size_t dnssec_key_size) {
    // If the first byte is, non-zero then it is the length,
    // if it is 0, then the length is encoded in the next two bytes.
    uint16_t exponent_length;
    if (dnssec_key[0] != 0) {
        exponent_length = dnssec_key[0];
        dnssec_key_size--;
        dnssec_key++;
    } else {
        uint16_t exponent_length_net;
        memcpy(&exponent_length_net, dnssec_key + 1, sizeof(exponent_length_net));
        exponent_length = ntohs(exponent_length_net);
        dnssec_key_size -= 3;
        dnssec_key += 3;
    }
    if (dnssec_key_size <= exponent_length) return NULL;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM *params = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    BIGNUM *e = NULL, *n = NULL;

    if ((e = BN_bin2bn(dnssec_key, exponent_length, NULL)) == NULL) goto exit;
    if ((n = BN_bin2bn(dnssec_key + exponent_length, dnssec_key_size - exponent_length, NULL)) == NULL) goto exit;

    if ((param_bld = OSSL_PARAM_BLD_new()) == NULL) goto exit;
    if (OSSL_PARAM_BLD_push_BN(param_bld, "e", e) != 1) goto exit;
    if (OSSL_PARAM_BLD_push_BN(param_bld, "n", n) != 1) goto exit;
    if ((params = OSSL_PARAM_BLD_to_param(param_bld)) == NULL) goto exit;

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL) goto exit;
    if (EVP_PKEY_fromdata_init(ctx) != 1) goto exit;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        pkey = NULL;
        goto exit;
    }

exit:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    BN_free(n);
    BN_free(e);
    return pkey;
}

static EVP_PKEY *load_ecdsa_key(const uint8_t *dnssec_key, size_t dnssec_key_size, const char *curve) {
    EVP_PKEY *pkey = NULL;
    char *curve_copy = NULL;
    unsigned char *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if ((curve_copy = strdup(curve)) == NULL) goto exit;

    // DNSSEC stores key in uncompressed format and OpenSSL needs it to be
    // specified in the first byte of the key data.
    if ((key = OPENSSL_malloc(dnssec_key_size + 1)) == NULL) goto exit;
    key[0] = POINT_CONVERSION_UNCOMPRESSED;
    memcpy(key + 1, dnssec_key, dnssec_key_size);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", curve_copy, 0),
        OSSL_PARAM_construct_octet_string("pub", key, dnssec_key_size + 1),
        OSSL_PARAM_construct_end(),
    };

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL) goto exit;
    if (EVP_PKEY_fromdata_init(ctx) != 1) goto exit;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        pkey = NULL;
        goto exit;
    }

exit:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(key);
    free(curve_copy);
    return pkey;
}

// Converts public key from the format used by DNSSEC into the format used by OpenSSL.
static EVP_PKEY *load_dnskey(const DNSKEY *dnskey) {
    switch (dnskey->algorithm) {
        case SIGNING_RSASHA1:
        case SIGNING_RSASHA1NSEC3SHA1:
        case SIGNING_RSASHA256:
        case SIGNING_RSASHA512:        return load_rsa_key(dnskey->key, dnskey->key_size);
        case SIGNING_ECDSAP256SHA256:
            if (dnskey->key_size != 64) return NULL;
            return load_ecdsa_key(dnskey->key, dnskey->key_size, "prime256v1");
        case SIGNING_ECDSAP384SHA384:
            if (dnskey->key_size != 96) return NULL;
            return load_ecdsa_key(dnskey->key, dnskey->key_size, "secp384r1");
        default: return NULL;
    }
}

static unsigned char *load_ecdsa_signature(const uint8_t *dnssec_sig, size_t dnssec_sig_size, size_t *sig_length_out) {
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    int component_size = dnssec_sig_size / 2;
    if ((sig = ECDSA_SIG_new()) == NULL ||                                             //
        (r = BN_bin2bn(dnssec_sig, component_size, NULL)) == NULL ||                   //
        (s = BN_bin2bn(dnssec_sig + component_size, component_size, NULL)) == NULL ||  //
        !ECDSA_SIG_set0(sig, r, s)) {
        ECDSA_SIG_free(sig);
        BN_free(r);
        BN_free(s);
        return NULL;
    }

    int der_length = i2d_ECDSA_SIG(sig, NULL);
    if (der_length <= 0) {
        ECDSA_SIG_free(sig);
        return NULL;
    }

    unsigned char *der = OPENSSL_malloc(der_length);
    if (der == NULL) {
        ECDSA_SIG_free(sig);
        return NULL;
    }

    // i2d_ECDSA_SIG modifies the second argument so pass it a copy of `der`.
    unsigned char *tmp = der;
    if (i2d_ECDSA_SIG(sig, &tmp) != der_length) {
        ECDSA_SIG_free(sig);
        OPENSSL_free(der);
        return NULL;
    }
    ECDSA_SIG_free(sig);

    *sig_length_out = der_length;
    return der;
}

// Converts signature from the format used by DNSSEC into the format used by OpenSSL (when needed).
static unsigned char *load_signature(const RRSIG *rrsig, size_t *signature_length_out) {
    switch (rrsig->algorithm) {
        case SIGNING_RSASHA1:
        case SIGNING_RSASHA1NSEC3SHA1:
        case SIGNING_RSASHA256:
        case SIGNING_RSASHA512:
            // RSA signature format does not need to be converted.
            *signature_length_out = rrsig->signature_size;
            return rrsig->signature;
        case SIGNING_ECDSAP256SHA256:
            if (rrsig->signature_size != 64) return NULL;
            return load_ecdsa_signature(rrsig->signature, rrsig->signature_size, signature_length_out);
        case SIGNING_ECDSAP384SHA384:
            if (rrsig->signature_size != 96) return NULL;
            return load_ecdsa_signature(rrsig->signature, rrsig->signature_size, signature_length_out);
        default: return NULL;
    }
}

static void free_signature(const RRSIG *rrsig, unsigned char *signature) {
    switch (rrsig->algorithm) {
        case SIGNING_RSASHA1:
        case SIGNING_RSASHA1NSEC3SHA1:
        case SIGNING_RSASHA256:
        case SIGNING_RSASHA512:        break;
        case SIGNING_ECDSAP256SHA256:
        case SIGNING_ECDSAP384SHA384:  OPENSSL_free(signature); break;
    }
}

static size_t domain_to_canonical(const char *domain, uint8_t output_buffer[static DOMAIN_SIZE]) {
    if (is_root_domain(domain)) {
        *output_buffer = 0;
        return 1;
    }

    uint8_t *out = output_buffer;
    const char *start = domain;
    for (const char *cur = domain; *cur != '\0'; cur++) {
        if (*cur == '.') {
            uint8_t length = cur - start;
            *out++ = length;
            memcpy(out, start, length);
            out += length;
            start = cur + 1;
        }
    }
    *out++ = 0;

    return out - output_buffer;
}

static uint8_t count_domain_labels(const char *domain) {
    if (is_root_domain(domain)) return 0;

    uint8_t labels = 0;
    for (const char *cur = domain; *cur != '\0'; cur++) {
        if (*cur == '.') labels++;
    }
    return labels;
}

static bool domain_to_labels(const char *domain, StrVec *labels) {
    if (is_root_domain(domain)) return true;

    const char *start = domain;
    for (const char *cur = domain; *cur != '\0'; cur++) {
        if (*cur == '.') {
            size_t length = cur - start;
            char *label = malloc(length + 1);
            if (label == NULL) return false;
            memcpy(label, start, length);
            label[length] = '\0';

            VECTOR_PUSH(labels, label);
            start = cur + 1;
        }
    }
    return true;
}

static int canonical_order_comparator(const void *a_raw, const void *b_raw) {
    RRWithLabels a = *((const RRWithLabels *) a_raw);
    RRWithLabels b = *((const RRWithLabels *) b_raw);

    int result = 0;
    int i = a.labels.length - 1, j = b.labels.length - 1;
    while (result == 0 && i >= 0 && j >= 0) {
        result = strcmp(a.labels.data[i], b.labels.data[j]);
        i--;
        j--;
    }
    if (result != 0) return result;
    if (i >= 0) return +1;
    if (j >= 0) return -1;

    switch (a.rr->type) {
        case TYPE_DNSKEY: {
            DNSKEY *dnskey_a = &a.rr->data.dnskey;
            DNSKEY *dnskey_b = &b.rr->data.dnskey;

            result = memcmp(dnskey_a->data, dnskey_b->data, MIN(dnskey_a->data_length, dnskey_b->data_length));
            if (result != 0) return result;

            if (dnskey_a->data_length > dnskey_b->data_length) return +1;
            if (dnskey_a->data_length < dnskey_b->data_length) return -1;
            FATAL("Duplicate RR are not allowed");
        }
        default: FATAL("TODO: domains are equal, compare RDATA");
    }
}

static bool sort_rr_vec_canonically(RRVec rr_vec) {
    bool result = false;
    RRWithLabels *temp_rrs = NULL;

    size_t temp_rrs_size = rr_vec.length * sizeof(*temp_rrs);
    if ((temp_rrs = malloc(temp_rrs_size)) == NULL) goto exit;
    memset(temp_rrs, 0, temp_rrs_size);

    for (uint32_t i = 0; i < rr_vec.length; i++) {
        temp_rrs[i].rr = rr_vec.data[i];
        if (!domain_to_labels(rr_vec.data[i]->domain, &temp_rrs[i].labels)) goto exit;
    }

    qsort(temp_rrs, rr_vec.length, sizeof(*temp_rrs), canonical_order_comparator);
    result = true;

exit:
    for (uint32_t i = 0; i < rr_vec.length; i++) {
        rr_vec.data[i] = temp_rrs[i].rr;
        for (uint32_t j = 0; j < temp_rrs[i].labels.length; j++) free(temp_rrs[i].labels.data[j]);
        VECTOR_FREE(&temp_rrs[i].labels);
    }
    free(temp_rrs);
    return result;
}

static const EVP_MD *get_ds_digest_algorithm(uint8_t algorithm) {
    switch (algorithm) {
        case DIGEST_SHA1:   return EVP_sha1();
        case DIGEST_SHA256: return EVP_sha256();
        case DIGEST_SHA384: return EVP_sha384();
        default:            return NULL;
    }
}

static const EVP_MD *get_rrsig_digest_algorithm(uint8_t algorithm) {
    switch (algorithm) {
        case SIGNING_RSASHA1:
        case SIGNING_RSASHA1NSEC3SHA1: return EVP_sha1();
        case SIGNING_RSASHA256:
        case SIGNING_ECDSAP256SHA256:  return EVP_sha256();
        case SIGNING_ECDSAP384SHA384:  return EVP_sha384();
        case SIGNING_RSASHA512:        return EVP_sha512();
        default:                       return NULL;
    }
}

int get_ds_digest_size(uint8_t algorithm) {
    const EVP_MD *md = get_ds_digest_algorithm(algorithm);
    if (md == NULL) return -1;
    return EVP_MD_get_size(md);
}

bool verify_dnskeys(RRVec dnskeys, RRVec dss, RRVec *verified_dnskeys_out) {
    if (dnskeys.length == 0 || dss.length == 0) return false;

    bool result = false;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *digest_algorithm;
    int digest_size;
    unsigned char *digest = NULL;
    uint8_t canonical_domain[DOMAIN_SIZE];

    if ((ctx = EVP_MD_CTX_new()) == NULL) goto exit;
    for (uint32_t i = 0; i < dss.length; i++) {
        DS *ds = &dss.data[i]->data.ds;
        if ((digest_algorithm = get_ds_digest_algorithm(ds->digest_algorithm)) == NULL) goto exit;
        if ((digest_size = EVP_MD_get_size(digest_algorithm)) <= 0) goto exit;
        if ((digest = OPENSSL_realloc(digest, digest_size)) == NULL) goto exit;

        for (uint32_t i = 0; i < dnskeys.length; i++) {
            RR *dnskey_rr = dnskeys.data[i];
            DNSKEY *dnskey = &dnskey_rr->data.dnskey;
            if (dnskey->key_tag != ds->key_tag) continue;
            if (!dnskey->is_zone_key) continue;

            size_t canonical_length = domain_to_canonical(dnskey_rr->domain, canonical_domain);
            if (!EVP_DigestInit_ex(ctx, digest_algorithm, NULL)
                || !EVP_DigestUpdate(ctx, canonical_domain, canonical_length)
                || !EVP_DigestUpdate(ctx, dnskey->data, dnskey->data_length)
                || !EVP_DigestFinal_ex(ctx, digest, NULL)) {
                continue;
            }

            if (digest_size == ds->digest_size && memcmp(digest, ds->digest, digest_size) == 0) {
                VECTOR_PUSH(verified_dnskeys_out, dnskey_rr);
                result = true;
                break;
            }
        }
    }

exit:
    OPENSSL_free(digest);
    EVP_MD_CTX_free(ctx);
    return result;
}

bool verify_rrsig(RRVec rr_vec, uint16_t rr_type, const RR *rrsig_rr, RRVec dnskeys, const char *zone_domain) {
    if (rr_vec.length == 0 || dnskeys.length == 0) return false;

    bool result = false;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *signature = NULL;
    const EVP_MD *digest_algorithm = NULL;
    EVP_PKEY *pkey = NULL;

    time_t time_now = time(NULL);
    const RRSIG *rrsig = &rrsig_rr->data.rrsig;
    if (rrsig->type_covered != rr_type) goto exit;
    if (!(rrsig->inception_time <= time_now && time_now <= rrsig->expiration_time)) goto exit;
    if (strcmp(rrsig->signer_name, zone_domain) != 0) goto exit;
    if (strcmp(rrsig_rr->domain, rr_vec.data[0]->domain) != 0) goto exit;

    size_t signature_length;
    if ((signature = load_signature(rrsig, &signature_length)) == NULL) goto exit;
    if ((ctx = EVP_MD_CTX_new()) == NULL) goto exit;
    if (!sort_rr_vec_canonically(rr_vec)) goto exit;

    uint8_t canonical_domain[DOMAIN_SIZE];
    for (uint32_t i = 0; !result && i < dnskeys.length; i++) {
        RR *dnskey_rr = dnskeys.data[i];
        DNSKEY *dnskey = &dnskey_rr->data.dnskey;

        if (rrsig->key_tag != dnskey->key_tag) continue;
        if (rrsig->algorithm != dnskey->algorithm) continue;
        if (rrsig->labels > count_domain_labels(dnskey_rr->domain)) continue;
        if (strcmp(rrsig->signer_name, dnskey_rr->domain) != 0) continue;

        if ((digest_algorithm = get_rrsig_digest_algorithm(dnskey->algorithm)) == NULL) continue;
        if ((pkey = load_dnskey(dnskey)) == NULL) continue;

        if (EVP_DigestVerifyInit(ctx, NULL, digest_algorithm, NULL, pkey) != 1) goto bad_key;
        if (EVP_DigestVerifyUpdate(ctx, rrsig->data, rrsig->data_length) != 1) goto bad_key;

        for (uint32_t j = 0; j < rr_vec.length; j++) {
            RR *rr = rr_vec.data[j];

            size_t canonical_length = domain_to_canonical(rr->domain, canonical_domain);
            uint16_t type_net = htons(rr->type);
            uint16_t class_net = htons(CLASS_IN);
            uint32_t ttl_net = htonl(rrsig->original_ttl);

            assert(rr->type == TYPE_DNSKEY);
            uint16_t data_length_net = htons(rr->data.dnskey.data_length);

            if (EVP_DigestVerifyUpdate(ctx, canonical_domain, canonical_length) != 1
                || EVP_DigestVerifyUpdate(ctx, &type_net, sizeof(type_net)) != 1
                || EVP_DigestVerifyUpdate(ctx, &class_net, sizeof(class_net)) != 1
                || EVP_DigestVerifyUpdate(ctx, &ttl_net, sizeof(ttl_net)) != 1
                || EVP_DigestVerifyUpdate(ctx, &data_length_net, sizeof(data_length_net)) != 1
                || EVP_DigestVerifyUpdate(ctx, rr->data.dnskey.data, rr->data.dnskey.data_length) != 1) {
                goto bad_key;
            }
        }

        if (EVP_DigestVerifyFinal(ctx, signature, signature_length) == 1) result = true;

    bad_key:
        EVP_PKEY_free(pkey);
    }

exit:
    free_signature(rrsig, signature);
    EVP_MD_CTX_free(ctx);
    return result;
}
