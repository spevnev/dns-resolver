#define _POSIX_C_SOURCE 200809L
#include "dnssec.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"

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

// Converts raw signature format used by DNSSEC into DER format used by OpenSSL.
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

const EVP_MD *get_ds_digest_algorithm(uint8_t algorithm) {
    switch (algorithm) {
        case DIGEST_SHA1:   return EVP_sha1();
        case DIGEST_SHA256: return EVP_sha256();
        case DIGEST_SHA384: return EVP_sha384();
        default:            return NULL;
    }
}

const EVP_MD *get_rrsig_digest_algorithm(uint8_t algorithm) {
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

EVP_PKEY *load_dnskey(const DNSKEY *dnskey) {
    switch (dnskey->algorithm) {
        case SIGNING_ECDSAP256SHA256:
            if (dnskey->key_size != 64) return NULL;
            return load_ecdsa_key(dnskey->key, dnskey->key_size, "prime256v1");
        case SIGNING_ECDSAP384SHA384:
            if (dnskey->key_size != 96) return NULL;
            return load_ecdsa_key(dnskey->key, dnskey->key_size, "secp384r1");
        default: return NULL;
    }
}

unsigned char *load_signature(const RRSIG *rrsig, size_t *signature_length_out) {
    switch (rrsig->algorithm) {
        case SIGNING_ECDSAP256SHA256:
            if (rrsig->signature_size != 64) return NULL;
            return load_ecdsa_signature(rrsig->signature, rrsig->signature_size, signature_length_out);
        case SIGNING_ECDSAP384SHA384:
            if (rrsig->signature_size != 96) return NULL;
            return load_ecdsa_signature(rrsig->signature, rrsig->signature_size, signature_length_out);
        default: return NULL;
    }
}
