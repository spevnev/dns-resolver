#ifndef DNSSEC_H
#define DNSSEC_H

#include <openssl/evp.h>
#include <stdint.h>
#include "dns.h"

const EVP_MD *get_ds_digest_algorithm(uint8_t algorithm);
const EVP_MD *get_rrsig_digest_algorithm(uint8_t algorithm);

EVP_PKEY *load_dnskey(const DNSKEY *dnskey);
unsigned char *load_signature(const RRSIG *rrsig, size_t *signature_length_out);
void free_signature(const RRSIG *rrsig, unsigned char *signature);

#endif  // DNSSEC_H
