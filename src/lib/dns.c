#define _POSIX_C_SOURCE 200809L
#include "dns.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include "dnssec.h"
#include "encode.h"
#include "vector.h"

static const size_t LABEL_SIZE = 64;
static const uint8_t LABEL_DATA_MASK = 63;      // 00111111
static const uint8_t LABEL_TYPE_MASK = 192;     // 11000000
static const uint8_t LABEL_TYPE_POINTER = 192;  // 11000000
static const uint8_t LABEL_TYPE_NORMAL = 0;     // 00000000

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static uint16_t compute_key_tag(const uint8_t *data, uint16_t data_length) {
    uint64_t ac = 0;
    for (int i = 0; i < data_length; ++i) ac += (i & 1) ? data[i] : data[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return ac & 0xFFFF;
}

static bool write(Request *request, const void *value, size_t size) {
    if (request->length + size > request->size) return false;
    memcpy(request->buffer + request->length, value, size);
    request->length += size;
    return true;
}

static bool write_u8(Request *request, uint8_t value) { return write(request, &value, sizeof(value)); }

static bool write_u16(Request *request, uint16_t value) {
    uint16_t net_value = htons(value);
    return write(request, &net_value, sizeof(net_value));
}

static bool write_domain(Request *request, const char *domain) {
    if (is_root_domain(domain)) return write_u8(request, 0);

    const char *start = domain;
    for (const char *cur = domain; *cur != '\0'; cur++) {
        if (*cur == '.') {
            uint8_t length = cur - start;
            if (!write_u8(request, length)) return false;
            if (!write(request, start, length)) return false;
            start = cur + 1;
        }
    }
    return write_u8(request, 0);
}

static bool read(Response *response, void *out, size_t size) {
    if (response->current + size > response->length) return false;
    memcpy(out, response->current + response->buffer, size);
    response->current += size;
    return true;
}

static bool read_u8(Response *response, uint8_t *out) { return read(response, out, sizeof(*out)); }

static bool read_u16(Response *response, uint16_t *out) {
    uint16_t value;
    if (!read(response, &value, sizeof(value))) return false;
    *out = ntohs(value);
    return true;
}

static bool read_u32(Response *response, uint32_t *out) {
    uint32_t value;
    if (!read(response, &value, sizeof(value))) return false;
    *out = ntohl(value);
    return true;
}

static void to_lowercase(const char *in, char *out, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if ('A' <= in[i] && in[i] <= 'Z') {
            out[i] = in[i] - 'A' + 'a';
        } else {
            out[i] = in[i];
        }
    }
}

static bool read_domain_rec(Response *response, bool allow_compression, char *output_buffer, int buffer_size) {
    // Handle root domain.
    if (response->buffer[response->current] == 0) {
        output_buffer[0] = '.';
        output_buffer[1] = '\0';
        response->current++;
        return true;
    }

    char *out = output_buffer;
    char label[LABEL_SIZE];
    for (;;) {
        uint8_t byte;
        if (!read_u8(response, &byte)) return false;
        uint8_t type = byte & LABEL_TYPE_MASK;
        uint8_t data = byte & LABEL_DATA_MASK;

        if (type == LABEL_TYPE_NORMAL) {
            uint8_t label_len = data;
            if (label_len == 0) {
                *out = '\0';
                return true;
            }

            // Check that there is enough space for label, dot, and null terminator.
            if (label_len + 2 > buffer_size) return false;
            buffer_size -= label_len + 1;

            if (!read(response, label, label_len)) return false;
            to_lowercase(label, out, label_len);
            out += label_len;
            *(out++) = '.';
        } else if (allow_compression && type == LABEL_TYPE_POINTER) {
            uint8_t lower_half;
            if (!read_u8(response, &lower_half)) return false;

            uint16_t offset = ((uint16_t) data << 8) | lower_half;
            if (offset >= response->length) return false;

            Response pointer_response = {
                .buffer = response->buffer,
                .current = offset,
                .length = response->length,
            };
            return read_domain_rec(&pointer_response, allow_compression, out, buffer_size);
        } else {
            return false;
        }
    }
}

static bool read_domain(Response *response, bool allow_compression, char **domain_out) {
    char buffer[DOMAIN_SIZE];
    if (!read_domain_rec(response, allow_compression, buffer, DOMAIN_SIZE)) return false;

    char *domain = strdup(buffer);
    if (domain == NULL) return false;

    *domain_out = domain;
    return true;
}

static bool read_soa_data(Response *response, SOA *soa) {
    if (!read_domain(response, true, &soa->master_name)) goto error;
    if (!read_domain(response, true, &soa->rname)) goto error;
    if (!read_u32(response, &soa->serial)) goto error;
    if (!read_u32(response, &soa->refresh)) goto error;
    if (!read_u32(response, &soa->retry)) goto error;
    if (!read_u32(response, &soa->expire)) goto error;
    if (!read_u32(response, &soa->negative_ttl)) goto error;
    return true;
error:
    free(soa->master_name);
    free(soa->rname);
    return false;
}

static bool read_char_string(Response *response, char **string_out) {
    uint8_t length;
    if (!read_u8(response, &length)) return false;

    char *string = malloc((length + 1) * sizeof(*string));
    if (string == NULL) return false;

    if (!read(response, string, length)) {
        free(string);
        return false;
    }
    string[length] = '\0';

    *string_out = string;
    return true;
}

// Copies the data (excluding first length byte) into buffer and replaces each
// length byte with '\0' to transform it into array of null-terminated strings.
// TXT's data is a dynamic array of strings pointing to the buffer.
static bool read_txt_data(Response *response, uint16_t data_length, TXT *txt) {
    txt->buffer = malloc(data_length * sizeof(*txt->buffer));
    if (txt->buffer == NULL) goto error;
    memcpy(txt->buffer, response->buffer + response->current + 1, data_length - 1);
    txt->buffer[data_length - 1] = '\0';

    char *cur = txt->buffer;
    uint32_t end = response->current + data_length;
    while (response->current < end) {
        uint8_t length;
        if (!read_u8(response, &length)) goto error;

        if (response->current + length > response->length) goto error;
        response->current += length;

        VECTOR_PUSH(txt, cur);
        cur += length;
        *(cur++) = '\0';
    }
    return true;
error:
    free(txt->buffer);
    VECTOR_FREE(txt);
    return false;
}

static bool read_opt_data(Response *response, uint16_t data_length, OPT *opt) {
    uint16_t option_code, option_length;
    while (data_length > 0) {
        if (!read_u16(response, &option_code)) return false;
        if (!read_u16(response, &option_length)) return false;

        if (OPTION_HEADER_SIZE + option_length > data_length) return false;
        data_length -= OPTION_HEADER_SIZE + option_length;

        switch (option_code) {
            case OPT_COOKIE:
                if (!(16 <= option_length && option_length <= 40)) return false;

                opt->has_cookies = true;
                if (!read(response, &opt->cookies.client, sizeof(opt->cookies.client))) return false;

                opt->cookies.server_size = option_length - sizeof(opt->cookies.client);
                if (!read(response, opt->cookies.server, opt->cookies.server_size)) return false;
                break;
            default:
                if (response->current + option_length > response->length) return false;
                response->current += option_length;
                break;
        }
    }
    return true;
}

static bool read_ds_data(Response *response, uint16_t data_length, DS *ds) {
    const uint8_t *data_pointer = response->buffer + response->current;
    if (!read_u16(response, &ds->key_tag)) goto error;
    if (!read_u8(response, &ds->signing_algorithm)) goto error;
    if (!read_u8(response, &ds->digest_algorithm)) goto error;
    if ((ds->digest_size = get_ds_digest_size(ds->digest_algorithm)) <= 0) goto error;
    if ((ds->digest = malloc(ds->digest_size)) == NULL) goto error;
    if (!read(response, ds->digest, ds->digest_size)) goto error;

    // Save data to verify the RRSIG later.
    ds->data_length = data_length;
    if ((ds->data = malloc(ds->data_length)) == NULL) goto error;
    memcpy(ds->data, data_pointer, ds->data_length);

    return true;
error:
    free(ds->digest);
    return false;
}

static bool read_rrsig_data(Response *response, uint16_t data_length, RRSIG *rrsig) {
    uint32_t data_offset = response->current;
    if (!read_u16(response, &rrsig->type_covered)) goto error;
    if (!read_u8(response, &rrsig->algorithm)) goto error;
    if (!read_u8(response, &rrsig->labels)) goto error;
    if (!read_u32(response, &rrsig->original_ttl)) goto error;
    if (!read_u32(response, &rrsig->expiration_time)) goto error;
    if (!read_u32(response, &rrsig->inception_time)) goto error;
    if (!read_u16(response, &rrsig->key_tag)) goto error;
    if (!read_domain(response, false, &rrsig->signer_name)) goto error;
    uint32_t data_without_signature_length = response->current - data_offset;

    // The remaining part of data is the signature.
    rrsig->signature_size = data_length - data_without_signature_length;
    if ((rrsig->signature = malloc(rrsig->signature_size)) == NULL) goto error;
    if (!read(response, rrsig->signature, rrsig->signature_size)) goto error;

    // Save data without signature to verify it later.
    rrsig->data_length = data_without_signature_length;
    if ((rrsig->data = malloc(rrsig->data_length)) == NULL) goto error;
    memcpy(rrsig->data, response->buffer + data_offset, rrsig->data_length);

    return true;
error:
    free(rrsig->signer_name);
    free(rrsig->signature);
    return false;
}

static bool read_rr_type_bitmap(Response *response, uint16_t data_length, RRTypeVec *types) {
    uint8_t window_block, bitmap_length;
    uint8_t bitmap[32];
    while (data_length > 0) {
        if (!read_u8(response, &window_block)) return false;
        if (!read_u8(response, &bitmap_length)) return false;
        if (!(1 <= bitmap_length && bitmap_length <= 32)) return false;
        if (!read(response, bitmap, bitmap_length)) return false;
        data_length -= 2 + bitmap_length;

        RRType type_upper_half = ((RRType) window_block) << 8;
        for (uint32_t i = 0; i < bitmap_length; i++) {
            for (int j = 0; j < 8; j++) {
                if (bitmap[i] & 0x80) {
                    RRType type = type_upper_half | (i * 8 + j);
                    VECTOR_PUSH(types, type);
                }
                bitmap[i] <<= 1;
            }
        }
    }
    return true;
}

static bool read_nsec_data(Response *response, uint16_t data_length, NSEC *nsec) {
    uint32_t offset_before_data = response->current;
    if (!read_domain(response, false, &nsec->next_domain)) return false;

    data_length -= response->current - offset_before_data;
    if (!read_rr_type_bitmap(response, data_length, &nsec->types)) {
        free(nsec->next_domain);
        return false;
    }

    return true;
}

static bool read_dnskey_data(Response *response, uint16_t data_length, DNSKEY *dnskey) {
    const uint8_t *data_pointer = response->buffer + response->current;

    if (!read(response, &dnskey->flags, sizeof(dnskey->flags))) goto error;
    if (!read_u8(response, &dnskey->protocol)) goto error;
    if (dnskey->protocol != DNSKEY_PROTOCOL) goto error;
    if (!read_u8(response, &dnskey->algorithm)) goto error;

    // The remaining part of data is the key.
    dnskey->key_size = data_length - DNSKEY_HEADER_SIZE;
    if ((dnskey->key = malloc(dnskey->key_size)) == NULL) goto error;
    if (!read(response, dnskey->key, dnskey->key_size)) goto error;

    dnskey->key_tag = compute_key_tag(data_pointer, data_length);

    // Save data to verify the RRSIG later.
    dnskey->data_length = data_length;
    if ((dnskey->data = malloc(dnskey->data_length)) == NULL) goto error;
    memcpy(dnskey->data, data_pointer, dnskey->data_length);

    return true;
error:
    free(dnskey->key);
    return false;
}

static bool read_nsec3_data(Response *response, uint16_t data_length, NSEC3 *nsec) {
    uint32_t offset_before_data = response->current;
    if (!read_u8(response, &nsec->algorithm)) goto error;
    if (!read(response, &nsec->flags, sizeof(nsec->flags))) goto error;
    if (!read_u16(response, &nsec->iterations)) goto error;
    if (!read_u8(response, &nsec->salt_length)) goto error;
    if (nsec->salt_length > 0) {
        if ((nsec->salt = malloc(nsec->salt_length)) == NULL) goto error;
        if (!read(response, nsec->salt, nsec->salt_length)) goto error;
    }
    if (!read_u8(response, &nsec->hash_length)) goto error;
    if (nsec->hash_length == 0) goto error;
    if ((nsec->next_domain_hash = malloc(nsec->hash_length)) == NULL) goto error;
    if (!read(response, nsec->next_domain_hash, nsec->hash_length)) goto error;

    data_length -= response->current - offset_before_data;
    if (!read_rr_type_bitmap(response, data_length, &nsec->types)) goto error;

    return true;
error:
    free(nsec->salt);
    free(nsec->next_domain_hash);
    return false;
}

static const char *type_to_str(RRType type) {
    switch (type) {
        case TYPE_A:      return "A";
        case TYPE_NS:     return "NS";
        case TYPE_CNAME:  return "CNAME";
        case TYPE_SOA:    return "SOA";
        case TYPE_HINFO:  return "HINFO";
        case TYPE_TXT:    return "TXT";
        case TYPE_AAAA:   return "AAAA";
        case TYPE_OPT:    return "OPT";
        case TYPE_DS:     return "DS";
        case TYPE_RRSIG:  return "RRSIG";
        case TYPE_NSEC:   return "NSEC";
        case TYPE_DNSKEY: return "DNSKEY";
        case TYPE_NSEC3:  return "NSEC3";
        default:          {
            static char buffer[10];
            snprintf(buffer, sizeof(buffer), "TYPE%hu", type);
            return buffer;
        }
    }
}

bool is_root_domain(const char *domain) { return domain[0] == '.' && domain[1] == '\0'; }

char *fully_qualify_domain(const char *domain) {
    size_t domain_len = strlen(domain);
    if (domain_len > MAX_DOMAIN_LENGTH) return NULL;

    char *fqd = malloc(domain_len + 2);
    if (fqd == NULL) return NULL;
    to_lowercase(domain, fqd, domain_len);

    bool is_fully_qualified = domain_len >= 1 && domain[domain_len - 1] == '.';
    if (!is_fully_qualified) {
        fqd[domain_len] = '.';
        domain_len++;
    }
    fqd[domain_len] = '\0';

    return fqd;
}

void print_rr(RR *rr) {
    printf("%-24s %-8u %-6s ", rr->domain, rr->ttl, type_to_str(rr->type));
    switch (rr->type) {
        case TYPE_A: {
            char addr_buffer[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &rr->data.ip4_addr, addr_buffer, sizeof(addr_buffer)) == NULL) {
                printf("invalid address");
            } else {
                printf("%s", addr_buffer);
            }
        } break;
        case TYPE_NS:
        case TYPE_CNAME: printf("%s", rr->data.domain); break;
        case TYPE_SOA:
            printf("%s %s %u %u %u %u %u", rr->data.soa.master_name, rr->data.soa.rname, rr->data.soa.serial,
                   rr->data.soa.refresh, rr->data.soa.retry, rr->data.soa.expire, rr->data.soa.negative_ttl);
            break;
        case TYPE_HINFO: printf("%s %s", rr->data.hinfo.cpu, rr->data.hinfo.os); break;
        case TYPE_TXT:
            for (uint32_t i = 0; i < rr->data.txt.length; i++) printf(" \"%s\"", rr->data.txt.data[i]);
            break;
        case TYPE_AAAA: {
            char addr_buffer[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &rr->data.ip6_addr, addr_buffer, sizeof(addr_buffer)) == NULL) {
                printf("invalid address");
            } else {
                printf("%s", addr_buffer);
            }
        } break;
        case TYPE_DS: {
            char *digest = hex_string_encode(rr->data.ds.digest, rr->data.ds.digest_size);
            printf("%u %u %u %s", rr->data.ds.key_tag, rr->data.ds.signing_algorithm, rr->data.ds.digest_algorithm,
                   digest);
            free(digest);
        } break;
        case TYPE_RRSIG: {
            char *signature = base64_encode(rr->data.rrsig.signature, rr->data.rrsig.signature_size);
            printf("%s %u %u %u %u %u %u %s %s", type_to_str(rr->data.rrsig.type_covered), rr->data.rrsig.algorithm,
                   rr->data.rrsig.labels, rr->data.rrsig.original_ttl, rr->data.rrsig.expiration_time,
                   rr->data.rrsig.inception_time, rr->data.rrsig.key_tag, rr->data.rrsig.signer_name, signature);
            free(signature);
        } break;
        case TYPE_NSEC:
            printf("%s (", rr->data.nsec.next_domain);
            for (uint32_t i = 0; i < rr->data.nsec.types.length; i++) {
                if (i > 0) printf(" ");
                printf("%s", type_to_str(rr->data.nsec.types.data[i]));
            }
            printf(")");
            break;
        case TYPE_DNSKEY: {
            char *key = base64_encode(rr->data.dnskey.key, rr->data.dnskey.key_size);
            printf("%u %u %u %s", ntohs(rr->data.dnskey.flags), rr->data.dnskey.protocol, rr->data.dnskey.protocol,
                   key);
            free(key);
        } break;
        case TYPE_NSEC3: {
            char *salt = "-";
            if (rr->data.nsec3.salt != NULL) salt = hex_string_encode(rr->data.nsec3.salt, rr->data.nsec3.salt_length);
            char *hash = base32_encode(rr->data.nsec3.next_domain_hash, rr->data.nsec3.hash_length);
            printf("%u %u %u %s %s (", rr->data.nsec3.algorithm, rr->data.nsec3.flags, rr->data.nsec3.iterations, salt,
                   hash);
            for (uint32_t i = 0; i < rr->data.nsec3.types.length; i++) {
                if (i > 0) printf(" ");
                printf("%s", type_to_str(rr->data.nsec3.types.data[i]));
            }
            printf(")");
            if (rr->data.nsec3.salt != NULL) free(salt);
            free(hash);
        } break;
    }
    printf("\n");
}

void free_rr(RR *rr) {
    if (rr == NULL) return;
    switch (rr->type) {
        case TYPE_A:
        case TYPE_AAAA:
        case TYPE_OPT:   break;
        case TYPE_NS:
        case TYPE_CNAME: free(rr->data.domain); break;
        case TYPE_SOA:
            free(rr->data.soa.master_name);
            free(rr->data.soa.rname);
            break;
        case TYPE_HINFO:
            free(rr->data.hinfo.cpu);
            free(rr->data.hinfo.os);
            break;
        case TYPE_TXT:
            free(rr->data.txt.buffer);
            VECTOR_FREE(&rr->data.txt);
            break;
        case TYPE_DS:
            free(rr->data.ds.digest);
            free(rr->data.ds.data);
            break;
        case TYPE_RRSIG:
            free(rr->data.rrsig.signer_name);
            free(rr->data.rrsig.signature);
            free(rr->data.rrsig.data);
            break;
        case TYPE_NSEC:
            free(rr->data.nsec.next_domain);
            VECTOR_FREE(&rr->data.nsec.types);
            break;
        case TYPE_DNSKEY:
            free(rr->data.dnskey.key);
            free(rr->data.dnskey.data);
            break;
        case TYPE_NSEC3:
            free(rr->data.nsec3.salt);
            free(rr->data.nsec3.next_domain_hash);
            VECTOR_FREE(&rr->data.nsec3.types);
            break;
    }
    free(rr->domain);
    free(rr);
}

bool write_request(Request *request, bool enable_rd, const char *domain, RRType qtype, bool enable_edns,
                   bool enable_cookie, bool enable_dnssec, DNSCookies *cookies, uint16_t *id_out) {
    uint16_t id;
    if (getrandom(&id, sizeof(id), 0) != sizeof(id)) return false;

    DNSHeader header = {
        .id = htons(id),
        .enable_rd = enable_rd,
        .opcode = OPCODE_QUERY,
        .is_response = false,
        .checking_disabled = false,
        .question_count = htons(1),
        .additional_count = enable_edns ? htons(1) : 0,
    };
    if (!write(request, &header, sizeof(header))) return false;

    // Write question.
    if (!write_domain(request, domain)) return false;
    if (!write_u16(request, qtype)) return false;
    if (!write_u16(request, CLASS_IN)) return false;

    // Write the OPT pseudo-RR (RFC6891):
    if (enable_edns) {
        // Domain must be root.
        if (!write_u8(request, 0)) return false;
        if (!write_u16(request, TYPE_OPT)) return false;
        // CLASS contains max UDP payload size.
        if (!write_u16(request, MAX(request->size, STANDARD_UDP_PAYLOAD_SIZE))) return false;

        // TTL contains additional OPT fields.
        OptTtlFields opt_fields = {
            .version = EDNS_VERSION,
            .dnssec_ok = enable_dnssec,
        };
        if (!write(request, &opt_fields, sizeof(opt_fields))) return false;

        // Write options.
        if (enable_cookie) {
            if (!cookies->is_client_set) {
                cookies->is_client_set = true;
                if (getrandom(&cookies->client, sizeof(cookies->client), 0) != sizeof(cookies->client)) return false;
            }

            uint16_t option_length = sizeof(cookies->client) + cookies->server_size;
            if (!write_u16(request, OPTION_HEADER_SIZE + option_length)) return false;
            if (!write_u16(request, OPT_COOKIE)) return false;
            if (!write_u16(request, option_length)) return false;
            if (!write(request, &cookies->client, sizeof(cookies->client))) return false;
            if (!write(request, cookies->server, cookies->server_size)) return false;
        } else {
            if (!write_u16(request, 0)) return false;
        }
    }

    *id_out = id;
    return true;
}

bool read_response_header(Response *response, uint16_t request_id, DNSHeader *header) {
    if (!read_u16(response, &header->id)) return false;
    if (!read(response, &header->flags, sizeof(header->flags))) return false;
    if (!read_u16(response, &header->question_count)) return false;
    if (!read_u16(response, &header->answer_count)) return false;
    if (!read_u16(response, &header->authority_count)) return false;
    if (!read_u16(response, &header->additional_count)) return false;

    if (!header->is_response) return false;
    if (header->opcode != OPCODE_QUERY) return false;
    if (header->id != request_id) return false;
    if (header->question_count != 1) return false;  // RFC9619

    return true;
}

bool validate_question(Response *response, RRType request_qtype, const char *request_domain) {
    char *domain;
    if (!read_domain(response, true, &domain)) return false;

    int result = strcmp(domain, request_domain);
    free(domain);
    if (result != 0) return false;

    RRType qtype;
    uint16_t qclass;
    if (!read_u16(response, &qtype)) return false;
    if (!read_u16(response, &qclass)) return false;

    if (qtype != request_qtype) return false;
    if (qclass != CLASS_IN) return false;

    return true;
}

bool read_rr(Response *response, RR **rr_out) {
    free_rr(*rr_out);
    *rr_out = NULL;

    RR *rr = malloc(sizeof(*rr));
    if (rr == NULL) return false;

    uint16_t class, data_length;
    if (!read_domain(response, true, &rr->domain)) {
        free(rr);
        return false;
    }
    if (!read_u16(response, &rr->type)) goto error;
    if (!read_u16(response, &class)) goto error;
    if (!read_u32(response, &rr->ttl)) goto error;
    if (!read_u16(response, &data_length)) goto error;

    if (rr->type != TYPE_OPT) {
        // Class must be Internet, or it is OPT RR whose CLASS contains UDP payload size (RFC6891).
        if (class != CLASS_IN) goto error;
        // TTL is an unsigned number between 0 and 2147483647 (RFC2181).
        // Treat TTL values with the MBS set as if the value was zero.
        if (rr->ttl > MAX_TTL) rr->ttl = 0;
    }

    if (response->current + data_length > response->length) goto error;
    memset(&rr->data, 0, sizeof(rr->data));

    switch (rr->type) {
        case TYPE_A:
            if (!read(response, &rr->data.ip4_addr, sizeof(rr->data.ip4_addr))) goto error;
            break;
        case TYPE_NS:
        case TYPE_CNAME:
            if (!read_domain(response, true, &rr->data.domain)) goto error;
            break;
        case TYPE_SOA:
            if (!read_soa_data(response, &rr->data.soa)) goto error;
            break;
        case TYPE_HINFO:
            if (!read_char_string(response, &rr->data.hinfo.cpu)) goto error;
            if (!read_char_string(response, &rr->data.hinfo.os)) {
                free(rr->data.hinfo.cpu);
                goto error;
            }
            break;
        case TYPE_TXT:
            if (!read_txt_data(response, data_length, &rr->data.txt)) goto error;
            break;
        case TYPE_AAAA:
            if (!read(response, &rr->data.ip6_addr, sizeof(rr->data.ip6_addr))) goto error;
            break;
        case TYPE_OPT: {
            if (!is_root_domain(rr->domain)) goto error;

            // Nameserver's max UDP payload size is stored in the class field.
            rr->data.opt.udp_payload_size = MAX(class, STANDARD_UDP_PAYLOAD_SIZE);

            uint32_t net_ttl = htonl(rr->ttl);
            OptTtlFields opt_fields;
            memcpy(&opt_fields, &net_ttl, sizeof(opt_fields));

            rr->data.opt.extended_rcode = opt_fields.extended_rcode;
            if (opt_fields.version > EDNS_VERSION) goto error;

            if (!read_opt_data(response, data_length, &rr->data.opt)) goto error;
        } break;
        case TYPE_DS:
            if (!read_ds_data(response, data_length, &rr->data.ds)) goto error;
            break;
        case TYPE_RRSIG:
            if (!read_rrsig_data(response, data_length, &rr->data.rrsig)) goto error;
            break;
        case TYPE_NSEC:
            if (!read_nsec_data(response, data_length, &rr->data.nsec)) goto error;
            break;
        case TYPE_DNSKEY:
            if (!read_dnskey_data(response, data_length, &rr->data.dnskey)) goto error;
            break;
        case TYPE_NSEC3:
            if (!read_nsec3_data(response, data_length, &rr->data.nsec3)) goto error;
            break;
        default: response->current += data_length; break;
    }

    *rr_out = rr;
    return true;
error:
    free(rr->domain);
    free(rr);
    return false;
}
