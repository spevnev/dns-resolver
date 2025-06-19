#define _POSIX_C_SOURCE 200809L
#include "dns.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include "encode.h"
#include "vector.h"

static const uint8_t LABEL_DATA_MASK = 63;      // 00111111
static const uint8_t LABEL_TYPE_MASK = 192;     // 11000000
static const uint8_t LABEL_TYPE_POINTER = 192;  // 11000000
static const uint8_t LABEL_TYPE_NORMAL = 0;     // 00000000

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static uint16_t compute_key_tag(const uint8_t *rdata, uint16_t rdata_length) {
    uint64_t ac = 0;
    for (int i = 0; i < rdata_length; ++i) ac += (i & 1) ? rdata[i] : rdata[i] << 8;
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
    // Handle root domain.
    if (domain[0] == '\0') return write_u8(request, 0);

    const char *start = domain;
    const char *cur = domain;
    for (;;) {
        if (*cur == '.' || *cur == '\0') {
            uint8_t length = cur - start;
            if (!write_u8(request, length)) return false;
            if (!write(request, start, length)) return false;
            start = cur + 1;
        }
        if (*cur == '\0') break;
        cur++;
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

static bool read_domain_rec(Response *response, bool allow_compression, char *output_buffer, int buffer_size) {
    // Handle root domain.
    if (response->buffer[response->current] == 0) {
        *output_buffer = '\0';
        response->current++;
        return true;
    }

    char *out = output_buffer;
    for (;;) {
        uint8_t byte;
        if (!read_u8(response, &byte)) return false;
        uint8_t type = byte & LABEL_TYPE_MASK;
        uint8_t data = byte & LABEL_DATA_MASK;

        if (type == LABEL_TYPE_NORMAL) {
            uint8_t label_len = data;
            if (label_len == 0) {
                // End of domain, remove trailing dot.
                *(out - 1) = '\0';
                return true;
            }
            if (response->current + label_len > response->length) return false;
            if (label_len + 1 > buffer_size) return false;
            buffer_size -= label_len + 1;

            memcpy(out, response->buffer + response->current, label_len);
            response->current += label_len;
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

static bool read_char_string(Response *response, char **string_out) {
    uint8_t length;
    if (!read_u8(response, &length)) return false;
    if (response->current + length > response->length) return false;

    char *string = malloc((length + 1) * sizeof(*string));
    if (string == NULL) return false;

    memcpy(string, response->buffer + response->current, length);
    response->current += length;
    string[length] = '\0';

    *string_out = string;
    return true;
}

// Copies the data (excluding first length byte) into buffer and replaces each
// length byte with '\0' to transform it into array of null-terminated strings.
// TXT's data is a dynamic array of strings pointing to the buffer.
static bool read_txt_data(Response *response, uint16_t data_length, TXT *txt) {
    txt->buffer = malloc(data_length * sizeof(*txt->buffer));
    if (txt->buffer == NULL) return false;
    memcpy(txt->buffer, response->buffer + response->current + 1, data_length - 1);
    txt->buffer[data_length - 1] = '\0';

    char *cur = txt->buffer;
    uint32_t end = response->current + data_length;
    while (response->current < end) {
        uint8_t length;
        if (!read_u8(response, &length)) return false;

        if (response->current + length > response->length) return false;
        response->current += length;

        VECTOR_PUSH(txt, cur);
        cur += length;
        *(cur++) = '\0';
    }
    return true;
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

static const char *type_to_str(uint16_t type) {
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
        case TYPE_DNSKEY: return "DNSKEY";
        default:          return "unknown";
    }
}

void print_rr(RR *rr) {
    printf("%-24s %-8u %-6s ", rr->domain[0] == '\0' ? "." : rr->domain, rr->ttl, type_to_str(rr->type));
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
            printf("%u %u %u %s", rr->data.ds.key_tag, rr->data.ds.algorithm, rr->data.ds.digest_type, digest);
            free(digest);
        } break;
        case TYPE_RRSIG: {
            char *signature = base64_encode(rr->data.rrsig.signature, rr->data.rrsig.signature_size);
            printf("%s %u %u %u %u %u %u %s %s", type_to_str(rr->data.rrsig.type_covered), rr->data.rrsig.algorithm,
                   rr->data.rrsig.labels, rr->data.rrsig.original_ttl, rr->data.rrsig.expiration_time,
                   rr->data.rrsig.inception_time, rr->data.rrsig.key_tag, rr->data.rrsig.signer_name, signature);
            free(signature);
        } break;
        case TYPE_DNSKEY: {
            char *public_key = base64_encode(rr->data.dnskey.public_key, rr->data.dnskey.public_key_size);
            printf("%u %u %u %s", rr->data.dnskey.flags, rr->data.dnskey.protocol, rr->data.dnskey.protocol,
                   public_key);
            free(public_key);
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
        case TYPE_DS: free(rr->data.ds.digest); break;
        case TYPE_RRSIG:
            free(rr->data.rrsig.signer_name);
            free(rr->data.rrsig.signature);
            free(rr->data.rrsig.rdata);
            break;
        case TYPE_DNSKEY:
            free(rr->data.dnskey.public_key);
            free(rr->data.dnskey.rdata);
            break;
    }
    free(rr->domain);
    free(rr);
}

bool write_request(Request *request, bool recursion_desired, const char *domain, uint16_t qtype, bool enable_edns,
                   bool enable_cookie, bool enable_dnssec, uint16_t udp_payload_size, DNSCookies *cookies,
                   uint16_t *id_out) {
    uint16_t id;
    if (getrandom(&id, sizeof(id), 0) != sizeof(id)) return false;

    DNSHeader header = {
        .id = htons(id),
        .recursion_desired = recursion_desired,
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
        if (!write_u16(request, MAX(udp_payload_size, STANDARD_UDP_PAYLOAD_SIZE))) return false;

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

bool validate_question(Response *response, uint16_t request_qtype, const char *request_domain) {
    char *domain;
    if (!read_domain(response, true, &domain)) return false;

    int result = strcasecmp(domain, request_domain);
    free(domain);
    if (result != 0) return false;

    uint16_t qtype, qclass;
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
    switch (rr->type) {
        case TYPE_A:
            if (data_length != sizeof(rr->data.ip4_addr)) goto error;
            memcpy(&rr->data.ip4_addr, response->buffer + response->current, sizeof(rr->data.ip4_addr));
            response->current += sizeof(rr->data.ip4_addr);
            break;
        case TYPE_NS:
        case TYPE_CNAME:
            if (!read_domain(response, true, &rr->data.domain)) goto error;
            break;
        case TYPE_SOA:
            if (!read_domain(response, true, &rr->data.soa.master_name)) goto error;
            if (!read_domain(response, true, &rr->data.soa.rname)) {
                free(rr->data.soa.master_name);
                goto error;
            }
            if (!read_u32(response, &rr->data.soa.serial) ||   //
                !read_u32(response, &rr->data.soa.refresh) ||  //
                !read_u32(response, &rr->data.soa.retry) ||    //
                !read_u32(response, &rr->data.soa.expire) ||   //
                !read_u32(response, &rr->data.soa.negative_ttl)) {
                free(rr->data.soa.master_name);
                free(rr->data.soa.rname);
                goto error;
            }
            break;
        case TYPE_HINFO:
            if (!read_char_string(response, &rr->data.hinfo.cpu)) goto error;
            if (!read_char_string(response, &rr->data.hinfo.os)) {
                free(rr->data.hinfo.cpu);
                goto error;
            }
            break;
        case TYPE_TXT:
            memset(&rr->data.txt, 0, sizeof(rr->data.txt));
            if (!read_txt_data(response, data_length, &rr->data.txt)) goto error;
            break;
        case TYPE_AAAA:
            if (data_length != sizeof(rr->data.ip6_addr)) goto error;
            memcpy(&rr->data.ip6_addr, response->buffer + response->current, sizeof(rr->data.ip6_addr));
            response->current += sizeof(rr->data.ip6_addr);
            break;
        case TYPE_OPT: {
            if (rr->domain[0] != 0) goto error;

            rr->data.opt.udp_payload_size = MAX(class, STANDARD_UDP_PAYLOAD_SIZE);

            uint32_t net_ttl = htonl(rr->ttl);
            OptTtlFields opt_fields;
            memcpy(&opt_fields, &net_ttl, sizeof(opt_fields));

            rr->data.opt.extended_rcode = opt_fields.extended_rcode;
            if (opt_fields.version > EDNS_VERSION) goto error;

            if (!read_opt_data(response, data_length, &rr->data.opt)) goto error;
        } break;
        case TYPE_DS: {
            if (!read_u16(response, &rr->data.ds.key_tag)) goto error;
            if (!read_u8(response, &rr->data.ds.algorithm)) goto error;
            if (!read_u8(response, &rr->data.ds.digest_type)) goto error;

            rr->data.ds.digest_size = data_length - 4;
            rr->data.ds.digest = malloc(rr->data.ds.digest_size);
            if (rr->data.ds.digest == NULL) goto error;

            if (!read(response, rr->data.ds.digest, rr->data.ds.digest_size)) {
                free(rr->data.ds.digest);
                goto error;
            }
        } break;
        case TYPE_RRSIG: {
            const uint8_t *rrsig_rdata = response->buffer + response->current;
            size_t response_current_before = response->current;
            if (!read_u16(response, &rr->data.rrsig.type_covered)) goto error;
            if (!read_u8(response, &rr->data.rrsig.algorithm)) goto error;
            if (!read_u8(response, &rr->data.rrsig.labels)) goto error;
            if (!read_u32(response, &rr->data.rrsig.original_ttl)) goto error;
            if (!read_u32(response, &rr->data.rrsig.expiration_time)) goto error;
            if (!read_u32(response, &rr->data.rrsig.inception_time)) goto error;
            if (!read_u16(response, &rr->data.rrsig.key_tag)) goto error;
            if (!read_domain(response, false, &rr->data.rrsig.signer_name)) goto error;
            size_t rdata_length_without_signature = response->current - response_current_before;

            // Save RDATA without signature to verify it later.
            rr->data.rrsig.rdata_length = rdata_length_without_signature;
            rr->data.rrsig.rdata = malloc(rdata_length_without_signature);
            if (rr->data.rrsig.rdata == NULL) {
                free(rr->data.rrsig.signer_name);
                goto error;
            }
            memcpy(rr->data.rrsig.rdata, rrsig_rdata, rdata_length_without_signature);

            // The rest of RDATA is the signature.
            rr->data.rrsig.signature_size = data_length - rdata_length_without_signature;
            rr->data.rrsig.signature = malloc(rr->data.rrsig.signature_size);
            if (rr->data.rrsig.signature == NULL) {
                free(rr->data.rrsig.signer_name);
                free(rr->data.rrsig.rdata);
                goto error;
            }
            if (!read(response, rr->data.rrsig.signature, rr->data.rrsig.signature_size)) {
                free(rr->data.rrsig.signer_name);
                free(rr->data.rrsig.rdata);
                free(rr->data.rrsig.signature);
                goto error;
            }
        } break;
        case TYPE_DNSKEY: {
            const uint8_t *dnskey_rdata = response->buffer + response->current;
            if (!read(response, &rr->data.dnskey.flags, sizeof(rr->data.dnskey.flags))) goto error;
            if (!read_u8(response, &rr->data.dnskey.protocol)) goto error;
            if (rr->data.dnskey.protocol != DNSKEY_PROTOCOL) goto error;
            if (!read_u8(response, &rr->data.dnskey.algorithm)) goto error;

            rr->data.dnskey.public_key_size = data_length - 4;
            rr->data.dnskey.public_key = malloc(rr->data.dnskey.public_key_size);
            if (rr->data.dnskey.public_key == NULL) goto error;

            if (!read(response, rr->data.dnskey.public_key, rr->data.dnskey.public_key_size)) {
                free(rr->data.dnskey.public_key);
                goto error;
            }

            rr->data.dnskey.key_tag = compute_key_tag(dnskey_rdata, data_length);

            rr->data.dnskey.rdata_length = data_length;
            rr->data.dnskey.rdata = malloc(data_length);
            if (rr->data.dnskey.rdata == NULL) {
                free(rr->data.dnskey.public_key);
                goto error;
            }
            memcpy(rr->data.dnskey.rdata, dnskey_rdata, data_length);
        } break;
        default: goto error;
    }

    *rr_out = rr;
    return true;
error:
    free(rr->domain);
    free(rr);
    return false;
}
