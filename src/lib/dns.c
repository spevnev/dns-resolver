#define _POSIX_C_SOURCE 200809L
#include "dns.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include "vector.h"

const char *ROOT_NAMESERVER_IP_ADDRS[ROOT_NAMESERVER_COUNT] = {
    "198.41.0.4",    "170.247.170.2", "192.33.4.12",   "199.7.91.13",  "192.203.230.10", "192.5.5.241",  "192.112.36.4",
    "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",    "202.12.27.33",
};

static const uint8_t LABEL_DATA_MASK = 63;      // 00111111
static const uint8_t LABEL_TYPE_MASK = 192;     // 11000000
static const uint8_t LABEL_TYPE_POINTER = 192;  // 11000000
static const uint8_t LABEL_TYPE_NORMAL = 0;     // 00000000

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static bool write_u8(Request *request, uint8_t value) {
    if (request->length + sizeof(value) > request->size) return false;
    request->buffer[request->length++] = value;
    return true;
}

static bool write_u16(Request *request, uint16_t value) {
    if (request->length + sizeof(value) > request->size) return false;
    uint16_t net_value = htons(value);
    memcpy(request->buffer + request->length, &net_value, sizeof(net_value));
    request->length += sizeof(net_value);
    return true;
}

static bool write_domain(Request *request, const char *domain) {
    // Check root domain.
    if (domain[0] == '\0') return write_u8(request, 0);

    const char *start = domain;
    const char *cur = domain;
    for (;;) {
        if (*cur == '.' || *cur == '\0') {
            uint8_t len = cur - start;
            if (!write_u8(request, len)) return false;
            if (request->length + len > request->size) return false;
            memcpy(request->buffer + request->length, start, len);
            request->length += len;
            start = cur + 1;
        }
        if (*cur == '\0') break;
        cur++;
    }
    if (!write_u8(request, 0)) return false;

    return true;
}

static bool read_u8(Response *response, uint8_t *out) {
    if (response->current + sizeof(*out) > response->length) return false;
    *out = response->buffer[response->current];
    response->current += sizeof(*out);
    return true;
}

static bool read_u16(Response *response, uint16_t *out) {
    uint16_t value;
    if (response->current + sizeof(value) > response->length) return false;
    memcpy(&value, response->current + response->buffer, sizeof(value));
    response->current += sizeof(value);
    *out = ntohs(value);
    return true;
}

static bool read_u32(Response *response, uint32_t *out) {
    uint32_t value;
    if (response->current + sizeof(value) > response->length) return false;
    memcpy(&value, response->current + response->buffer, sizeof(value));
    response->current += sizeof(value);
    *out = ntohl(value);
    return true;
}

static bool read_domain_rec(Response *response, char *domain, int domain_size) {
    // Check root domain.
    if (response->buffer[response->current] == 0) {
        *domain = '\0';
        response->current++;
        return true;
    }

    char *cur = domain;
    for (;;) {
        uint8_t byte;
        if (!read_u8(response, &byte)) return false;
        uint8_t type = byte & LABEL_TYPE_MASK;
        uint8_t data = byte & LABEL_DATA_MASK;

        if (type == LABEL_TYPE_NORMAL) {
            uint8_t label_len = data;
            if (label_len == 0) {
                // End of domain, remove trailing dot.
                *(cur - 1) = '\0';
                return true;
            }
            if (response->current + label_len > response->length) return false;
            if (label_len + 1 > domain_size) return false;
            domain_size -= label_len + 1;

            memcpy(cur, response->buffer + response->current, label_len);
            response->current += label_len;
            cur += label_len;
            *(cur++) = '.';
        } else if (type == LABEL_TYPE_POINTER) {
            uint8_t lower_half;
            if (!read_u8(response, &lower_half)) return false;
            uint16_t offset = ((uint16_t) data << 8) | lower_half;

            Response pointer_response = {
                .buffer = response->buffer,
                .current = offset,
                .length = response->length,
            };
            return read_domain_rec(&pointer_response, cur, domain_size);
        } else {
            return false;
        }
    }
}

static bool read_domain(Response *response, char **domain_out) {
    char buffer[DOMAIN_SIZE];
    if (!read_domain_rec(response, buffer, DOMAIN_SIZE)) return false;

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

static const char *type_to_str(uint16_t type) {
    switch (type) {
        case TYPE_A:     return "A";
        case TYPE_NS:    return "NS";
        case TYPE_CNAME: return "CNAME";
        case TYPE_SOA:   return "SOA";
        case TYPE_HINFO: return "HINFO";
        case TYPE_TXT:   return "TXT";
        case TYPE_AAAA:  return "AAAA";
        default:         return "unknown";
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
    }
    printf("\n");
}

void free_rr(RR *rr) {
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
    }
    free(rr->domain);
    free(rr);
}

bool write_request(Request *request, bool recursion_desired, const char *domain, uint16_t qtype, bool enable_edns,
                   uint16_t udp_payload_size, uint16_t *id_out) {
    uint16_t id;
    if (getrandom(&id, sizeof(id), 0) != sizeof(id)) return false;

    DNSHeader header = {
        .id = htons(id),
        .recursion_desired = recursion_desired,
        .is_truncated = false,
        .is_authoritative = false,
        .opcode = OPCODE_QUERY,
        .is_response = false,
        .rcode = 0,
        .checking_disabled = false,
        .authentic_data = false,
        ._reserved = 0,
        .recursion_available = false,
        .question_count = htons(1),
        .answer_count = 0,
        .authority_count = 0,
        .additional_count = enable_edns ? htons(1) : 0,
    };
    if (request->length + sizeof(header) > request->size) return false;
    memcpy(request->buffer + request->length, &header, sizeof(header));
    request->length += sizeof(header);

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
            .extended_rcode = 0,
            .version = EDNS_VERSION,
            ._reserved = 0,
            .dnssec_ok = 0,
            ._reserved2 = 0,
        };
        if (request->length + sizeof(opt_fields) > request->size) return false;
        memcpy(request->buffer + request->length, &opt_fields, sizeof(opt_fields));
        request->length += sizeof(opt_fields);

        // No additional options.
        if (!write_u16(request, 0)) return false;
    }

    *id_out = id;
    return true;
}

bool read_response_header(Response *response, uint16_t request_id, DNSHeader *header) {
    if (response->current + sizeof(*header) > response->length) return false;
    memcpy(header, response->buffer + response->current, sizeof(*header));
    response->current += sizeof(*header);

    header->id = ntohs(header->id);
    header->question_count = ntohs(header->question_count);
    header->answer_count = ntohs(header->answer_count);
    header->authority_count = ntohs(header->authority_count);
    header->additional_count = ntohs(header->additional_count);

    if (!header->is_response) return false;
    if (header->opcode != OPCODE_QUERY) return false;
    if (header->id != request_id) return false;
    if (header->question_count != 1) return false;  // RFC9619

    return true;
}

bool validate_question(Response *response, uint16_t request_qtype, const char *request_domain) {
    char *domain;
    if (!read_domain(response, &domain)) return false;
    if (strcasecmp(domain, request_domain) != 0) return false;
    free(domain);

    uint16_t qtype, qclass;
    if (!read_u16(response, &qtype)) return false;
    if (!read_u16(response, &qclass)) return false;

    if (qtype != request_qtype) return false;
    if (qclass != CLASS_IN) return false;

    return true;
}

bool read_rr(Response *response, RR **rr_out) {
    RR *rr = malloc(sizeof(*rr));
    if (rr == NULL) return false;

    uint16_t class, data_length;
    if (!read_domain(response, &rr->domain)) goto error;
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
            if (!read_domain(response, &rr->data.domain)) goto error;
            break;
        case TYPE_SOA:
            if (!read_domain(response, &rr->data.soa.master_name)) goto error;
            if (!read_domain(response, &rr->data.soa.rname)) {
                free(rr->data.soa.master_name);
                goto error;
            }
            if (!read_u32(response, &rr->data.soa.serial)) goto error;
            if (!read_u32(response, &rr->data.soa.refresh)) goto error;
            if (!read_u32(response, &rr->data.soa.retry)) goto error;
            if (!read_u32(response, &rr->data.soa.expire)) goto error;
            if (!read_u32(response, &rr->data.soa.negative_ttl)) goto error;
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

            // Ignore additional options.
            response->current += data_length;
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
