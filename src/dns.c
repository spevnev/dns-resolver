#include "dns.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include "error.h"
#include "vector.h"

static const uint8_t LABEL_DATA_MASK = 63;      // 00111111
static const uint8_t LABEL_TYPE_MASK = 192;     // 11000000
static const uint8_t LABEL_TYPE_POINTER = 192;  // 11000000
static const uint8_t LABEL_TYPE_NORMAL = 0;     // 00000000

static uint8_t *write_domain_name(uint8_t *buffer, const char *domain) {
    const char *start = domain;
    const char *ch = domain;
    for (;;) {
        if (*ch == '.' || *ch == '\0') {
            uint8_t len = ch - start;
            *(buffer++) = len;
            memcpy(buffer, start, len);
            buffer += len;
            start = ch + 1;
        }
        if (*ch == '\0') break;
        ch++;
    }
    *(buffer++) = 0;  // end of labels
    return buffer;
}

static const uint8_t *read_domain_name(const uint8_t *response, const uint8_t *ptr, const uint8_t *end, char *domain) {
    // Check root domain.
    if (*ptr == 0) {
        *domain = 0;
        return ptr + 1;
    }

    char *domain_ptr = domain;
    for (;;) {
        if (ptr + 1 > end) ERROR("Response is too short");
        uint8_t type = *ptr & LABEL_TYPE_MASK;
        uint8_t data = *ptr & LABEL_DATA_MASK;
        ptr++;

        if (type == LABEL_TYPE_NORMAL) {
            uint8_t label_len = data;
            if (label_len == 0) {
                // End of domain, remove trailing dot and break.
                assert(domain_ptr > domain);  // check underflow
                *(domain_ptr - 1) = '\0';
                break;
            }
            if (ptr + label_len > end) ERROR("Response is too short");

            memcpy(domain_ptr, ptr, label_len);
            ptr += label_len;
            domain_ptr += label_len;
            *(domain_ptr++) = '.';
        } else if (type == LABEL_TYPE_POINTER) {
            if (ptr + 1 > end) ERROR("Response is too short");
            uint16_t offset = (data << 8) | *(ptr++);
            read_domain_name(response, response + offset, end, domain_ptr);
            size_t ptr_len = strlen(domain_ptr);
            domain_ptr += ptr_len;
            // Pointer is always the last part of domain.
            break;
        } else {
            ERROR("Invalid label length type");
        }
    }
    return ptr;
}

static const uint8_t *read_char_string(const uint8_t *ptr, const uint8_t *end, char **string) {
    if (ptr + 1 > end) ERROR("Response is too short");
    uint8_t length = *(ptr++);
    if (ptr + length > end) ERROR("Response is too short");

    *string = malloc((length + 1) * sizeof(**string));
    if (*string == NULL) OUT_OF_MEMORY();
    (*string)[length] = '\0';

    memcpy(*string, ptr, length);
    ptr += length;

    return ptr;
}

// Copies the data (excluding first length byte) into buffer and replaces each
// length byte with '\0' to transform it into array of null-terminated strings.
// TXT's data is a dynamic array of strings pointing to the buffer.
static const uint8_t *read_txt(const uint8_t *ptr, uint16_t data_length, TXT *txt) {
    txt->buffer = malloc(data_length * sizeof(*txt->buffer));
    if (txt->buffer == NULL) OUT_OF_MEMORY();
    memcpy(txt->buffer, ptr + 1, data_length - 1);
    txt->buffer[data_length - 1] = '\0';

    char *cur = txt->buffer;
    const uint8_t *end = ptr + data_length;
    while (ptr < end) {
        if (ptr + 1 > end) ERROR("Response is too short");
        uint8_t length = *(ptr++);

        if (ptr + length > end) ERROR("Response is too short");
        ptr += length;

        VECTOR_PUSH(txt, cur);
        cur += length;
        *(cur++) = '\0';
    }
    return ptr;
}

uint16_t str_to_qtype(const char *str) {
    if (strcasecmp(str, "A") == 0) return TYPE_A;
    if (strcasecmp(str, "NS") == 0) return TYPE_NS;
    if (strcasecmp(str, "CNAME") == 0) return TYPE_CNAME;
    if (strcasecmp(str, "SOA") == 0) return TYPE_SOA;
    if (strcasecmp(str, "HINFO") == 0) return TYPE_HINFO;
    if (strcasecmp(str, "TXT") == 0) return TYPE_TXT;
    if (strcasecmp(str, "AAAA") == 0) return TYPE_AAAA;
    if (strcasecmp(str, "ANY") == 0) return QTYPE_ANY;
    ERROR("Invalid or unsupported qtype \"%s\"", str);
}

const char *type_to_str(uint16_t type) {
    switch (type) {
        case TYPE_A:     return "A";
        case TYPE_NS:    return "NS";
        case TYPE_CNAME: return "CNAME";
        case TYPE_SOA:   return "SOA";
        case TYPE_HINFO: return "HINFO";
        case TYPE_TXT:   return "TXT";
        case TYPE_AAAA:  return "AAAA";
        default:         ERROR("Invalid or unsupported resource record type %u", type);
    }
}

void print_rr(ResourceRecord *rr) {
    printf("%-24s %-8u %-6s ", rr->domain, rr->ttl, type_to_str(rr->type));
    switch (rr->type) {
        case TYPE_A: {
            char buffer[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &rr->data.ip4_address, buffer, sizeof(buffer)) == NULL) PERROR("inet_ntop");
            printf("%s", buffer);
        } break;
        case TYPE_NS:
        case TYPE_CNAME: printf("%s", rr->data.domain); break;
        case TYPE_SOA:
            printf("%s %s %u %u %u %u %u", rr->data.soa.mname, rr->data.soa.rname, rr->data.soa.serial,
                   rr->data.soa.refresh, rr->data.soa.retry, rr->data.soa.expire, rr->data.soa.min_ttl);
            break;
        case TYPE_HINFO: printf("%s %s", rr->data.hinfo.cpu, rr->data.hinfo.os); break;
        case TYPE_TXT:
            for (uint32_t i = 0; i < rr->data.txt.length; i++) printf(" \"%s\"", rr->data.txt.data[i]);
            break;
        case TYPE_AAAA: {
            char buffer[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &rr->data.ip6_address, buffer, sizeof(buffer)) == NULL) PERROR("inet_ntop");
            printf("%s", buffer);
        } break;
        default: ERROR("Invalid or unsupported query type %u", rr->type);
    }
    printf("\n");
}

// Does not check the size because a request with single question always fits in max UDP payload.
ssize_t write_request(uint8_t *buffer, bool recursion_desired, const char *domain, uint16_t qtype, uint16_t *id) {
    uint8_t *ptr = buffer;

    if (getrandom(id, sizeof(*id), 0) != sizeof(*id)) PERROR("getrandom");

    DNSHeader header = {
        .id = htons(*id),
        .is_response = false,
        .opcode = OPCODE_QUERY,
        .is_authoritative = false,
        .is_truncated = false,
        .recursion_desired = recursion_desired,
        .recursion_available = false,
        ._reserved = 0,
        .checking_disabled = false,
        .authentic_data = false,
        .response_code = 0,
        .question_count = htons(1),
        .answer_count = 0,
        .authority_count = 0,
        .additional_count = 0,
    };
    memcpy(ptr, &header, sizeof(header));
    ptr += sizeof(header);

    ptr = write_domain_name(ptr, domain);

    uint16_t net_qtype = htons(qtype);
    memcpy(ptr, &net_qtype, sizeof(net_qtype));
    ptr += sizeof(net_qtype);

    uint16_t net_class = htons(CLASS_IN);
    memcpy(ptr, &net_class, sizeof(net_class));
    ptr += sizeof(net_class);

    return ptr - buffer;
}

const uint8_t *read_response_header(const uint8_t *ptr, const uint8_t *end, DNSHeader *header, uint16_t req_id) {
    if (ptr + sizeof(*header) >= end) ERROR("Response is too short");

    memcpy(header, ptr, sizeof(*header));
    ptr += sizeof(*header);

    header->id = ntohs(header->id);
    header->question_count = ntohs(header->question_count);
    header->answer_count = ntohs(header->answer_count);
    header->authority_count = ntohs(header->authority_count);
    header->additional_count = ntohs(header->additional_count);

    if (!header->is_response) ERROR("Message is not a response");
    if (header->opcode != OPCODE_QUERY) ERROR("Invalid response opcode");
    if (header->id != req_id) ERROR("Response id does not match request id");
    if (header->question_count != 1) ERROR("Question count is not 1");  // RFC9619

    return ptr;
}

const uint8_t *validate_question(const uint8_t *response, const uint8_t *ptr, const uint8_t *end, uint16_t req_qtype,
                                 const char *req_domain) {
    char domain[MAX_DOMAIN_LENGTH + 1];
    ptr = read_domain_name(response, ptr, end, domain);
    if (strcasecmp(domain, req_domain) != 0) ERROR("Invalid domain in response");

    uint16_t qtype, qclass;
    if (ptr + sizeof(qtype) + sizeof(qclass) > end) ERROR("Response is too short");

    memcpy(&qtype, ptr, sizeof(qtype));
    ptr += sizeof(qtype);
    if (ntohs(qtype) != req_qtype) ERROR("Invalid response question type");

    memcpy(&qclass, ptr, sizeof(qclass));
    ptr += sizeof(qclass);
    if (ntohs(qclass) != CLASS_IN) ERROR("Resource record class is not Internet");

    return ptr;
}

const uint8_t *read_resource_record(const uint8_t *response, const uint8_t *ptr, const uint8_t *end,
                                    ResourceRecord *rr) {
    ptr = read_domain_name(response, ptr, end, rr->domain);

    uint16_t type, class, length;
    uint32_t ttl;
    if (ptr + sizeof(type) + sizeof(class) + sizeof(ttl) + sizeof(length) > end) ERROR("Response is too short");

    memcpy(&type, ptr, sizeof(type));
    ptr += sizeof(type);
    rr->type = ntohs(type);

    memcpy(&class, ptr, sizeof(class));
    ptr += sizeof(class);
    if (ntohs(class) != CLASS_IN) ERROR("Resource record class is not Internet");

    memcpy(&ttl, ptr, sizeof(ttl));
    ptr += sizeof(ttl);
    rr->ttl = ntohl(ttl);

    memcpy(&length, ptr, sizeof(length));
    ptr += sizeof(length);
    rr->data_length = ntohs(length);
    if (ptr + rr->data_length > end) ERROR("Response is too short");

    switch (rr->type) {
        case TYPE_A:
            if (rr->data_length != sizeof(rr->data.ip4_address)) ERROR("Invalid A data length");
            memcpy(&rr->data.ip4_address, ptr, sizeof(rr->data.ip4_address));
            ptr += sizeof(rr->data.ip4_address);
            break;
        case TYPE_NS:
        case TYPE_CNAME: ptr = read_domain_name(response, ptr, ptr + rr->data_length, rr->data.domain); break;
        case TYPE_SOA:   {
            ptr = read_domain_name(response, ptr, end, rr->data.soa.mname);
            ptr = read_domain_name(response, ptr, end, rr->data.soa.rname);

            uint32_t serial, refresh, retry, expire, min_ttl;
            if (ptr + sizeof(serial) + sizeof(refresh) + sizeof(retry) + sizeof(expire) + sizeof(min_ttl) > end) {
                ERROR("Response is too short");
            }

            memcpy(&serial, ptr, sizeof(serial));
            ptr += sizeof(serial);
            rr->data.soa.serial = ntohl(serial);

            memcpy(&refresh, ptr, sizeof(refresh));
            ptr += sizeof(refresh);
            rr->data.soa.refresh = ntohl(refresh);

            memcpy(&retry, ptr, sizeof(retry));
            ptr += sizeof(retry);
            rr->data.soa.retry = ntohl(retry);

            memcpy(&expire, ptr, sizeof(expire));
            ptr += sizeof(expire);
            rr->data.soa.expire = ntohl(expire);

            memcpy(&min_ttl, ptr, sizeof(min_ttl));
            ptr += sizeof(min_ttl);
            rr->data.soa.min_ttl = ntohl(min_ttl);
        } break;
        case TYPE_HINFO:
            ptr = read_char_string(ptr, end, &rr->data.hinfo.cpu);
            ptr = read_char_string(ptr, end, &rr->data.hinfo.os);
            break;
        case TYPE_TXT:
            rr->data.txt.length = 0;
            ptr = read_txt(ptr, rr->data_length, &rr->data.txt);
            break;
        case TYPE_AAAA:
            if (rr->data_length != sizeof(rr->data.ip6_address)) ERROR("Invalid AAAA data length");
            memcpy(&rr->data.ip6_address, ptr, sizeof(rr->data.ip6_address));
            ptr += sizeof(rr->data.ip6_address);
            break;
        default: ERROR("Invalid or unsupported resource record type %d", rr->type);
    }

    return ptr;
}
