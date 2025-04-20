#include "dns.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include "error.h"

static const uint8_t LABEL_DATA_MASK = 63;      // 00111111
static const uint8_t LABEL_TYPE_MASK = 192;     // 11000000
static const uint8_t LABEL_TYPE_POINTER = 192;  // 11000000
static const uint8_t LABEL_TYPE_NORMAL = 0;     // 00000000

uint16_t get_qtype(const char *type) {
    if (strcmp(type, "A") == 0) return TYPE_A;
    if (strcmp(type, "NS") == 0) return TYPE_NS;
    if (strcmp(type, "CNAME") == 0) return TYPE_CNAME;
    if (strcmp(type, "SOA") == 0) return TYPE_SOA;
    if (strcmp(type, "TXT") == 0) return TYPE_TXT;
    ERROR("Invalid or unsupported query type \"%s\"", type);
}

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
    if (header->question_count != 1) ERROR("Question count is not 1");  // https://www.rfc-editor.org/rfc/rfc9619

    return ptr;
}

const uint8_t *validate_question(const uint8_t *response, const uint8_t *ptr, const uint8_t *end, uint16_t req_qtype,
                                 const char *req_domain) {
    char domain[MAX_DOMAIN_LENGTH];
    ptr = read_domain_name(response, ptr, end, domain);
    if (strcmp(domain, req_domain) != 0) ERROR("Invalid domain in response");

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
        case TYPE_A: {
            if (rr->data_length != sizeof(rr->data.ip4_address)) ERROR("Invalid A data length");
            memcpy(&rr->data.ip4_address, ptr, sizeof(rr->data.ip4_address));
            ptr += sizeof(rr->data.ip4_address);
        } break;
        default: ERROR("Invalid or unsupported resource record type %d", rr->type);
    }

    return ptr;
}
