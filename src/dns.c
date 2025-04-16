#include "dns.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "error.h"

static const uint8_t NAME_DATA_MASK = 63;      // 00111111
static const uint8_t NAME_TYPE_MASK = 192;     // 11000000
static const uint8_t NAME_TYPE_POINTER = 192;  // 11000000
static const uint8_t NAME_TYPE_LABEL = 0;      // 00000000

uint16_t write_request_header(uint8_t *buffer, bool recursion_desired, uint8_t opcode, uint16_t question_count) {
    uint16_t id = 0x1234;
    DNSHeader header = {
        .id = htons(id),
        .is_response = false,
        .opcode = opcode,
        .is_authoritative = false,
        .is_truncated = false,
        .recursion_desired = recursion_desired,
        .recursion_available = false,
        ._reserved = 0,
        .response_code = 0,
        .question_count = htons(question_count),
        .answer_count = htons(0),
        .authority_count = htons(0),
        .additional_count = htons(0),
    };
    memcpy(buffer, &header, sizeof(header));
    return id;
}

void write_question(uint8_t *buffer, const char *domain, uint16_t type) {
    const char *start = domain;
    const char *current = domain;
    for (;;) {
        if (*current == '.' || *current == '\0') {
            uint8_t len = current - start;
            *(buffer++) = len;
            memcpy(buffer, start, len);
            buffer += len;
            start = current + 1;
        }
        if (*current == '\0') break;
        current++;
    }
    *(buffer++) = 0;  // end of labels

    uint16_t net_type = htons(type);
    memcpy(buffer, &net_type, sizeof(net_type));
    buffer += sizeof(net_type);

    uint16_t net_class = htons(CLASS_IN);
    memcpy(buffer, &net_class, sizeof(net_class));
    buffer += sizeof(net_class);
}

uint8_t *read_response_header(uint8_t *buffer, DNSHeader *header) {
    memcpy(header, buffer, sizeof(*header));
    buffer += sizeof(*header);

    header->id = ntohs(header->id);
    header->question_count = ntohs(header->question_count);
    header->answer_count = ntohs(header->answer_count);
    header->authority_count = ntohs(header->authority_count);
    header->additional_count = ntohs(header->additional_count);

    return buffer;
}

static uint8_t *read_domain_name(uint8_t *message, uint8_t *buffer, char *domain) {
    char *dst = domain;
    for (;;) {
        uint8_t type = *buffer & NAME_TYPE_MASK;
        uint8_t data = *buffer & NAME_DATA_MASK;
        buffer++;

        if (type == NAME_TYPE_LABEL) {
            uint8_t length = data;
            if (length == 0) {
                // Remove trailing dot.
                *(dst - 1) = '\0';
                break;
            }

            memcpy(dst, buffer, length);
            buffer += length;
            dst += length;
            *(dst++) = '.';
        } else if (type == NAME_TYPE_POINTER) {
            uint16_t offset = (data << 8) | *(buffer++);
            read_domain_name(message, message + offset, dst);
            dst += strlen(dst);
            // Pointer is always last part of domain.
            break;
        } else {
            ERROR("Unknown or invalid label length type");
        }
    }
    return buffer;
}

uint8_t *read_question(uint8_t *message, uint8_t *buffer) {
    char domain[MAX_DOMAIN_LENGTH];
    buffer = read_domain_name(message, buffer, domain);
    buffer += sizeof(uint16_t);  // qtype
    buffer += sizeof(uint16_t);  // qclass
    return buffer;
}

uint8_t *read_resource_record(uint8_t *message, uint8_t *buffer, ResourceRecord *rr) {
    buffer = read_domain_name(message, buffer, rr->domain);

    uint16_t type;
    memcpy(&type, buffer, sizeof(type));
    buffer += sizeof(type);
    rr->type = ntohs(type);

    uint16_t class;
    memcpy(&class, buffer, sizeof(class));
    buffer += sizeof(class);
    if (ntohs(class) != CLASS_IN) ERROR("Resource record class is not Internet");

    uint32_t ttl;
    memcpy(&ttl, buffer, sizeof(ttl));
    buffer += sizeof(ttl);
    rr->ttl = ntohl(ttl);

    uint16_t length;
    memcpy(&length, buffer, sizeof(length));
    buffer += sizeof(length);
    rr->data_length = ntohs(length);

    switch (rr->type) {
        case TYPE_A: {
            if (rr->data_length != sizeof(rr->data.ip4_address)) ERROR("Invalid A data length");
            memcpy(&rr->data.ip4_address, buffer, sizeof(rr->data.ip4_address));
            buffer += sizeof(rr->data.ip4_address);
        } break;
        default: ERROR("TODO");
    }

    return buffer;
}
