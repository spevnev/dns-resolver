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

#define MAX(a, b) ((a) > (b) ? (a) : (b))

static const uint8_t LABEL_DATA_MASK = 63;      // 00111111
static const uint8_t LABEL_TYPE_MASK = 192;     // 11000000
static const uint8_t LABEL_TYPE_POINTER = 192;  // 11000000
static const uint8_t LABEL_TYPE_NORMAL = 0;     // 00000000

static void write_u8(Request *request, uint8_t value) {
    if (request->length + sizeof(value) > request->size) ERROR("Request buffer is too small");
    request->buffer[request->length++] = value;
}

static void write_u16(Request *request, uint16_t value) {
    if (request->length + sizeof(value) > request->size) ERROR("Request buffer is too small");
    uint16_t net_value = htons(value);
    memcpy(request->buffer + request->length, &net_value, sizeof(net_value));
    request->length += sizeof(net_value);
}

static void write_u32(Request *request, uint32_t value) {
    if (request->length + sizeof(value) > request->size) ERROR("Request buffer is too small");
    uint32_t net_value = htonl(value);
    memcpy(request->buffer + request->length, &net_value, sizeof(net_value));
    request->length += sizeof(net_value);
}

static void write_domain(Request *request, const char *domain) {
    // Check root domain.
    if (domain[0] == '\0') {
        write_u8(request, 0);
        return;
    }

    const char *start = domain;
    const char *ch = domain;
    for (;;) {
        if (*ch == '.' || *ch == '\0') {
            uint8_t len = ch - start;
            write_u8(request, len);
            memcpy(request->buffer + request->length, start, len);
            request->length += len;
            start = ch + 1;
        }
        if (*ch == '\0') break;
        ch++;
    }
    write_u8(request, 0);  // end of labels
}

static uint8_t read_u8(Response *response) {
    uint8_t value;
    if (response->current + sizeof(value) > response->length) ERROR("Response is too short");
    value = response->buffer[response->current];
    response->current += sizeof(value);
    return value;
}

static uint16_t read_u16(Response *response) {
    uint16_t value;
    if (response->current + sizeof(value) > response->length) ERROR("Response is too short");
    memcpy(&value, response->current + response->buffer, sizeof(value));
    response->current += sizeof(value);
    return ntohs(value);
}

static uint32_t read_u32(Response *response) {
    uint32_t value;
    if (response->current + sizeof(value) > response->length) ERROR("Response is too short");
    memcpy(&value, response->current + response->buffer, sizeof(value));
    response->current += sizeof(value);
    return ntohl(value);
}

static void read_domain(Response *response, char *domain) {
    // Check root domain.
    if (response->buffer[response->current] == 0) {
        *domain = '\0';
        response->current++;
        return;
    }

    char *domain_ptr = domain;
    for (;;) {
        uint8_t byte = read_u8(response);
        uint8_t type = byte & LABEL_TYPE_MASK;
        uint8_t data = byte & LABEL_DATA_MASK;

        if (type == LABEL_TYPE_NORMAL) {
            uint8_t label_len = data;
            if (label_len == 0) {
                // End of domain, remove trailing dot and break.
                assert(domain_ptr > domain);  // check underflow
                *(domain_ptr - 1) = '\0';
                break;
            }
            if (response->current + label_len > response->length) ERROR("Response is too short");

            memcpy(domain_ptr, response->buffer + response->current, label_len);
            response->current += label_len;
            domain_ptr += label_len;
            *(domain_ptr++) = '.';
        } else if (type == LABEL_TYPE_POINTER) {
            uint16_t offset = (data << 8) | read_u8(response);
            Response ptr_response = {
                .buffer = response->buffer,
                .current = offset,
                .length = response->length,
            };
            read_domain(&ptr_response, domain_ptr);
            // Pointer is always the last part of domain.
            break;
        } else {
            ERROR("Invalid label length type");
        }
    }
}

static char *read_char_string(Response *response) {
    uint8_t length = read_u8(response);
    if (response->current + length > response->length) ERROR("Response is too short");

    char *string = malloc((length + 1) * sizeof(*string));
    if (string == NULL) OUT_OF_MEMORY();

    memcpy(string, response->buffer + response->current, length);
    response->current += length;
    string[length] = '\0';

    return string;
}

// Copies the data (excluding first length byte) into buffer and replaces each
// length byte with '\0' to transform it into array of null-terminated strings.
// TXT's data is a dynamic array of strings pointing to the buffer.
static TXT read_txt_data(Response *response, uint16_t data_length) {
    TXT txt = {0};

    txt.buffer = malloc(data_length * sizeof(*txt.buffer));
    if (txt.buffer == NULL) OUT_OF_MEMORY();
    memcpy(txt.buffer, response->buffer + response->current + 1, data_length - 1);
    txt.buffer[data_length - 1] = '\0';

    char *cur = txt.buffer;
    uint32_t end = response->current + data_length;
    while (response->current < end) {
        uint8_t length = read_u8(response);

        if (response->current + length > response->length) ERROR("Response is too short");
        response->current += length;

        VECTOR_PUSH(&txt, cur);
        cur += length;
        *(cur++) = '\0';
    }

    return txt;
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

void print_resource_record(ResourceRecord *rr) {
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

uint16_t write_request(Request *request, bool recursion_desired, const char *domain, uint16_t qtype,
                       uint16_t udp_payload_size, bool enable_edns) {
    uint16_t id;
    if (getrandom(&id, sizeof(id), 0) != sizeof(id)) PERROR("getrandom");

    DNSHeader header = {
        .id = htons(id),
        .recursion_desired = recursion_desired,
        .is_truncated = false,
        .is_authoritative = false,
        .opcode = OPCODE_QUERY,
        .is_response = false,
        .response_code = 0,
        .checking_disabled = false,
        .authentic_data = false,
        ._reserved = 0,
        .recursion_available = false,
        .question_count = htons(1),
        .answer_count = 0,
        .authority_count = 0,
        .additional_count = enable_edns ? htons(1) : 0,
    };
    if (request->length + sizeof(header) > request->size) ERROR("Request buffer is too small");
    memcpy(request->buffer + request->length, &header, sizeof(header));
    request->length += sizeof(header);

    // Write question:
    write_domain(request, domain);
    write_u16(request, qtype);
    write_u16(request, CLASS_IN);

    // Write the OPT pseudo-RR (RFC6891):
    if (enable_edns) {
        // Domain must be root.
        write_u8(request, 0);
        write_u16(request, TYPE_OPT);
        // CLASS contains max UDP payload size.
        write_u16(request, MAX(udp_payload_size, STANDARD_UDP_PAYLOAD_SIZE));

        // TTL contains additional OPT fields.
        OPTTTLFields opt_fields = {
            .extended_rcode = 0,
            .version = EDNS_VERSION,
            ._reserved = 0,
            .dnssec_ok = 0,
            ._reserved2 = 0,
        };
        if (request->length + sizeof(opt_fields) > request->size) ERROR("Request buffer is too small");
        memcpy(request->buffer + request->length, &opt_fields, sizeof(opt_fields));
        request->length += sizeof(opt_fields);

        // No additional options.
        write_u16(request, 0);
    }

    return id;
}

DNSHeader read_response_header(Response *response, uint16_t req_id) {
    DNSHeader header;
    if (response->current + sizeof(header) > response->length) ERROR("Response is too short");

    memcpy(&header, response->buffer + response->current, sizeof(header));
    response->current += sizeof(header);

    header.id = ntohs(header.id);
    header.question_count = ntohs(header.question_count);
    header.answer_count = ntohs(header.answer_count);
    header.authority_count = ntohs(header.authority_count);
    header.additional_count = ntohs(header.additional_count);

    if (!header.is_response) ERROR("Message is not a response");
    if (header.opcode != OPCODE_QUERY) ERROR("Invalid response opcode");
    if (header.id != req_id) ERROR("Response id does not match request id");
    if (header.question_count != 1) ERROR("Question count is not 1");  // RFC9619

    return header;
}

void validate_question(Response *response, uint16_t req_qtype, const char *req_domain) {
    char domain[DOMAIN_BUFFER_SIZE];
    read_domain(response, domain);
    if (strcasecmp(domain, req_domain) != 0) ERROR("Invalid domain in response");

    uint16_t qtype = read_u16(response);
    if (qtype != req_qtype) ERROR("Invalid response question type");

    uint16_t qclass = read_u16(response);
    if (qclass != CLASS_IN) ERROR("Resource record class is not Internet");
}

void read_resource_record(Response *response, ResourceRecord *rr) {
    read_domain(response, rr->domain);

    rr->type = read_u16(response);

    // Class must be Internet, or it is OPT RR whose CLASS contains UDP payload size (RFC6891).
    uint16_t class = read_u16(response);
    if (rr->type != TYPE_OPT && class != CLASS_IN) ERROR("Resource record class is not Internet");

    uint32_t net_ttl;
    if (response->current + sizeof(net_ttl) > response->length) ERROR("Response is too short");
    memcpy(&net_ttl, response->buffer + response->current, sizeof(net_ttl));
    rr->ttl = ntohl(net_ttl);
    response->current += sizeof(net_ttl);

    rr->data_length = read_u16(response);
    if (response->current + rr->data_length > response->length) ERROR("Response is too short");

    switch (rr->type) {
        case TYPE_A:
            if (rr->data_length != sizeof(rr->data.ip4_address)) ERROR("Invalid A data length");
            memcpy(&rr->data.ip4_address, response->buffer + response->current, sizeof(rr->data.ip4_address));
            response->current += sizeof(rr->data.ip4_address);
            break;
        case TYPE_NS:
        case TYPE_CNAME: read_domain(response, rr->data.domain); break;
        case TYPE_SOA:   {
            read_domain(response, rr->data.soa.mname);
            read_domain(response, rr->data.soa.rname);
            rr->data.soa.serial = read_u32(response);
            rr->data.soa.refresh = read_u32(response);
            rr->data.soa.retry = read_u32(response);
            rr->data.soa.expire = read_u32(response);
            rr->data.soa.min_ttl = read_u32(response);
        } break;
        case TYPE_HINFO:
            rr->data.hinfo.cpu = read_char_string(response);
            rr->data.hinfo.os = read_char_string(response);
            break;
        case TYPE_TXT: rr->data.txt = read_txt_data(response, rr->data_length); break;
        case TYPE_AAAA:
            if (rr->data_length != sizeof(rr->data.ip6_address)) ERROR("Invalid AAAA data length");
            memcpy(&rr->data.ip6_address, response->buffer + response->current, sizeof(rr->data.ip6_address));
            response->current += sizeof(rr->data.ip6_address);
            break;
        case TYPE_OPT: {
            if (rr->domain[0] != 0) ERROR("OPT domain must be root");

            rr->data.opt.udp_payload_size = MAX(class, STANDARD_UDP_PAYLOAD_SIZE);

            OPTTTLFields opt_fields;
            memcpy(&opt_fields, &net_ttl, sizeof(opt_fields));

            rr->data.opt.extended_rcode = opt_fields.extended_rcode;
            if (opt_fields.version > EDNS_VERSION) ERROR("Unsupported or invalid EDNS version");

            // Ignore additional options.
            response->current += rr->data_length;
        } break;
        default: ERROR("Invalid or unsupported resource record type %d", rr->type);
    }
}
