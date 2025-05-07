#ifndef DNS_H
#define DNS_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include "vector.h"

#define DNS_PORT 53

#define MAX_DOMAIN_LENGTH 255
#define DOMAIN_SIZE (MAX_DOMAIN_LENGTH + 1)

// Max payload size when using UDP without EDNS (RFC1035).
#define STANDARD_UDP_PAYLOAD_SIZE 512
// Recommended request payload size when using UDP with EDNS (RFC6891).
#define EDNS_UDP_PAYLOAD_SIZE 1280

#define CLASS_IN 1

#define OPCODE_QUERY 0

#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_SOA 6
#define TYPE_HINFO 13
#define TYPE_TXT 16
#define TYPE_AAAA 28
#define TYPE_OPT 41

#define QTYPE_ANY 255

#define RCODE_SUCCESS 0
#define RCODE_FORMAT_ERROR 1
#define RCODE_SERVER_ERROR 2
#define RCODE_NAME_ERROR 3
#define RCODE_NOT_IMPLEMENTED 4
#define RCODE_REFUSED 5
#define RCODE_BAD_VERSION 16

#define EDNS_VERSION 0

typedef struct {
    uint16_t id;
    uint8_t recursion_desired : 1;
    uint8_t is_truncated : 1;
    uint8_t is_authoritative : 1;
    uint8_t opcode : 4;
    uint8_t is_response : 1;
    uint8_t response_code : 4;
    uint8_t checking_disabled : 1;
    uint8_t authentic_data : 1;
    uint8_t _reserved : 1;
    uint8_t recursion_available : 1;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
} DNSHeader;

typedef struct {
    char *buffer;
    uint32_t length;
    uint32_t capacity;
    char **data;  // dynamic array of string, which are stored in buffer
} TXT;

typedef struct {
    uint8_t extended_rcode;
    uint8_t version;
    uint8_t _reserved : 7;
    uint8_t dnssec_ok : 1;
    uint8_t _reserved2 : 8;
} OPTTTLFields;

typedef struct {
    char domain[DOMAIN_SIZE];
    uint16_t type;
    uint32_t ttl;
    uint16_t data_length;
    union {
        in_addr_t ip4_address;
        char domain[DOMAIN_SIZE];
        struct {
            char mname[DOMAIN_SIZE];
            char rname[DOMAIN_SIZE];
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t min_ttl;
        } soa;
        struct {
            char *cpu;
            char *os;
        } hinfo;
        TXT txt;
        struct in6_addr ip6_address;
        struct {
            uint16_t udp_payload_size;
            uint8_t extended_rcode;
        } opt;
    } data;
} ResourceRecord;

VECTOR_TYPEDEF(RRVec, ResourceRecord);

typedef struct {
    uint8_t *buffer;
    uint32_t size;
    uint32_t length;
} Request;

typedef struct {
    const uint8_t *buffer;
    uint32_t length;
    uint32_t current;
} Response;

uint16_t str_to_qtype(const char *str);
const char *type_to_str(uint16_t type);

void print_resource_record(ResourceRecord *rr);

uint16_t write_request(Request *request, bool recursion_desired, const char *domain, uint16_t qtype, bool enable_edns,
                       uint16_t udp_payload_size);

DNSHeader read_response_header(Response *response, uint16_t req_id);
void validate_question(Response *response, uint16_t req_qtype, const char *req_domain);
void read_resource_record(Response *response, ResourceRecord *rr);

#endif  // DNS_H
