#ifndef DNS_H
#define DNS_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

#define DNS_PORT 53

#define MAX_DOMAIN_LENGTH 255
#define MAX_UDP_PAYLOAD_SIZE 512

#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_SOA 6
#define TYPE_TXT 16
#define TYPE_AAAA 28

#define CLASS_IN 1

#define OPCODE_QUERY 0

#define RCODE_SUCCESS 0
#define RCODE_FORMAT_ERROR 1
#define RCODE_SERVER_ERROR 2
#define RCODE_NAME_ERROR 3
#define RCODE_NOT_IMPLEMENTED 4
#define RCODE_REFUSED 5

typedef struct {
    uint16_t id;
    uint8_t recursion_desired : 1;
    uint8_t is_truncated : 1;
    uint8_t is_authoritative : 1;
    uint8_t opcode : 4;
    uint8_t is_response : 1;
    uint8_t response_code : 4;
    uint8_t _reserved : 1;
    uint8_t checking_disabled : 1;
    uint8_t authentic_data : 1;
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
    char domain[MAX_DOMAIN_LENGTH + 1];
    uint16_t type;
    uint32_t ttl;
    uint16_t data_length;
    union {
        in_addr_t ip4_address;
        char domain[MAX_DOMAIN_LENGTH + 1];
        struct {
            char mname[MAX_DOMAIN_LENGTH + 1];
            char rname[MAX_DOMAIN_LENGTH + 1];
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t min_ttl;
        } soa;
        TXT txt;
        struct in6_addr ip6_address;
    } data;
} ResourceRecord;

uint16_t str_to_qtype(const char *str);
const char *type_to_str(uint16_t type);

void free_rr(ResourceRecord *rr);

ssize_t write_request(uint8_t *buffer, bool recursion_desired, const char *domain, uint16_t qtype, uint16_t *id);

const uint8_t *read_response_header(const uint8_t *ptr, const uint8_t *end, DNSHeader *header, uint16_t req_id);
const uint8_t *validate_question(const uint8_t *message, const uint8_t *ptr, const uint8_t *end, uint16_t req_qtype,
                                 const char *req_domain);
const uint8_t *read_resource_record(const uint8_t *message, const uint8_t *ptr, const uint8_t *end, ResourceRecord *rr);

#endif  // DNS_H
