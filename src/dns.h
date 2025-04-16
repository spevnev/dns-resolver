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

#define CLASS_IN 1

#define OPCODE_QUERY 0
#define OPCODE_INVERSE_QUERY 1
#define OPCODE_STATUS 2

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
    uint8_t _reserved : 3;
    uint8_t recursion_available : 1;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
} DNSHeader;

typedef struct {
    char domain[MAX_DOMAIN_LENGTH];
    uint16_t type;
    uint32_t ttl;
    uint16_t data_length;
    union {
        in_addr_t ip4_address;  // network order
    } data;
} ResourceRecord;

uint16_t write_request_header(uint8_t *buffer, bool recursion_desired, uint8_t opcode, uint16_t question_count);
void write_question(uint8_t *buffer, const char *domain, uint16_t type);

uint8_t *read_response_header(uint8_t *buffer, DNSHeader *header);
uint8_t *read_question(uint8_t *message, uint8_t *buffer);
uint8_t *read_resource_record(uint8_t *message, uint8_t *buffer, ResourceRecord *rr);

#endif  // DNS_H
