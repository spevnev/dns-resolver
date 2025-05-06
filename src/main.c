#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "args.h"
#include "dns.h"
#include "error.h"
#include "resolve.h"

static const char *ROOT_NAMESERVER_IPS[] = {
    "198.41.0.4",    "170.247.170.2", "192.33.4.12",   "199.7.91.13",  "192.203.230.10", "192.5.5.241",  "192.112.36.4",
    "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",    "202.12.27.33",
};

static void usage(const char *program) {
    printf("Usage: %s domain\n", program);
    printf("Options:\n");
    print_options();
}

int main(int argc, char **argv) {
    bool *help = option_bool('h', "help", "show this message", false, false);
    const char **nameserver_ip = option_str('s', "server", "specify nameserver IP address", false, NULL);
    long *port = option_long('p', "port", "specify nameserver port", true, DNS_PORT);
    const char **qtype_str = option_str('t', "type", "specify query type", true, "A");
    long *timeout_sec = option_long('T', "timeout", "timeout in seconds", true, 10);
    bool *recursion_desired = option_bool('r', "rdflag", "set Recursion Desired", true, true);
    bool *enable_edns = option_bool('\0', "edns", "enable EDNS", true, true);
    bool *trace
        = option_bool('\0', "trace", "trace requests starting from root, ignores specified nameserver", true, false);

    const char *program = parse_args(argc, argv);

    if (*help) {
        usage(program);
        return EXIT_SUCCESS;
    }

    uint16_t qtype = str_to_qtype(*qtype_str);
    if (*timeout_sec <= 0) ERROR("Timeout must be a positive integer");
    if (*port <= 0 || *port > UINT16_MAX) ERROR("Port must be between 1 and 65535");

    if (!has_next_arg()) ERROR("Invalid arguments, domain is not specified");
    const char *domain = next_arg();
    if (has_next_arg()) ERROR("Expected one argument (domain) but found \"%s\" and \"%s\"", domain, next_arg());

    uint32_t flags = 0;
    if (*recursion_desired) flags |= RESOLVE_RECURSION_DESIRED;
    if (*enable_edns) flags |= RESOLVE_EDNS;

    if (*trace) {
        flags |= RESOLVE_TRACE;

        // Start search from one of the root nameservers.
        if (*nameserver_ip != NULL) printf("Ignoring specified nameserver because trace is enabled.\n");
        *nameserver_ip = ROOT_NAMESERVER_IPS[rand() % (sizeof(ROOT_NAMESERVER_IPS) / sizeof(*ROOT_NAMESERVER_IPS))];
    }

    RRVec results = resolve(domain, qtype, *nameserver_ip, *port, *timeout_sec, flags);

    if (results.length > 0) {
        printf("Answer:\n");
        for (uint32_t i = 0; i < results.length; i++) print_resource_record(&results.data[i]);
    }

    // If qtype is ANY and response matches section 4.2 of RFC8482, print special message.
    if (qtype == QTYPE_ANY && results.length == 1 && results.data[0].type == TYPE_HINFO
        && strcmp(results.data[0].data.hinfo.cpu, "RFC8482") == 0 && results.data[0].data.hinfo.os[0] == '\0') {
        printf("Nameserver does not support ANY query (see RFC8482).\n");
    }

    return EXIT_SUCCESS;
}
