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
    bool *recursion_desired = option_bool('r', "recurse", "set Recursion Desired", true, true);

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

    resolve(domain, *nameserver_ip, *port, qtype, *timeout_sec, *recursion_desired);
    return EXIT_SUCCESS;
}
