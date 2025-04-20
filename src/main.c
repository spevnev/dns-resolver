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

static const char *ROOT_NAMESERVER_IP = "198.41.0.4";  // a.root-servers.net

static void usage(const char *program) {
    printf("Usage: %s domain\n", program);
    printf("Options:\n");
    print_options();
}

int main(int argc, char **argv) {
    bool *help = option_bool('h', "help", "show this message", false, false);
    const char **nameserver_ip = option_str('s', "server", "specify nameserver IP address", false, ROOT_NAMESERVER_IP);
    const char **qtype_str = option_str('t', "type", "specify query type", true, "A");
    long *timeout_sec = option_long('T', "timeout", "timeout in seconds", true, 10);
    bool *recursion_desired = option_bool(0, "recurse", "set Recursion Desired", true, true);

    const char *program = parse_args(argc, argv);

    if (*help) {
        usage(program);
        return EXIT_SUCCESS;
    }

    uint16_t qtype = get_qtype(*qtype_str);
    if (*timeout_sec <= 0) ERROR("Timeout must be a positive integer");

    if (!has_next_arg()) ERROR("Invalid arguments, domain is not specified");
    char *domain = next_arg();
    if (has_next_arg()) ERROR("Expected one argument (domain) but found \"%s\" and \"%s\"", domain, next_arg());

    resolve(domain, *nameserver_ip, qtype, *timeout_sec, *recursion_desired);
    return EXIT_SUCCESS;
}
