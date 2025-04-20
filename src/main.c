#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"
#include "error.h"
#include "resolve.h"

static const char *ROOT_NAMESERVER_IP = "198.41.0.4";  // a.root-servers.net

#define SHIFT_ARGS() (assert(argc > 0), argc--, *(argv++))

static void usage(const char *program) {
    printf("Usage:\n");
    printf("  %s domain\n", program);
    printf("Options:\n");
    printf("  -h, --help      - show this message\n");
    printf("  -s, --server    - specify nameserver IP address\n");
    printf("  -t, --type      - specify query type\n");
    printf("  -T, --timeout   - timeout in seconds\n");
    printf("  --no-recursion  - set Recursion Desired to false\n");
}

int main(int argc, char **argv) {
    if (argc == 0) ERROR("Invalid arguments");
    const char *program = SHIFT_ARGS();

    const char *nameserver_ip = ROOT_NAMESERVER_IP;
    uint16_t qtype = TYPE_A;
    int timeout_sec = 10;
    bool recursion_desired = true;
    char *domain = NULL;
    while (argc > 0) {
        char *arg = SHIFT_ARGS();

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            usage(program);
            return EXIT_SUCCESS;
        } else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--server") == 0) {
            if (argc == 0) ERROR("Expected IP address of nameserver after %s", arg);
            nameserver_ip = SHIFT_ARGS();
        } else if (strcmp(arg, "-t") == 0 || strcmp(arg, "--type") == 0) {
            if (argc == 0) ERROR("Expected query type after %s", arg);
            qtype = get_qtype(SHIFT_ARGS());
        } else if (strcmp(arg, "-T") == 0 || strcmp(arg, "--timeout") == 0) {
            if (argc == 0) ERROR("Expected timeout after %s", arg);
            const char *timeout_arg = SHIFT_ARGS();

            char *end = NULL;
            timeout_sec = strtol(timeout_arg, &end, 10);
            if (*end != '\0' || timeout_sec <= 0) {
                ERROR("Timeout must be a positive integer but found \"%s\"", timeout_arg);
            }
        } else if (strcmp(arg, "--no-recursion") == 0) {
            recursion_desired = false;
        } else {
            // Unknown flag/option.
            size_t arg_len = strlen(arg);
            if (arg_len > 2 && arg[0] == '-' && arg[1] != '-') ERROR("Unknown option \"%s\"", arg);  // short option
            if (arg_len > 3 && arg[0] == '-' && arg[1] == '-') ERROR("Unknown option \"%s\"", arg);  // long option

            // Multiple arguments.
            if (domain != NULL) ERROR("Expected one argument (domain) but found \"%s\" and \"%s\"", domain, arg);
            domain = arg;
        }
    }
    if (domain == NULL) ERROR("Invalid arguments, domain is not specified");

    resolve(domain, nameserver_ip, qtype, timeout_sec, recursion_desired);
    return EXIT_SUCCESS;
}
