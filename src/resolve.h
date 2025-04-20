#ifndef RESOLVE_H
#define RESOLVE_H

#include <stdbool.h>
#include <stdint.h>

void resolve(char *domain, const char *nameserver_ip, uint16_t qtype, int timeout_sec, bool recursion_desired);

#endif  // RESOLVE_H
