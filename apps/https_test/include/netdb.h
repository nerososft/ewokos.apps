#ifndef EXTRA_APPS_HTTPS_TEST_NETDB_H
#define EXTRA_APPS_HTTPS_TEST_NETDB_H

#include <sys/socket.h>

const char* ewok_gai_strerror_compat(int ecode);
void ewok_freeaddrinfo_compat(struct addrinfo *res);

#endif
