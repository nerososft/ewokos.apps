#include <stddef.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <ewoksys/kernel_tic.h>
#include <ewoksys/proc.h>

#include "netdb.h"

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif

#ifndef SO_ERROR
#define SO_ERROR 4
#endif

#ifndef EINTR
#define EINTR 4
#endif

#ifndef EINPROGRESS
#define EINPROGRESS 119
#endif

#ifndef EINVAL
#define EINVAL 22
#endif

static int ewok_https_open_compat(const char *path, int flags, ...);
static ssize_t ewok_https_read_compat(int fd, void *buf, size_t len);
static int ewok_https_close_compat(int fd);
static int ewok_https_fcntl_compat(int fd, int cmd, ...);
static int ewok_https_select_compat(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout);
static int ewok_https_getsockopt_compat(int fd, int level, int optname,
		void *optval, socklen_t *optlen);
static int ewok_https_getentropy_compat(void *buf, size_t len);
static void ewok_https_entropy_fill(void *buf, size_t len);
static int ewok_https_validation_time(uint32_t *days, uint32_t *seconds);

#define __linux__ 1
#define __unix__ 1
#define open ewok_https_open_compat
#define read ewok_https_read_compat
#define close ewok_https_close_compat
#define fcntl ewok_https_fcntl_compat
#define select ewok_https_select_compat
#define getsockopt ewok_https_getsockopt_compat
#define getentropy ewok_https_getentropy_compat
#define gai_strerror ewok_gai_strerror_compat
#define freeaddrinfo ewok_freeaddrinfo_compat
#include "vendor/BearHttpsClientOne.c"
#undef freeaddrinfo
#undef gai_strerror
#undef getentropy
#undef getsockopt
#undef select
#undef fcntl
#undef close
#undef read
#undef open

#define EWOK_HTTPS_FAKE_URANDOM_FD (-0x7070)
#define EWOK_HTTPS_PREVIEW_LIMIT 512

static uint64_t ewok_https_entropy_state = 0;

in_addr_t inet_addr(const char *cp) {
	struct in_addr addr;
	if (inet_pton(AF_INET, cp, &addr) != 1) {
		return INADDR_NONE;
	}
	return addr.s_un.s_addr;
}

static uint64_t ewok_https_entropy_word(void) {
	uint64_t usec = 0;
	uint64_t mix;

	kernel_tic(NULL, &usec);
	mix = usec;
	mix ^= ((uint64_t)(uint32_t)time(NULL) << 32);
	mix ^= (uint64_t)(uint32_t)getpid();
	mix ^= (uint64_t)(uintptr_t)&mix;
	mix ^= ewok_https_entropy_state + 0x9e3779b97f4a7c15ULL;
	mix ^= mix << 13;
	mix ^= mix >> 7;
	mix ^= mix << 17;
	if (mix == 0) {
		mix = 0x2545f4914f6cdd1dULL;
	}
	ewok_https_entropy_state = mix;
	return mix;
}

static int ewok_https_month_from_abbrev(const char *mon) {
	static const char *months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};

	for (int i = 0; i < 12; ++i) {
		if (strcmp(mon, months[i]) == 0) {
			return i + 1;
		}
	}
	return -1;
}

static int64_t ewok_https_days_from_civil(int year, unsigned month, unsigned day) {
	year -= month <= 2;
	const int era = (year >= 0 ? year : year - 399) / 400;
	const unsigned yoe = (unsigned)(year - era * 400);
	const unsigned doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

static int ewok_https_validation_time(uint32_t *days, uint32_t *seconds) {
	static bool cached = false;
	static uint32_t cached_days = 0;
	static uint32_t cached_seconds = 0;

	if (!cached) {
		char month_name[4] = {0};
		int day;
		int year;
		int hour;
		int minute;
		int second;
		int month;
		int64_t unix_days;

		if (sscanf(__DATE__, "%3s %d %d", month_name, &day, &year) != 3) {
			return -1;
		}
		if (sscanf(__TIME__, "%d:%d:%d", &hour, &minute, &second) != 3) {
			return -1;
		}

		month = ewok_https_month_from_abbrev(month_name);
		if (month < 1) {
			return -1;
		}

		unix_days = ewok_https_days_from_civil(year, (unsigned)month, (unsigned)day);
		if (unix_days < 0) {
			return -1;
		}

		cached_days = (uint32_t)(719528 + unix_days);
		cached_seconds = (uint32_t)(hour * 3600 + minute * 60 + second);
		cached = true;
	}

	if (days != NULL) {
		*days = cached_days;
	}
	if (seconds != NULL) {
		*seconds = cached_seconds;
	}
	return 0;
}

static void ewok_https_entropy_fill(void *buf, size_t len) {
	unsigned char *out = (unsigned char *)buf;

	while (len > 0) {
		uint64_t word = ewok_https_entropy_word();
		size_t chunk = len > sizeof(word) ? sizeof(word) : len;
		memcpy(out, &word, chunk);
		out += chunk;
		len -= chunk;
		proc_usleep(1);
	}
}

static int ewok_https_open_compat(const char *path, int flags, ...) {
	(void)flags;
	if (path != NULL && strcmp(path, "/dev/urandom") == 0) {
		return EWOK_HTTPS_FAKE_URANDOM_FD;
	}
	return open(path, flags);
}

static ssize_t ewok_https_read_compat(int fd, void *buf, size_t len) {
	if (fd == EWOK_HTTPS_FAKE_URANDOM_FD) {
		ewok_https_entropy_fill(buf, len);
		return (ssize_t)len;
	}
	return read(fd, buf, len);
}

static int ewok_https_close_compat(int fd) {
	if (fd == EWOK_HTTPS_FAKE_URANDOM_FD) {
		return 0;
	}
	return close(fd);
}

static int ewok_https_fcntl_compat(int fd, int cmd, ...) {
	(void)fd;
	(void)cmd;
	return 0;
}

static int ewok_https_select_compat(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout) {
	(void)nfds;
	(void)readfds;
	(void)writefds;
	(void)exceptfds;
	(void)timeout;
	return 1;
}

static int ewok_https_getsockopt_compat(int fd, int level, int optname,
		void *optval, socklen_t *optlen) {
	(void)fd;
	(void)level;
	(void)optname;
	if (optval != NULL && optlen != NULL && *optlen >= sizeof(int)) {
		*(int *)optval = 0;
	}
	return 0;
}

static int ewok_https_getentropy_compat(void *buf, size_t len) {
	if (buf == NULL) {
		errno = EINVAL;
		return -1;
	}
	ewok_https_entropy_fill(buf, len);
	return 0;
}

const char* ewok_gai_strerror_compat(int ecode) {
	switch (ecode) {
	case 0:
		return "success";
	default:
		return "getaddrinfo is not supported on Ewok; pass an explicit IPv4";
	}
}

void ewok_freeaddrinfo_compat(struct addrinfo *res) {
	while (res != NULL) {
		struct addrinfo *next = res->ai_next;
		if (res->ai_addr != NULL) {
			free(res->ai_addr);
		}
		if (res->ai_canonname != NULL) {
			free(res->ai_canonname);
		}
		free(res);
		res = next;
	}
}

static int parse_timeout_ms(const char *value) {
	int timeout = atoi(value);
	return timeout > 0 ? timeout : 5000;
}

static void print_preview(const char *body, int body_size) {
	int limit = body_size;
	if (limit > EWOK_HTTPS_PREVIEW_LIMIT) {
		limit = EWOK_HTTPS_PREVIEW_LIMIT;
	}

	printf("body_preview(%d bytes):\n", limit);
	for (int i = 0; i < limit; ++i) {
		unsigned char ch = (unsigned char)body[i];
		if (ch == '\n' || ch == '\r' || ch == '\t' || (ch >= 32 && ch <= 126)) {
			putchar((int)ch);
		}
		else {
			putchar('.');
		}
	}
	if (limit > 0 && body[limit - 1] != '\n') {
		putchar('\n');
	}
}

static void print_usage(const char *prog) {
	printf("usage: %s <https-url> <ipv4> [timeout_ms]\n", prog);
	printf("example: %s https://dns.google/resolve?name=example.com&type=A 8.8.8.8 5000\n", prog);
	printf("note: Ewok has no usable DNS yet, so keep the HTTPS host in the URL and pass its IPv4 separately.\n");
}

int main(int argc, char **argv) {
	const char *url;
	const char *known_ips[1];
	const char *body;
	const char *content_type;
	BearHttpsRequest *request;
	BearHttpsResponse *response;
	int timeout_ms = 5000;
	int status;
	int body_size;

	if (argc < 3) {
		print_usage(argv[0]);
		return 1;
	}

	url = argv[1];
	known_ips[0] = argv[2];
	if (argc > 3) {
		timeout_ms = parse_timeout_ms(argv[3]);
	}

	if (strncmp(url, "https://", 8) != 0) {
		printf("error: only https:// URLs are supported by this test app.\n");
		return 1;
	}

	request = newBearHttpsRequest(url);
	if (request == NULL) {
		printf("error: cannot allocate request\n");
		return 1;
	}

	request->connection_timeout = timeout_ms;
	BearHttpsRequest_set_known_ips(request, known_ips, 1);
	BearHttpsRequest_set_max_redirections(request, 0);
	BearHttpsRequest_add_header(request, "User-Agent", "ewokos-https-test/1");

	printf("requesting %s via %s (timeout=%dms)\n", url, known_ips[0], timeout_ms);
	response = BearHttpsRequest_fetch(request);
	if (response == NULL) {
		printf("error: fetch returned null response\n");
		BearHttpsRequest_free(request);
		return 1;
	}

	if (BearHttpsResponse_error(response)) {
		int ssl_error = 0;
		if (response->is_https) {
			ssl_error = br_ssl_engine_last_error(&response->ssl_client.eng);
		}
		printf("error: %s (code=%d, ssl=%d)\n",
			BearHttpsResponse_get_error_msg(response),
			BearHttpsResponse_get_error_code(response),
			ssl_error);
		BearHttpsResponse_free(response);
		BearHttpsRequest_free(request);
		return 2;
	}

	status = BearHttpsResponse_get_status_code(response);
	body_size = BearHttpsResponse_get_body_size(response);
	content_type = BearHttpsResponse_get_header_value_by_sanitized_key(response, "content-type");
	body = BearHttpsResponse_read_body_str(response);

	printf("status: %d\n", status);
	if (status >= 300 && status < 400) {
		const char *location = BearHttpsResponse_get_header_value_by_sanitized_key(response, "location");
		if (location != NULL) {
			printf("location: %s\n", location);
		}
	}
	printf("body_size: %d\n", body_size);
	if (content_type != NULL) {
		printf("content_type: %s\n", content_type);
	}

	if (body != NULL && body_size > 0) {
		print_preview(body, body_size);
	}
	else {
		printf("body_preview: <empty>\n");
	}

	BearHttpsResponse_free(response);
	BearHttpsRequest_free(request);
	return 0;
}
