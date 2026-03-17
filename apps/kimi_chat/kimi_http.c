#include "kimi_http.h"

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

static int kimi_http_open_compat(const char *path, int flags, ...);
static ssize_t kimi_http_read_compat(int fd, void *buf, size_t len);
static int kimi_http_close_compat(int fd);
static int kimi_http_fcntl_compat(int fd, int cmd, ...);
static int kimi_http_select_compat(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout);
static int kimi_http_getsockopt_compat(int fd, int level, int optname,
		void *optval, socklen_t *optlen);
static int kimi_http_getentropy_compat(void *buf, size_t len);
static void kimi_http_entropy_fill(void *buf, size_t len);
static int kimi_http_validation_time(uint32_t *days, uint32_t *seconds);
void ewok_https_entropy_fill(void *buf, size_t len);
int ewok_https_validation_time(uint32_t *days, uint32_t *seconds);
const char* kimi_gai_strerror_compat(int ecode);
void kimi_freeaddrinfo_compat(struct addrinfo *res);

#define __linux__ 1
#define __unix__ 1
#define open kimi_http_open_compat
#define read kimi_http_read_compat
#define close kimi_http_close_compat
#define fcntl kimi_http_fcntl_compat
#define select kimi_http_select_compat
#define getsockopt kimi_http_getsockopt_compat
#define getentropy kimi_http_getentropy_compat
#define gai_strerror kimi_gai_strerror_compat
#define freeaddrinfo kimi_freeaddrinfo_compat
#include "../https_test/vendor/BearHttpsClientOne.c"
#undef freeaddrinfo
#undef gai_strerror
#undef getentropy
#undef getsockopt
#undef select
#undef fcntl
#undef close
#undef read
#undef open

#define KIMI_HTTP_FAKE_URANDOM_FD (-0x7171)
#define KIMI_HTTP_DEFAULT_TIMEOUT_MS 15000

static uint64_t kimi_http_entropy_state = 0;

static char *kimi_http_strdup(const char *value) {
	size_t size;
	char *copy;

	if (value == NULL) {
		return NULL;
	}
	size = strlen(value) + 1;
	copy = (char *)malloc(size);
	if (copy == NULL) {
		return NULL;
	}
	memcpy(copy, value, size);
	return copy;
}

static char *kimi_http_strdup_printf(const char *fmt, ...) {
	va_list args;
	va_list args_copy;
	int needed;
	char *buffer;

	va_start(args, fmt);
	va_copy(args_copy, args);
	needed = vsnprintf(NULL, 0, fmt, args_copy);
	va_end(args_copy);
	if (needed < 0) {
		va_end(args);
		return NULL;
	}

	buffer = (char *)malloc((size_t)needed + 1);
	if (buffer == NULL) {
		va_end(args);
		return NULL;
	}

	vsnprintf(buffer, (size_t)needed + 1, fmt, args);
	va_end(args);
	return buffer;
}

static void kimi_http_append_text(char **buffer, size_t *size, const char *text) {
	size_t old_size;
	size_t add_size;
	char *next;

	if (buffer == NULL || size == NULL || text == NULL || text[0] == '\0') {
		return;
	}

	old_size = *size;
	add_size = strlen(text);
	next = (char *)realloc(*buffer, old_size + add_size + 1);
	if (next == NULL) {
		return;
	}

	memcpy(next + old_size, text, add_size);
	next[old_size + add_size] = '\0';
	*buffer = next;
	*size = old_size + add_size;
}

static char *kimi_http_json_to_string(const cJSON *json) {
	char *printed;
	char *copy;

	if (json == NULL) {
		return NULL;
	}

	printed = cJSON_Print((cJSON *)json);
	if (printed == NULL) {
		return NULL;
	}

	copy = kimi_http_strdup(printed);
	BearsslHttps_free(printed);
	return copy;
}

static char *kimi_http_extract_message_content(const cJSON *message) {
	const cJSON *content;
	const cJSON *reasoning;
	char *joined = NULL;
	size_t joined_size = 0;
	int total;
	int i;

	if (message == NULL) {
		return NULL;
	}

	content = cJSON_GetObjectItemCaseSensitive((cJSON *)message, "content");
	if (cJSON_IsString(content) && content->valuestring != NULL) {
		if (content->valuestring[0] != '\0') {
			return kimi_http_strdup(content->valuestring);
		}
	}

	if (!cJSON_IsArray(content)) {
		reasoning = cJSON_GetObjectItemCaseSensitive((cJSON *)message, "reasoning_content");
		if (cJSON_IsString(reasoning) && reasoning->valuestring != NULL &&
				reasoning->valuestring[0] != '\0') {
			return kimi_http_strdup(reasoning->valuestring);
		}
		return NULL;
	}

	total = cJSON_GetArraySize((cJSON *)content);
	for (i = 0; i < total; ++i) {
		const cJSON *part = cJSON_GetArrayItem((cJSON *)content, i);
		const cJSON *type;
		const cJSON *text;

		if (cJSON_IsString(part) && part->valuestring != NULL) {
			kimi_http_append_text(&joined, &joined_size, part->valuestring);
			continue;
		}

		if (!cJSON_IsObject(part)) {
			continue;
		}

		type = cJSON_GetObjectItemCaseSensitive((cJSON *)part, "type");
		text = cJSON_GetObjectItemCaseSensitive((cJSON *)part, "text");
		if (cJSON_IsString(text) && text->valuestring != NULL) {
			if (!cJSON_IsString(type) || strcmp(type->valuestring, "text") == 0) {
				kimi_http_append_text(&joined, &joined_size, text->valuestring);
			}
		}
	}

	if (joined == NULL || joined[0] == '\0') {
		reasoning = cJSON_GetObjectItemCaseSensitive((cJSON *)message, "reasoning_content");
		if (cJSON_IsString(reasoning) && reasoning->valuestring != NULL &&
				reasoning->valuestring[0] != '\0') {
			if (joined != NULL) {
				free(joined);
			}
			return kimi_http_strdup(reasoning->valuestring);
		}
	}

	return joined;
}

static char *kimi_http_extract_reply(const cJSON *root) {
	const cJSON *choices;
	const cJSON *choice;
	const cJSON *message;

	if (root == NULL) {
		return NULL;
	}

	choices = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "choices");
	if (!cJSON_IsArray(choices) || cJSON_GetArraySize((cJSON *)choices) <= 0) {
		return NULL;
	}

	choice = cJSON_GetArrayItem((cJSON *)choices, 0);
	if (!cJSON_IsObject(choice)) {
		return NULL;
	}

	message = cJSON_GetObjectItemCaseSensitive((cJSON *)choice, "message");
	if (!cJSON_IsObject(message)) {
		return NULL;
	}

	return kimi_http_extract_message_content(message);
}

static char *kimi_http_extract_error_message(const cJSON *root) {
	const cJSON *error;
	const cJSON *message;

	if (root == NULL) {
		return NULL;
	}

	error = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "error");
	if (cJSON_IsObject(error)) {
		message = cJSON_GetObjectItemCaseSensitive((cJSON *)error, "message");
		if (cJSON_IsString(message) && message->valuestring != NULL) {
			return kimi_http_strdup(message->valuestring);
		}
		return kimi_http_json_to_string(error);
	}

	message = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "message");
	if (cJSON_IsString(message) && message->valuestring != NULL) {
		return kimi_http_strdup(message->valuestring);
	}

	return kimi_http_json_to_string(root);
}

static char *kimi_http_extract_response_id(const cJSON *root) {
	const cJSON *id;

	if (root == NULL) {
		return NULL;
	}

	id = cJSON_GetObjectItemCaseSensitive((cJSON *)root, "id");
	if (cJSON_IsString(id) && id->valuestring != NULL) {
		return kimi_http_strdup(id->valuestring);
	}
	return NULL;
}

in_addr_t inet_addr(const char *cp) {
	struct in_addr addr;
	if (inet_pton(AF_INET, cp, &addr) != 1) {
		return INADDR_NONE;
	}
	return addr.s_un.s_addr;
}

static uint64_t kimi_http_entropy_word(void) {
	uint64_t usec = 0;
	uint64_t mix;

	kernel_tic(NULL, &usec);
	mix = usec;
	mix ^= ((uint64_t)(uint32_t)time(NULL) << 32);
	mix ^= (uint64_t)(uint32_t)getpid();
	mix ^= (uint64_t)(uintptr_t)&mix;
	mix ^= kimi_http_entropy_state + 0x9e3779b97f4a7c15ULL;
	mix ^= mix << 13;
	mix ^= mix >> 7;
	mix ^= mix << 17;
	if (mix == 0) {
		mix = 0x2545f4914f6cdd1dULL;
	}
	kimi_http_entropy_state = mix;
	return mix;
}

static int kimi_http_month_from_abbrev(const char *mon) {
	static const char *months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	int i;

	for (i = 0; i < 12; ++i) {
		if (strcmp(mon, months[i]) == 0) {
			return i + 1;
		}
	}
	return -1;
}

static int64_t kimi_http_days_from_civil(int year, unsigned month, unsigned day) {
	int era;
	unsigned yoe;
	unsigned doy;
	unsigned doe;

	year -= month <= 2;
	era = (year >= 0 ? year : year - 399) / 400;
	yoe = (unsigned)(year - era * 400);
	doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

static int kimi_http_validation_time(uint32_t *days, uint32_t *seconds) {
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

		month = kimi_http_month_from_abbrev(month_name);
		if (month < 1) {
			return -1;
		}

		unix_days = kimi_http_days_from_civil(year, (unsigned)month, (unsigned)day);
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

static void kimi_http_entropy_fill(void *buf, size_t len) {
	unsigned char *out = (unsigned char *)buf;

	while (len > 0) {
		uint64_t word = kimi_http_entropy_word();
		size_t chunk = len > sizeof(word) ? sizeof(word) : len;
		memcpy(out, &word, chunk);
		out += chunk;
		len -= chunk;
		proc_usleep(1);
	}
}

static int kimi_http_open_compat(const char *path, int flags, ...) {
	(void)flags;
	if (path != NULL && strcmp(path, "/dev/urandom") == 0) {
		return KIMI_HTTP_FAKE_URANDOM_FD;
	}
	return open(path, flags);
}

static ssize_t kimi_http_read_compat(int fd, void *buf, size_t len) {
	if (fd == KIMI_HTTP_FAKE_URANDOM_FD) {
		kimi_http_entropy_fill(buf, len);
		return (ssize_t)len;
	}
	return read(fd, buf, len);
}

static int kimi_http_close_compat(int fd) {
	if (fd == KIMI_HTTP_FAKE_URANDOM_FD) {
		return 0;
	}
	return close(fd);
}

static int kimi_http_fcntl_compat(int fd, int cmd, ...) {
	(void)fd;
	(void)cmd;
	return 0;
}

static int kimi_http_select_compat(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout) {
	(void)nfds;
	(void)readfds;
	(void)writefds;
	(void)exceptfds;
	(void)timeout;
	return 1;
}

static int kimi_http_getsockopt_compat(int fd, int level, int optname,
		void *optval, socklen_t *optlen) {
	(void)fd;
	(void)level;
	(void)optname;
	if (optval != NULL && optlen != NULL && *optlen >= sizeof(int)) {
		*(int *)optval = 0;
	}
	return 0;
}

static int kimi_http_getentropy_compat(void *buf, size_t len) {
	if (buf == NULL) {
		errno = EINVAL;
		return -1;
	}
	kimi_http_entropy_fill(buf, len);
	return 0;
}

void ewok_https_entropy_fill(void *buf, size_t len) {
	kimi_http_entropy_fill(buf, len);
}

int ewok_https_validation_time(uint32_t *days, uint32_t *seconds) {
	return kimi_http_validation_time(days, seconds);
}

const char* kimi_gai_strerror_compat(int ecode) {
	switch (ecode) {
	case 0:
		return "success";
	default:
		return "DNS resolution failed";
	}
}

void kimi_freeaddrinfo_compat(struct addrinfo *res) {
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

void kimi_http_result_clear(kimi_http_result_t *out) {
	if (out == NULL) {
		return;
	}

	if (out->reply != NULL) {
		free(out->reply);
	}
	if (out->response_id != NULL) {
		free(out->response_id);
	}
	if (out->error_message != NULL) {
		free(out->error_message);
	}
	if (out->response_json != NULL) {
		free(out->response_json);
	}

	memset(out, 0, sizeof(*out));
}

int kimi_http_chat(const char *api_key,
		const char *model,
		const char *thinking_mode,
		const kimi_http_message_t *messages,
		int message_count,
		int timeout_ms,
		kimi_http_result_t *out) {
	BearHttpsRequest *request = NULL;
	BearHttpsResponse *response = NULL;
	cJSON *payload = NULL;
	cJSON *messages_json = NULL;
	cJSON *response_json = NULL;
	const char *body_str = NULL;
	const char *model_name = "kimi-k2.5";
	int i;
	int rc = -1;

	if (out == NULL) {
		return -1;
	}
	memset(out, 0, sizeof(*out));

	if (api_key == NULL || api_key[0] == '\0') {
		out->error_message = kimi_http_strdup("missing Moonshot API key");
		return -1;
	}

	if (messages == NULL || message_count <= 0) {
		out->error_message = kimi_http_strdup("missing chat messages");
		return -1;
	}

	if (model != NULL && model[0] != '\0') {
		model_name = model;
	}

	request = newBearHttpsRequest("https://api.moonshot.cn/v1/chat/completions");
	if (request == NULL) {
		out->error_message = kimi_http_strdup("cannot allocate HTTPS request");
		goto cleanup;
	}

	request->connection_timeout = timeout_ms > 0 ? timeout_ms : KIMI_HTTP_DEFAULT_TIMEOUT_MS;
	BearHttpsRequest_set_method(request, "POST");
	BearHttpsRequest_set_max_redirections(request, 0);
	BearHttpsRequest_add_header_fmt(request, "Authorization", "Bearer %s", api_key);
	BearHttpsRequest_add_header(request, "Accept", "application/json");
	BearHttpsRequest_add_header(request, "User-Agent", "ewokos-kimi-chat/1");

	payload = cJSON_CreateObject();
	if (payload == NULL) {
		out->error_message = kimi_http_strdup("cannot allocate JSON payload");
		goto cleanup;
	}

	cJSON_AddStringToObject(payload, "model", model_name);
	messages_json = cJSON_AddArrayToObject(payload, "messages");
	if (messages_json == NULL) {
		out->error_message = kimi_http_strdup("cannot allocate messages array");
		goto cleanup;
	}

	for (i = 0; i < message_count; ++i) {
		cJSON *message_json;
		const char *role = messages[i].role;
		const char *content = messages[i].content;

		if (role == NULL || role[0] == '\0' || content == NULL || content[0] == '\0') {
			continue;
		}

		message_json = cJSON_CreateObject();
		if (message_json == NULL) {
			out->error_message = kimi_http_strdup("cannot allocate message JSON");
			goto cleanup;
		}

		cJSON_AddStringToObject(message_json, "role", role);
		cJSON_AddStringToObject(message_json, "content", content);
		cJSON_AddItemToArray(messages_json, message_json);
	}

	if (thinking_mode != NULL && thinking_mode[0] != '\0' &&
			strcmp(thinking_mode, "default") != 0 &&
			strcmp(thinking_mode, "auto") != 0) {
		cJSON *extra_body = cJSON_AddObjectToObject(payload, "extra_body");
		cJSON *thinking = NULL;
		if (extra_body != NULL) {
			thinking = cJSON_AddObjectToObject(extra_body, "thinking");
		}
		if (thinking != NULL) {
			cJSON_AddStringToObject(thinking, "type", thinking_mode);
		}
	}

	BearHttpsRequest_send_cJSON_with_ownership_control(request, payload, BEARSSL_HTTPS_GET_OWNERSHIP);
	payload = NULL;

	response = BearHttpsRequest_fetch(request);
	if (response == NULL) {
		out->error_message = kimi_http_strdup("fetch returned null response");
		goto cleanup;
	}

	out->http_status = BearHttpsResponse_get_status_code(response);

	if (BearHttpsResponse_error(response)) {
		int ssl_error = 0;
		if (response->is_https) {
			ssl_error = br_ssl_engine_last_error(&response->ssl_client.eng);
		}
		out->error_message = kimi_http_strdup_printf("%s (code=%d, ssl=%d)",
				BearHttpsResponse_get_error_msg(response),
				BearHttpsResponse_get_error_code(response),
				ssl_error);
		goto cleanup;
	}

	body_str = BearHttpsResponse_read_body_str(response);
	if (body_str != NULL) {
		out->response_json = kimi_http_strdup(body_str);
		response_json = cJSON_Parse(body_str);
	}

	if (response_json != NULL) {
		out->response_id = kimi_http_extract_response_id(response_json);
	}

	if (out->http_status >= 200 && out->http_status < 300) {
		out->reply = kimi_http_extract_reply(response_json);
		if (out->reply == NULL) {
			out->error_message = kimi_http_strdup("response has no assistant message");
			goto cleanup;
		}
		rc = 0;
		goto cleanup;
	}

	out->error_message = kimi_http_extract_error_message(response_json);
	if (out->error_message == NULL && out->response_json != NULL) {
		out->error_message = kimi_http_strdup(out->response_json);
	}
	if (out->error_message == NULL) {
		out->error_message = kimi_http_strdup_printf("HTTP %d", out->http_status);
	}

cleanup:
	if (response_json != NULL) {
		cJSON_Delete(response_json);
	}
	if (payload != NULL) {
		cJSON_Delete(payload);
	}
	if (response != NULL) {
		BearHttpsResponse_free(response);
	}
	if (request != NULL) {
		BearHttpsRequest_free(request);
	}
	if (rc != 0 && out->error_message == NULL) {
		out->error_message = kimi_http_strdup("request failed");
	}
	return rc;
}
