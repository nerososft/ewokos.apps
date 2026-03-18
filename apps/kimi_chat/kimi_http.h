#ifndef KIMI_HTTP_H
#define KIMI_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const char *role;
	const char *content;
} kimi_http_message_t;

typedef struct {
	int http_status;
	char *reply;
	char *response_id;
	char *error_message;
	char *response_json;
} kimi_http_result_t;

int kimi_http_chat(const char *api_key,
		const char *model,
		const char *thinking_mode,
		const kimi_http_message_t *messages,
		int message_count,
		int timeout_ms,
		kimi_http_result_t *out);

void kimi_http_result_clear(kimi_http_result_t *out);

#ifdef __cplusplus
}
#endif

#endif
