#include <Widget/WidgetWin.h>
#include <Widget/WidgetX.h>
#include <Widget/EditLine.h>
#include <Widget/Label.h>
#include <Widget/LabelButton.h>
#include <Widget/RootWidget.h>
#include <Widget/Scroller.h>
#include <Widget/Text.h>
#include <x++/X.h>
#include <x++/XTheme.h>

#include <ewoksys/keydef.h>

#include <font/font.h>
#include <graph/graph_ex.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <string>

#include "kimi_http.h"

using namespace Ewok;
using std::string;

static const char *KIMI_CHAT_DEFAULT_MODEL = "kimi-k2.5";
static const char *KIMI_CHAT_DEFAULT_SYSTEM = "You are Kimi, a concise and helpful assistant.";
static const char *KIMI_CHAT_DEFAULT_THINKING = "disabled";
static const char *KIMI_CHAT_DEFAULT_API_KEY = "sk-I42FnrWQmJT4yEi8hNBLkIEjbSmDUFyOYAhgY0MOG2CzuILb";
static const int KIMI_CHAT_TIMEOUT_MS = 15000;
static const int KIMI_CHAT_MAX_HISTORY = 16;

static string kimiChatIntToString(int value) {
	char buffer[32] = {0};
	snprintf(buffer, sizeof(buffer) - 1, "%d", value);
	return string(buffer);
}

struct ChatTurn {
	string role;
	string content;
};

struct ChatHistory {
	int count;
	ChatTurn turns[KIMI_CHAT_MAX_HISTORY];

	ChatHistory() : count(0) {
	}
};

struct PendingOutcome {
	bool ok;
	int http_status;
	string user_prompt;
	string assistant_reply;
	string response_id;
	string error_message;
	string response_json;
	ChatHistory history_snapshot;

	PendingOutcome() : ok(false), http_status(0) {
	}
};

class KimiChatWindow;

class LeftLabel : public Label {
protected:
	void onRepaint(graph_t* g, XTheme* theme, const grect_t& r) {
		font_t* font = theme->getFont();
		int y;

		if (font == NULL) {
			return;
		}

		if (!alpha) {
			graph_fill(g, r.x, r.y, r.w, r.h, theme->basic.bgColor);
		}

		y = r.y + (r.h - (int)theme->basic.fontSize) / 2;
		graph_draw_text_font(g, r.x + 6, y, label.c_str(),
				font, theme->basic.fontSize, theme->basic.fgColor);
	}
public:
	explicit LeftLabel(const string& text) : Label(text) {
		alpha = true;
	}
};

class StatusLabel : public Label {
	KimiChatWindow* owner;
protected:
	void onRepaint(graph_t* g, XTheme* theme, const grect_t& r);
	void onTimer(uint32_t timerFPS, uint32_t timerStep);
public:
	explicit StatusLabel(KimiChatWindow* owner);
};

class SubmitEditLine : public EditLine {
	KimiChatWindow* owner;
protected:
	bool onIM(xevent_t* ev);
public:
	explicit SubmitEditLine(KimiChatWindow* owner);
};

struct RequestJob {
	KimiChatWindow* owner;
	string api_key;
	string model;
	string system_prompt;
	string thinking_mode;
	string user_prompt;
	ChatHistory history_snapshot;
};

class KimiChatWindow : public WidgetWin {
	pthread_mutex_t pending_lock;
	PendingOutcome* pending;
	bool request_running;
	ChatHistory history;
	string transcript;

	StatusLabel* status_label;
	Text* transcript_text;
	EditLine* api_key_edit;
	EditLine* model_edit;
	EditLine* system_edit;
	EditLine* thinking_edit;
	SubmitEditLine* user_edit;
	LabelButton* send_button;
	LabelButton* clear_button;

	void appendTranscriptLine(const string& prefix, const string& value) {
		transcript += prefix;
		transcript += value;
		transcript += "\n\n";
	}

	void refreshTranscript() {
		if (transcript_text != NULL) {
			transcript_text->setContent(transcript.c_str(), transcript.size());
		}
	}

	void setStatusText(const string& value) {
		if (status_label != NULL) {
			status_label->setLabel(value);
		}
	}

	void pushHistoryTurn(const string& role, const string& content) {
		if (history.count >= KIMI_CHAT_MAX_HISTORY) {
			for (int i = 1; i < history.count; ++i) {
				history.turns[i - 1] = history.turns[i];
			}
			history.count = KIMI_CHAT_MAX_HISTORY - 1;
		}

		history.turns[history.count].role = role;
		history.turns[history.count].content = content;
		history.count++;
	}

	static void* requestThread(void* arg) {
		RequestJob* job = (RequestJob*)arg;
		KimiChatWindow* owner = job->owner;
		kimi_http_message_t messages[1 + KIMI_CHAT_MAX_HISTORY + 1];
		int message_count = 0;
		PendingOutcome* outcome = new PendingOutcome();
		kimi_http_result_t result;
		int rc;

		memset(&result, 0, sizeof(result));

		if (!job->system_prompt.empty()) {
			messages[message_count].role = "system";
			messages[message_count].content = job->system_prompt.c_str();
			message_count++;
		}

		for (int i = 0; i < job->history_snapshot.count; ++i) {
			messages[message_count].role = job->history_snapshot.turns[i].role.c_str();
			messages[message_count].content = job->history_snapshot.turns[i].content.c_str();
			message_count++;
		}

		messages[message_count].role = "user";
		messages[message_count].content = job->user_prompt.c_str();
		message_count++;

		outcome->user_prompt = job->user_prompt;
		outcome->history_snapshot = job->history_snapshot;
		rc = kimi_http_chat(job->api_key.c_str(),
				job->model.c_str(),
				job->thinking_mode.c_str(),
				message_count == 0 ? NULL : messages,
				message_count,
				KIMI_CHAT_TIMEOUT_MS,
				&result);
		outcome->ok = (rc == 0);
		outcome->http_status = result.http_status;
		if (result.reply != NULL) {
			outcome->assistant_reply = result.reply;
		}
		if (result.response_id != NULL) {
			outcome->response_id = result.response_id;
		}
		if (result.error_message != NULL) {
			outcome->error_message = result.error_message;
		}
		if (result.response_json != NULL) {
			outcome->response_json = result.response_json;
		}
		kimi_http_result_clear(&result);

		pthread_mutex_lock(&owner->pending_lock);
		if (owner->pending != NULL) {
			delete owner->pending;
		}
		owner->pending = outcome;
		pthread_mutex_unlock(&owner->pending_lock);

		delete job;
		return NULL;
	}

	static void onSendClick(Widget* wd, xevent_t* evt, void* arg) {
		(void)wd;
		(void)arg;
		if (evt->type != XEVT_MOUSE || evt->state != MOUSE_STATE_CLICK) {
			return;
		}
		KimiChatWindow* win = (KimiChatWindow*)wd->getWin();
		win->beginRequest();
	}

	static void onClearClick(Widget* wd, xevent_t* evt, void* arg) {
		(void)arg;
		if (evt->type != XEVT_MOUSE || evt->state != MOUSE_STATE_CLICK) {
			return;
		}
		KimiChatWindow* win = (KimiChatWindow*)wd->getWin();
		win->clearConversation();
	}

	Container* addRow(RootWidget* root, int height) {
		Container* row = new Container();
		row->setType(Container::HORIZONTAL);
		row->fix(0, height);
		root->add(row);
		return row;
	}

	EditLine* addLabeledField(RootWidget* root, const char* label, const char* initial) {
		Container* row = addRow(root, 30);
		LeftLabel* field_label = new LeftLabel(label);
		EditLine* edit = new EditLine();

		field_label->fix(96, 0);
		row->add(field_label);

		row->add(edit);
		if (initial != NULL) {
			edit->setContent(initial);
		}
		return edit;
	}

public:
	KimiChatWindow() {
		pthread_mutex_init(&pending_lock, NULL);
		pending = NULL;
		request_running = false;
		status_label = NULL;
		transcript_text = NULL;
		api_key_edit = NULL;
		model_edit = NULL;
		system_edit = NULL;
		thinking_edit = NULL;
		user_edit = NULL;
		send_button = NULL;
		clear_button = NULL;
	}

	~KimiChatWindow() {
		if (pending != NULL) {
			delete pending;
		}
		pthread_mutex_destroy(&pending_lock);
	}

	void buildUI() {
		RootWidget* root = new RootWidget();
		Container* row;
		Container* transcript_row;
		LeftLabel* label;
		Scroller* transcript_scroller;

		root->setType(Container::VERTICLE);
		root->setAlpha(false);
		setRoot(root);

		status_label = new StatusLabel(this);
		status_label->fix(0, 24);
		root->add(status_label);

		api_key_edit = addLabeledField(root, "Key", KIMI_CHAT_DEFAULT_API_KEY);
		model_edit = addLabeledField(root, "Model", KIMI_CHAT_DEFAULT_MODEL);
		system_edit = addLabeledField(root, "System", KIMI_CHAT_DEFAULT_SYSTEM);
		thinking_edit = addLabeledField(root, "Thinking", KIMI_CHAT_DEFAULT_THINKING);

		transcript_row = new Container();
		transcript_row->setType(Container::HORIZONTAL);
		root->add(transcript_row);

		transcript_text = new Text();
		transcript_row->add(transcript_text);

		transcript_scroller = new Scroller();
		transcript_scroller->fix(8, 0);
		transcript_row->add(transcript_scroller);
		transcript_text->setScrollerV(transcript_scroller);

		row = addRow(root, 34);
		label = new LeftLabel("Message");
		label->fix(96, 0);
		row->add(label);

		user_edit = new SubmitEditLine(this);
		row->add(user_edit);

		send_button = new LabelButton("Send");
		send_button->fix(72, 0);
		send_button->setEventFunc(onSendClick);
		row->add(send_button);

		clear_button = new LabelButton("Clear");
		clear_button->fix(72, 0);
		clear_button->setEventFunc(onClearClick);
		row->add(clear_button);

		root->focus(user_edit);

			transcript =
				"Kimi Chat Desktop Test\n"
				"\n"
				"- default API key is prefilled and editable in the Key field\n"
				"- default model follows Moonshot Kimi K2.5 quickstart\n"
				"- thinking supports disabled / default / enabled\n"
				"\n";
		refreshTranscript();
		setStatusText("Ready");
	}

	void beginRequest() {
		RequestJob* job;
		pthread_t tid;
		string api_key;
		string model;
		string system_prompt;
		string thinking_mode;
		string user_prompt;

		if (request_running) {
			setStatusText("Request already in flight");
			return;
		}

		api_key = api_key_edit->getContent();
		model = model_edit->getContent();
		system_prompt = system_edit->getContent();
		thinking_mode = thinking_edit->getContent();
		user_prompt = user_edit->getContent();

		if (api_key.empty()) {
			setStatusText("Missing API key");
			appendTranscriptLine("error: ", "Enter your Moonshot API key in the API Key field.");
			refreshTranscript();
			return;
		}

		if (model.empty()) {
			model = KIMI_CHAT_DEFAULT_MODEL;
			model_edit->setContent(model);
		}

		if (thinking_mode.empty()) {
			thinking_mode = KIMI_CHAT_DEFAULT_THINKING;
			thinking_edit->setContent(thinking_mode);
		}

		if (user_prompt.empty()) {
			setStatusText("Message is empty");
			return;
		}

		job = new RequestJob();
		job->owner = this;
		job->api_key = api_key;
		job->model = model;
		job->system_prompt = system_prompt;
		job->thinking_mode = thinking_mode;
		job->user_prompt = user_prompt;
		job->history_snapshot = history;

		appendTranscriptLine("you: ", user_prompt);
		refreshTranscript();
		user_edit->setContent("");
		send_button->setLabel("Busy");
		setStatusText("Requesting Moonshot...");
		busy(true);
		request_running = true;

		if (pthread_create(&tid, NULL, requestThread, job) == 0) {
			return;
		}

		request_running = false;
		busy(false);
		send_button->setLabel("Send");
		setStatusText("Failed to start request thread");
		delete job;
	}

	void clearConversation() {
		if (request_running) {
			setStatusText("Wait for the current request to finish");
			return;
		}
		history.count = 0;
			transcript =
				"Kimi Chat Desktop Test\n"
				"\n"
				"- default API key is prefilled and editable in the Key field\n"
				"- default model follows Moonshot Kimi K2.5 quickstart\n"
				"- thinking supports disabled / default / enabled\n"
				"\n";
		refreshTranscript();
		setStatusText("Conversation cleared");
	}

	void flushPending() {
		PendingOutcome* done = NULL;

		pthread_mutex_lock(&pending_lock);
		done = pending;
		pending = NULL;
		pthread_mutex_unlock(&pending_lock);

		if (done == NULL) {
			return;
		}

		request_running = false;
		busy(false);
		send_button->setLabel("Send");

		if (done->ok) {
			string status = "HTTP " + kimiChatIntToString(done->http_status);

			history = done->history_snapshot;
			pushHistoryTurn("user", done->user_prompt);
			pushHistoryTurn("assistant", done->assistant_reply);

			appendTranscriptLine("kimi: ", done->assistant_reply);
			if (!done->response_id.empty()) {
				status += "  id=" + done->response_id;
			}
			setStatusText(status);
		}
		else {
			string detail = done->error_message;
			string status = "Request failed";
			if (done->http_status > 0) {
				status += " (HTTP " + kimiChatIntToString(done->http_status) + ")";
			}
			if (detail.empty()) {
				detail = "unknown error";
			}
			appendTranscriptLine("error: ", detail);
			if (!done->response_json.empty()) {
				appendTranscriptLine("raw: ", done->response_json);
			}
			setStatusText(status);
		}

		refreshTranscript();
		delete done;
	}
};

StatusLabel::StatusLabel(KimiChatWindow* owner) : Label("Ready"), owner(owner) {
	alpha = false;
}

void StatusLabel::onRepaint(graph_t* g, XTheme* theme, const grect_t& r) {
	font_t* font = theme->getFont();
	int y;

	if (font == NULL) {
		return;
	}

	graph_fill_3d(g, r.x, r.y, r.w, r.h, theme->basic.titleBGColor, true);
	y = r.y + (r.h - font_get_height(font, theme->basic.fontSize)) / 2;
	graph_draw_text_font(g, r.x + 6, y, label.c_str(),
			font, theme->basic.fontSize, theme->basic.titleColor);
}

void StatusLabel::onTimer(uint32_t timerFPS, uint32_t timerStep) {
	(void)timerFPS;
	(void)timerStep;
	if (owner != NULL) {
		owner->flushPending();
	}
}

SubmitEditLine::SubmitEditLine(KimiChatWindow* owner) : owner(owner) {
}

bool SubmitEditLine::onIM(xevent_t* ev) {
	if (ev->state == XIM_STATE_PRESS && ev->value.im.value == KEY_ENTER) {
		if (owner != NULL) {
			owner->beginRequest();
		}
		return true;
	}
	return EditLine::onIM(ev);
}

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;

	X x;
	KimiChatWindow win;

	win.buildUI();
	win.open(&x, -1, -1, -1, 720, 520, "kimi_chat", XWIN_STYLE_NORMAL);
	win.setTimer(20);
	widgetXRun(&x, &win);
	return 0;
}
