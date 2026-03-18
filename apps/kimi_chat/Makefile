SW_ROOT_DIR=../..
include $(SW_ROOT_DIR)/make.inc

TASK = kimi_chat
TASK_OBJS = kimi_chat.o kimi_http.o
BUILD_DIR = $(SW_ROOT_DIR)/build/$(HW)/apps/$(TASK)

CFLAGS += -I ../https_test/include

all: $(TASK)

$(TASK): $(TASK_OBJS)
	mkdir -p $(BUILD_DIR)
	$(LD) -Ttext=100 $(TASK_OBJS) -o $(BUILD_DIR)/$(TASK) $(LDFLAGS) $(EWOK_LIB_X) $(EWOK_LIB_GRAPH) -lsocket $(EWOK_LIBC) -lcxx
	cp -r res $(BUILD_DIR)

clean:
	rm -f $(TASK_OBJS)
