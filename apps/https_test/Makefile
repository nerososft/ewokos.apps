SW_ROOT_DIR=../..
include $(SW_ROOT_DIR)/make.inc

TASK = https_test
TASK_OBJS = https_test.o
BUILD_DIR = $(SW_ROOT_DIR)/build/$(HW)/apps/$(TASK)

all: $(TASK)

$(TASK): $(TASK_OBJS)
	mkdir -p $(BUILD_DIR)
	$(LD) -Ttext=100 $(TASK_OBJS) -o $(BUILD_DIR)/$(TASK) $(LDFLAGS) -lsocket $(EWOK_LIBC)

clean:
	rm -f $(TASK_OBJS)
