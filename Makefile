BIN_DIR := src/cli
LIB_DIR := src/lib
OUT_DIR := build

TEST_COMMON_DIR := tests/common
TEST_MOCK_DIR   := tests/mock
BIND_CASES_DIR  := tests/cases/bind
MOCK_CASES_DIR  := tests/cases/mock

BIN_NAME := resolve
BIN_PATH := $(OUT_DIR)/$(BIN_NAME)

CC      := gcc
CFLAGS  := -O2 -std=c99 -Wall -Wextra -pedantic -I $(LIB_DIR) -MMD -MP
LDFLAGS :=
DEBUG_CFLAGS := -g3 -fsanitize=address,leak

ifeq ($(DEBUG), 1)
	CFLAGS += $(DEBUG_CFLAGS)
endif

BIN_SRCS := $(shell find $(BIN_DIR) -type f -name '*.c')
BIN_OBJS := $(patsubst %.c, $(OUT_DIR)/%.o, $(BIN_SRCS))
BIN_DEPS := $(patsubst %.o, %.d, $(BIN_OBJS))

LIB_SRCS := $(shell find $(LIB_DIR) -type f -name '*.c')
LIB_OBJS := $(patsubst %.c, $(OUT_DIR)/%.o, $(LIB_SRCS))
LIB_DEPS := $(patsubst %.o, %.d, $(LIB_OBJS))

TEST_COMMON_OBJ_DIR := $(OUT_DIR)/$(TEST_COMMON_DIR)
TEST_COMMON_SRCS    := $(shell find $(TEST_COMMON_DIR) -type f -name '*.c') $(LIB_SRCS)
TEST_COMMON_OBJS    := $(patsubst %.c, $(TEST_COMMON_OBJ_DIR)/%.o, $(TEST_COMMON_SRCS))
TEST_COMMON_DEPS    := $(patsubst %.o, %.d, $(TEST_COMMON_OBJS))

TEST_MOCK_OBJ_DIR := $(OUT_DIR)/$(TEST_MOCK_DIR)
TEST_MOCK_SRCS    := $(shell find $(TEST_MOCK_DIR) -type f -name '*.c')
TEST_MOCK_OBJS    := $(patsubst %.c, $(TEST_MOCK_OBJ_DIR)/%.o, $(TEST_MOCK_SRCS))
TEST_MOCK_DEPS    := $(patsubst %.o, %.d, $(TEST_MOCK_OBJS))

BIND_CASES_OUT_DIR  := $(OUT_DIR)/$(BIND_CASES_DIR)
BIND_CASES_SRCS     := $(shell find $(BIND_CASES_DIR) -type f -name '*.c')
BIND_CASES          := $(patsubst $(BIND_CASES_DIR)/%.c, $(BIND_CASES_OUT_DIR)/%, $(BIND_CASES_SRCS))
BIND_CASES_DEPS     := $(addsuffix .d, $(BIND_CASES))

MOCK_CASES_OUT_DIR  := $(OUT_DIR)/$(MOCK_CASES_DIR)
MOCK_CASES_SRCS     := $(shell find $(MOCK_CASES_DIR) -type f -name '*.c')
MOCK_CASES          := $(patsubst $(MOCK_CASES_DIR)/%.c, $(MOCK_CASES_OUT_DIR)/%, $(MOCK_CASES_SRCS))
MOCK_CASES_DEPS     := $(addsuffix .d, $(MOCK_CASES))

.PHONY: all build test clean
all: build

clean:
	rm -rf $(OUT_DIR)

build: $(BIN_PATH)

$(BIN_PATH): $(BIN_OBJS) $(LIB_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OUT_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $<

test: $(BIND_CASES) $(MOCK_CASES)
	@./tests/test.sh

$(BIND_CASES_OUT_DIR)/%: $(BIND_CASES_OUT_DIR)/%.o $(TEST_COMMON_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -o $@ $^

$(BIND_CASES_OUT_DIR)/%.o: $(BIND_CASES_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -I $(TEST_COMMON_DIR) -o $@ -c $<

$(TEST_COMMON_OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -o $@ -c $<

$(MOCK_CASES_OUT_DIR)/%: $(MOCK_CASES_OUT_DIR)/%.o $(TEST_COMMON_OBJS) $(TEST_MOCK_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -o $@ $^

$(MOCK_CASES_OUT_DIR)/%.o: $(MOCK_CASES_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -I $(TEST_COMMON_DIR) -o $@ -c $<

$(TEST_MOCK_OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -I $(TEST_COMMON_DIR) -o $@ -c $<

-include $(BIN_DEPS) $(LIB_DEPS) $(TEST_COMMON_DEPS) $(TEST_MOCK_DEPS) $(BIND_CASES_DEPS) $(MOCK_CASES_DEPS)
