SRC_DIR      := src
OUT_DIR      := build
EXTERNAL_DIR := external

TEST_COMMON_DIR := tests/common
TEST_MOCK_DIR   := tests/mock
BIND_CASES_DIR  := tests/cases/bind
MOCK_CASES_DIR  := tests/cases/mock

BIN_NAME := resolve
BIN_PATH := $(OUT_DIR)/$(BIN_NAME)

CC      := clang++
CFLAGS  := -O2 -std=c++23 -Wall -Wextra -pedantic -I $(SRC_DIR) -MMD -MP
LDFLAGS := $(shell pkg-config --libs openssl)
DEBUG_CFLAGS := -g3 -fsanitize=address,leak,undefined

ifeq ($(DEBUG), 1)
	CFLAGS += $(DEBUG_CFLAGS)
endif

BIN_SRCS := $(shell find $(SRC_DIR) -type f -name '*.cc')
BIN_OBJS := $(patsubst %.cc, $(OUT_DIR)/%.o, $(BIN_SRCS))
BIN_DEPS := $(patsubst %.o, %.d, $(BIN_OBJS))

TEST_COMMON_SRCS    := $(shell find $(TEST_COMMON_DIR) -type f -name '*.cc') $(filter-out $(SRC_DIR)/main.cc, $(BIN_SRCS))
BIND_COMMON_OBJ_DIR := $(OUT_DIR)/$(TEST_COMMON_DIR)/bind
BIND_COMMON_OBJS    := $(patsubst %.cc, $(BIND_COMMON_OBJ_DIR)/%.o, $(TEST_COMMON_SRCS))
BIND_COMMON_DEPS    := $(patsubst %.o, %.d, $(BIND_COMMON_OBJS))
MOCK_COMMON_OBJ_DIR := $(OUT_DIR)/$(TEST_COMMON_DIR)/mock
MOCK_COMMON_OBJS    := $(patsubst %.cc, $(MOCK_COMMON_OBJ_DIR)/%.o, $(TEST_COMMON_SRCS))
MOCK_COMMON_DEPS    := $(patsubst %.o, %.d, $(MOCK_COMMON_OBJS))

TEST_MOCK_OBJ_DIR := $(OUT_DIR)/$(TEST_MOCK_DIR)
TEST_MOCK_SRCS    := $(shell find $(TEST_MOCK_DIR) -type f -name '*.cc')
TEST_MOCK_OBJS    := $(patsubst %.cc, $(TEST_MOCK_OBJ_DIR)/%.o, $(TEST_MOCK_SRCS))
TEST_MOCK_DEPS    := $(patsubst %.o, %.d, $(TEST_MOCK_OBJS))

BIND_CASES_OUT_DIR  := $(OUT_DIR)/$(BIND_CASES_DIR)
BIND_CASES_SRCS     := $(shell find $(BIND_CASES_DIR) -type f -name '*.cc')
BIND_CASES          := $(patsubst $(BIND_CASES_DIR)/%.cc, $(BIND_CASES_OUT_DIR)/%, $(BIND_CASES_SRCS))
BIND_CASES_DEPS     := $(addsuffix .d, $(BIND_CASES))

MOCK_CASES_OUT_DIR  := $(OUT_DIR)/$(MOCK_CASES_DIR)
MOCK_CASES_SRCS     := $(shell find $(MOCK_CASES_DIR) -type f -name '*.cc')
MOCK_CASES          := $(patsubst $(MOCK_CASES_DIR)/%.cc, $(MOCK_CASES_OUT_DIR)/%, $(MOCK_CASES_SRCS))
MOCK_CASES_DEPS     := $(addsuffix .d, $(MOCK_CASES))

.PHONY: all clean build test
all: build

clean:
	rm -rf $(OUT_DIR)

build: $(BIN_PATH)

$(BIN_PATH): $(BIN_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OUT_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I $(EXTERNAL_DIR)/cxxopts -o $@ -c $<

test: $(BIND_CASES) $(MOCK_CASES)
	@./tests/test.sh

$(BIND_CASES_OUT_DIR)/%: $(BIND_CASES_OUT_DIR)/%.o $(BIND_COMMON_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIND_CASES_OUT_DIR)/%.o: $(BIND_CASES_DIR)/%.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -I $(TEST_COMMON_DIR) -o $@ -c $<

$(BIND_COMMON_OBJ_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -o $@ -c $<

$(MOCK_CASES_OUT_DIR)/%: $(MOCK_CASES_OUT_DIR)/%.o $(TEST_MOCK_OBJS) $(MOCK_COMMON_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(MOCK_CASES_OUT_DIR)/%.o: $(MOCK_CASES_DIR)/%.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I $(TEST_COMMON_DIR) -I $(TEST_MOCK_DIR) -o $@ -c $<

$(MOCK_COMMON_OBJ_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $<

$(TEST_MOCK_OBJ_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I $(TEST_COMMON_DIR) -o $@ -c $<

-include $(BIN_DEPS) $(BIND_COMMON_DEPS) $(MOCK_COMMON_DEPS) $(TEST_MOCK_DEPS) $(BIND_CASES_DEPS) $(MOCK_CASES_DEPS)
