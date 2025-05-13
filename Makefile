SRC_DIR   := src
OUT_DIR   := build
TEST_COMMON_DIR := tests
TEST_CASES_DIR  := tests/cases

BIN_NAME := resolve
BIN_PATH := $(OUT_DIR)/$(BIN_NAME)

CC      := gcc
CFLAGS  := -O2 -std=c99 -Wall -Wextra -pedantic -I $(SRC_DIR) -MMD -MP
LDFLAGS :=
DEBUG_CFLAGS := -g3 -fsanitize=address,leak,undefined

ifeq ($(DEBUG), 1)
	CFLAGS += $(DEBUG_CFLAGS)
endif

OBJ_DIR  := $(OUT_DIR)/$(SRC_DIR)
BIN_SRCS := $(shell find $(SRC_DIR) -type f -name '*.c')
BIN_OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(BIN_SRCS))
BIN_DEPS := $(patsubst %.o, %.d, $(BIN_OBJS))

TEST_COMMON_OBJ_DIR := $(OUT_DIR)/$(TEST_COMMON_DIR)
TEST_COMMON_SRCS    := $(TEST_COMMON_DIR)/common.c $(filter-out %main.c,$(BIN_SRCS))
TEST_COMMON_OBJS    := $(patsubst %.c, $(TEST_COMMON_OBJ_DIR)/%.o, $(TEST_COMMON_SRCS))
TEST_COMMON_DEPS    := $(patsubst %.o, %.d, $(TEST_COMMON_OBJS))
TEST_CASES_OUT_DIR  := $(OUT_DIR)/$(TEST_CASES_DIR)
TEST_CASES_SRCS     := $(shell find $(TEST_CASES_DIR) -type f -name '*.c')
TEST_CASES          := $(patsubst $(TEST_CASES_DIR)/%.c, $(TEST_CASES_OUT_DIR)/%, $(TEST_CASES_SRCS))
TEST_CASES_DEPS     := $(addsuffix .d, $(TEST_CASES))

.PHONY: all build test clean
all: build

clean:
	rm -rf $(OUT_DIR)

build: $(BIN_PATH)

$(BIN_PATH): $(BIN_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $<

test: $(TEST_CASES)
	@./tests/test.sh

$(TEST_CASES_OUT_DIR)/%: $(TEST_CASES_OUT_DIR)/%.o $(TEST_COMMON_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -I $(TEST_COMMON_DIR) -o $@ $^

$(TEST_CASES_OUT_DIR)/%.o: $(TEST_CASES_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -I $(TEST_COMMON_DIR) -o $@ -c $<

$(TEST_COMMON_OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) -o $@ -c $<

-include $(BIN_DEPS) $(TEST_COMMON_DEPS) $(TEST_CASES_DEPS)
