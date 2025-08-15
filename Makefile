prefix      := /usr/local
exec_prefix := $(prefix)
bindir      := $(exec_prefix)/bin

SRC_DIR      := src
OUT_DIR      := build
EXTERNAL_DIR := external

TEST_COMMON_DIR := tests/common
TEST_MOCK_DIR   := tests/mock
BIND_CASES_DIR  := tests/cases/bind
MOCK_CASES_DIR  := tests/cases/mock

BIN_NAME := resolve
BIN_PATH := $(OUT_DIR)/$(BIN_NAME)
BIN_INSTALL_PATH := $(DESTDIR)$(bindir)/$(BIN_NAME)

CPPFLAGS := -I $(SRC_DIR)
CXXFLAGS := -std=c++23 -Wall -Wextra -pedantic -MMD -MP -O2
DEBUG_CXXFLAGS := -g3 -fsanitize=address,leak,undefined

LIBRARIES := "openssl >= 3.0"
CPPFLAGS  += $(shell pkg-config --cflags-only-I $(LIBRARIES))
CXXFLAGS  += $(shell pkg-config --cflags-only-other $(LIBRARIES))
LDFLAGS   += $(shell pkg-config --libs-only-L $(LIBRARIES))
LDLIBS    += $(shell pkg-config --libs-only-l $(LIBRARIES))

BIN_CXXFLAGS  := $(CXXFLAGS)
BIN_CPPFLAGS  := $(CPPFLAGS) -I $(EXTERNAL_DIR)/cxxopts
BIND_CXXFLAGS := $(CXXFLAGS) $(DEBUG_CXXFLAGS)
BIND_CPPFLAGS := $(CPPFLAGS) -I $(TEST_COMMON_DIR)
# Mock tests must not include debug flags because they contain `-fsanitize` which prevents the mock functions from being used.
MOCK_CXXFLAGS := $(CXXFLAGS)
MOCK_CPPFLAGS := $(CPPFLAGS) -I $(TEST_COMMON_DIR) -I $(TEST_MOCK_DIR)

ifeq ($(DEBUG), 1)
	BIN_CXXFLAGS += $(DEBUG_CXXFLAGS)
endif

BIN_SRCS := $(wildcard $(SRC_DIR)/*.cc)
BIN_OBJS := $(patsubst %.cc, $(OUT_DIR)/%.o, $(BIN_SRCS))
BIN_DEPS := $(BIN_OBJS:.o=.d)

TEST_COMMON_SRCS    := $(filter-out $(SRC_DIR)/main.cc, $(BIN_SRCS))
BIND_COMMON_OBJ_DIR := $(OUT_DIR)/tests/common/bind
BIND_COMMON_OBJS    := $(patsubst $(SRC_DIR)/%.cc, $(BIND_COMMON_OBJ_DIR)/%.o, $(TEST_COMMON_SRCS))
BIND_COMMON_DEPS    := $(BIND_COMMON_OBJS:.o=.d)
MOCK_COMMON_OBJ_DIR := $(OUT_DIR)/tests/common/mock
MOCK_COMMON_OBJS    := $(patsubst $(SRC_DIR)/%.cc, $(MOCK_COMMON_OBJ_DIR)/%.o, $(TEST_COMMON_SRCS))
MOCK_COMMON_DEPS    := $(MOCK_COMMON_OBJS:.o=.d)

TEST_MOCK_OBJ_DIR   := $(OUT_DIR)/tests/mock
TEST_MOCK_SRCS      := $(wildcard $(TEST_MOCK_DIR)/*.cc)
TEST_MOCK_OBJS      := $(patsubst $(TEST_MOCK_DIR)/%.cc, $(TEST_MOCK_OBJ_DIR)/%.o, $(TEST_MOCK_SRCS))
TEST_MOCK_DEPS      := $(TEST_MOCK_OBJS:.o=.d)

BIND_CASES_OUT_DIR  := $(OUT_DIR)/tests/cases/bind
BIND_CASES_SRCS     := $(wildcard $(BIND_CASES_DIR)/*.cc)
BIND_CASES          := $(patsubst $(BIND_CASES_DIR)/%.cc, $(BIND_CASES_OUT_DIR)/%, $(BIND_CASES_SRCS))
BIND_CASES_DEPS     := $(addsuffix .d, $(BIND_CASES))

MOCK_CASES_OUT_DIR  := $(OUT_DIR)/tests/cases/mock
MOCK_CASES_SRCS     := $(wildcard $(MOCK_CASES_DIR)/*.cc)
MOCK_CASES          := $(patsubst $(MOCK_CASES_DIR)/%.cc, $(MOCK_CASES_OUT_DIR)/%, $(MOCK_CASES_SRCS))
MOCK_CASES_DEPS     := $(addsuffix .d, $(MOCK_CASES))

.PHONY: all test clean install uninstall
all: $(BIN_PATH)

test: $(BIND_CASES) $(MOCK_CASES)
	@./tests/test.sh

clean:
	rm -rf $(OUT_DIR)

install:
	install -D -m755 $(BIN_PATH) $(BIN_INSTALL_PATH)

uninstall:
	rm $(BIN_INSTALL_PATH)

$(BIN_PATH): $(BIN_OBJS)
	@mkdir -p $(@D)
	$(CXX) $(BIN_CXXFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(OUT_DIR)/%.o: %.cc
	@mkdir -p $(@D)
	$(CXX) $(BIN_CPPFLAGS) $(BIN_CXXFLAGS) -c $< -o $@

$(BIND_COMMON_OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	@mkdir -p $(@D)
	$(CXX) $(BIND_CPPFLAGS) $(BIND_CXXFLAGS) -c $< -o $@

$(BIND_CASES_OUT_DIR)/%: $(BIND_CASES_DIR)/%.cc $(BIND_COMMON_OBJS)
	@mkdir -p $(@D)
	$(CXX) $(BIND_CPPFLAGS) $(BIND_CXXFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(MOCK_COMMON_OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	@mkdir -p $(@D)
	$(CXX) $(MOCK_CPPFLAGS) $(MOCK_CXXFLAGS) -c $< -o $@

$(TEST_MOCK_OBJ_DIR)/%.o: $(TEST_MOCK_DIR)/%.cc
	@mkdir -p $(@D)
	$(CXX) $(MOCK_CPPFLAGS) $(MOCK_CXXFLAGS) -c $< -o $@

$(MOCK_CASES_OUT_DIR)/%: $(MOCK_CASES_DIR)/%.cc $(TEST_MOCK_OBJS) $(MOCK_COMMON_OBJS)
	@mkdir -p $(@D)
	$(CXX) $(MOCK_CPPFLAGS) $(MOCK_CXXFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

-include $(BIN_DEPS) $(BIND_COMMON_DEPS) $(MOCK_COMMON_DEPS) $(TEST_MOCK_DEPS) $(BIND_CASES_DEPS) $(MOCK_CASES_DEPS)
