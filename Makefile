# bhttp: bserve and bcurl.
#
#   make          release build: ./bserve and ./bcurl
#   make debug    ASan + UBSan build in build/debug/
#   make test     unit tests + conformance tests against the debug build
#   make clean

CC      ?= cc
PYTHON  ?= python3

WARNINGS = -Wall -Wextra -Werror -Wpedantic -Wshadow -Wconversion -Wformat=2 \
           -Wstrict-prototypes -Wmissing-prototypes -Wvla
BASE     = -std=c11 -D_XOPEN_SOURCE=700 $(WARNINGS)
RELEASE  = $(BASE) -O2
DEBUG    = $(BASE) -O1 -g -fno-omit-frame-pointer \
           -fsanitize=address,undefined -fno-sanitize-recover=all
SANITIZE = -fsanitize=address,undefined

COMMON   = bhttp netio dump
REL_DIR  = build/release
DBG_DIR  = build/debug

REL_COMMON = $(COMMON:%=$(REL_DIR)/%.o)
DBG_COMMON = $(COMMON:%=$(DBG_DIR)/%.o)

.PHONY: all debug test clean

all: bserve bcurl

bserve: $(REL_DIR)/bserve.o $(REL_COMMON)
	$(CC) $(RELEASE) -o $@ $^

bcurl: $(REL_DIR)/bcurl.o $(REL_COMMON)
	$(CC) $(RELEASE) -o $@ $^

$(REL_DIR)/%.o: src/%.c | $(REL_DIR)
	$(CC) $(RELEASE) -MMD -MP -c $< -o $@

debug: $(DBG_DIR)/bserve $(DBG_DIR)/bcurl $(DBG_DIR)/unit_test

$(DBG_DIR)/bserve: $(DBG_DIR)/bserve.o $(DBG_COMMON)
	$(CC) $(DEBUG) $(SANITIZE) -o $@ $^

$(DBG_DIR)/bcurl: $(DBG_DIR)/bcurl.o $(DBG_COMMON)
	$(CC) $(DEBUG) $(SANITIZE) -o $@ $^

$(DBG_DIR)/unit_test: $(DBG_DIR)/unit_test.o $(DBG_COMMON)
	$(CC) $(DEBUG) $(SANITIZE) -o $@ $^

$(DBG_DIR)/unit_test.o: tests/unit_test.c | $(DBG_DIR)
	$(CC) $(DEBUG) -Isrc -MMD -MP -c $< -o $@

$(DBG_DIR)/%.o: src/%.c | $(DBG_DIR)
	$(CC) $(DEBUG) -MMD -MP -c $< -o $@

$(REL_DIR) $(DBG_DIR):
	mkdir -p $@

test: debug
	$(DBG_DIR)/unit_test
	BSERVE=$(DBG_DIR)/bserve BCURL=$(DBG_DIR)/bcurl $(PYTHON) tests/run_tests.py

clean:
	rm -rf build bserve bcurl

-include $(wildcard $(REL_DIR)/*.d $(DBG_DIR)/*.d)
