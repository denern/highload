SRC := main.c
OUT := test

GLOBALFLAGS := -O2 -pthread

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
# Add flag to allow experimental API as l2fwd uses rte_ethdev_set_ptype API
CFLAGS += -DALLOW_EXPERIMENTAL_API
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -ljson-c
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -ljson-c

ifeq ($(MAKECMDGOALS),static)
# check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif

all: main
build:
	@mkdir -p $(BUILDDIR)
main: Makefile $(PC_FILE) | build
	$(CC) $(GLOBALFLAGS) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS) $(LDFLAGS_STATIC)
clean:
	rm -f test
#	$(MAKE) clean
.PHONY: main clean
