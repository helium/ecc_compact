# Based on c_src.mk from erlang.mk by Loic Hoguin <essen@ninenines.eu>

CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT ?= $(notdir $(BASEDIR))
PROJECT := $(strip $(PROJECT))

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~ts/erts-~ts/include/\", [code:root_dir(), erlang:system_info(version)]).")
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~ts\", [code:lib_dir(erl_interface, include)]).")
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -s init stop -eval "io:format(\"~ts\", [code:lib_dir(erl_interface, lib)]).")
ERL_BEAM_SMP ?= $(shell erl -noshell -s init stop -eval "io:format(\"~ts/beam.smp\", [os:getenv(\"BINDIR\")]).")

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT).so

# System type and C compiler/flags.

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
	CC ?= cc
	CPPFLAGS ?= -I$(shell brew --prefix openssl)/include
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDFLAGS ?= -bundle -bundle_loader $(ERL_BEAM_SMP) $(shell brew --prefix openssl)/lib/libcrypto.a
else ifeq ($(UNAME_SYS), FreeBSD)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDFLAGS += -shared
	LDLIBS += -lcrypto
else ifeq ($(UNAME_SYS), Linux)
	CC ?= gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDFLAGS += -shared
	LDLIBS += -lcrypto
endif

CFLAGS += -fPIC -I$(ERTS_INCLUDE_DIR) -I$(ERL_INTERFACE_INCLUDE_DIR) -Wextra
CXXFLAGS += -fPIC -I$(ERTS_INCLUDE_DIR) -I$(ERL_INTERFACE_INCLUDE_DIR)  -Wextra

# Verbosity.

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(?F);
cpp_verbose = $(cpp_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" -o -name "*.C" -o -name "*.cc" -o -name "*.cpp" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

$(C_SRC_OUTPUT): $(OBJECTS)
	@mkdir -p $(BASEDIR)/priv/
	$(link_verbose) $(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(C_SRC_OUTPUT)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:
	@rm -f $(C_SRC_OUTPUT) $(OBJECTS)

%.compdb_entry: %.c
	@echo "    {" > $@
	@echo "        \"command\": \"cc  $(CFLAGS) $(CPPFLAGS) -c $<\","   >> $@
	@echo "        \"directory\": \"$(CURDIR)\","               >> $@
	@echo "        \"file\": \"$<\""                    >> $@
	@echo "    },"                              >> $@

COMPDB_ENTRIES = $(addsuffix .compdb_entry, $(basename $(SOURCES)))

compile_commands.json: $(COMPDB_ENTRIES)
	@echo "[" > $@.tmp
	@cat $^ >> $@.tmp
	@sed '$$d' < $@.tmp > $@
	@echo "    }" >> $@
	@echo "]" >> $@
	@rm $@.tmp

clang-tidy: compile_commands.json
	run-clang-tidy.py

cppcheck: compile_commands.json
	cppcheck --enable=all --inconclusive --std=c99 -I$(ERTS_INCLUDE_DIR) -I$(ERL_INTERFACE_INCLUDE_DIR) --project=$(CURDIR)/compile_commands.json --template=gcc --check-config -v -DHAVE_CONFIG=0
