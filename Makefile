.PHONY: compile rel cover test dialyzer doc cppcheck clang-tidy
REBAR=./rebar3

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean

cover: test
	$(REBAR) cover

test: compile
	$(REBAR) as test do eunit

dialyzer:
	$(REBAR) dialyzer

xref:
	$(REBAR) xref

doc:
	$(REBAR) edoc

check: test dialyzer xref


compile_commands.json: c_src/Makefile
	$(MAKE) -C c_src clean
	bear $(MAKE) -C c_src

cppcheck: compile_commands.json
	cppcheck --enable=all --inconclusive --std=c99 --project=compile_commands.json --template=gcc

clang-tidy: compile_commands.json
	run-clang-tidy.py
