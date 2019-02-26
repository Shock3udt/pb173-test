LDFLAGS+= -L ./library/ -lmylog -lmbedtls
CPPFLAGS+= -I ./include/
CXXFLAGS+= -std=c++17 -Wall -Wextra

all: main test_main

test: main test_main
    ./test_main

test_main: test_main.o library/libmylog.a library/libmbedtls.a
    $(CXX) $< $(LDFLAGS) -o $@

main: main.o library/libmylog.a library/libmbedtls.a
	$(CXX) $< $(LDFLAGS) -o $@

library/libmylog.a:
	cd ./library/ && $(MAKE) libmylog.a

library/libmbedtls.a:
	cd ./library/ && $(MAKE) libmbedtls.a

.PHONY: all clean

clean:
	$(RM) main.o pb173hw 
	cd ./library/ && $(MAKE) clean
