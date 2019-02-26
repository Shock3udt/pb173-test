CXXFLAGS = -I ../include


all: libmbedtls.a libmylog.a

%.o: %.c
	$(CC) -c -fPIC -o $@ $<

libmbedtls.a: aes.o aesni.o platform.o platform_util.o ctr_drbg.o entropy.o entropy_poll.o sha512.o timing.o
	ar rvs $@ $^
libmylog.o: mylog.c
	$(CC) -c -I ../include -fPIC $< -o $@
libmylog.a: libmylog.o
	ar rvs $@ $^

.PHONY: all clean

clean:
	$(RM) libmylog.o libmylog.a libmbedtls.a *.o
