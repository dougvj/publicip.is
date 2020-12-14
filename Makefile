CFLAGS=-Wall -Werror -std=gnu11 -lpthread

release: CFLAGS+=-O3
release: publicip.is

debug: CFLAGS+=-g
debug: publicip.is

publicip.is: publicip.is.c
	gcc $(CFLAGS) publicip.is.c -o publicip.is

clean:
	-rm publicip.is
