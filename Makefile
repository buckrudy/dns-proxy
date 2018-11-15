
BINS := dns_proxy test

CC := gcc
LDFLAGS += -lpthread -lev -lcares

all: $(BINS)

#dns_proxy: dns_proxy.c list.h
#	$(CC) -o $@ $^ $(LDFLAGS)


clean:
	$(RM) $(BINS)

.PHONY: clean all
