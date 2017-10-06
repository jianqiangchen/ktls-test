CFLAGS += -Wall -g -D_GNU_SOURCE
LDFLAGS += -lssl -lpthread -lcrypto

TESTS = epoll_server epoll_client

all: $(TESTS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $^  $(LDFLAGS)
%: %.cpp
	$(CC) $(CFLAGS) -o $@ $^  $(LDFLAGS)

clean:
	$(RM) $(TESTS)
