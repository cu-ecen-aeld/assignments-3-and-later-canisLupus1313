.PHONY: clean

CC := $(CROSS_COMPILE)$(CC)

USE_AESD_CHAR_DEVICE ?= 1

all: main.c
	$(CC) main2.c -g -o aesdsocket -DUSE_AESD_CHAR=$(USE_AESD_CHAR_DEVICE)

clean:
	@rm -rf aesdsocket
