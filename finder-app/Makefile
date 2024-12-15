.PHONY: clean

CC := $(CROSS_COMPILE)$(CC)

build: writer.c
	@$(CC) writer.c -o writer

clean:
	@rm -rf writer
