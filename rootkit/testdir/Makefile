CC = gcc
CFLAGS = -Wall

TARGET = ./ioctl

all: $(TARGET)

$(TARGET): ioctl.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
