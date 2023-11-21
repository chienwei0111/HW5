CC = gcc
CFLAGS = -Wall -g 
TARGET = ipscanner
SRCS = main.c debug.c fill_packet.c pcap.c 
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) -lpcap


clean:
	rm -f $(TARGET) $(OBJS)

