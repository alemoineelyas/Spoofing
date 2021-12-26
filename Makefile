# WARNING : this is the classic prototype of a simple makefile.
# It can be reused for other projects with several files
# here, there are only 2 files so you can compile it using
# gcc -o spoof spoof.c
# you can of course add any flag you want.

CC 				= gcc
OBJS 			= spoof.o
TARGET 			= spoof
REBUILDABLES	= $(OBJS) $(TARGET)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -g -Wall -o $@ $^

%.o: %.c
	$(CC) -g -c -Wall -o $@ $<

spoof.o: spoof.h

clean:
	rm $(REBUILDABLES)