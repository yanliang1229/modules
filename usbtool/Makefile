LD_FLAGS := -pthread
CFLAGS += -g 

objects := core.o descriptor.o event.o io.o libusb.o linux_usbfs.o \
		   log.o sync.o threads_posix.o
all:libusb

libusb:$(objects) test/main.o
	$(CC)  $(LD_FLAGS)  $^  -o $@ 
test/main.o:
	make -C test
%.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< 

tags:
	ctags -R
cscope:
	cscope -Rbq

.PHONY : clean
clean:
	rm -f $(objects) libusb
	make -C test clean

