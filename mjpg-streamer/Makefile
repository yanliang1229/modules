objects := $(patsubst %.c, %.o, $(wildcard *.c)) 
# set the compiler to use
CC = arm-fsl-linux-gnueabi-gcc 

CFLAGS += -O2 -DLINUX -D_GNU_SOURCE -Wall -fPIC  -I/usr/local/src/out_jpeg/include

LDFLAGS += -lpthread


all: mjpg_streamer

ifeq ($(USE_LIBV4L2),true)
LDFLAGS += -lv4l2
CFLAGS += -DUSE_LIBV4L2

endif
LDFLAGS += -ljpeg
LDFLAGS += -static

mjpg_streamer:$(objects)
	$(CC)  -o mjpg_streamer $(objects) $(CFLAGS) $(LDFLAGS) -L /usr/local/src/out_jpeg/lib

clean:
	rm -rf *.o mjpg_streamer tags cscope.*
