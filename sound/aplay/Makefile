objects := $(patsubst %.c, %.o, $(wildcard *.c)) 

CC= arm-fsl-linux-gnueabi-gcc

LDFLAGS += -L/home/yanl1229/source/alsa-lib-1.1.2/output/lib -lasound
CFLAGS += -g -I/home/yanl1229/source/alsa-lib-1.1.2/output/include -I./include

all: aplay 

hwlib:$(objects)
	$(CC) -o aplay $(objects) $(CFLAGS) $(LDFLAGS) 

tags:
	ctags -R

cscope:
	cscope -Rbq

.PHONY: clean
clean:
	rm -rf $(objects) aplay 
