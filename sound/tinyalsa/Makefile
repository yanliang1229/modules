CFLAGS = -c -fPIC -Wall -g
INC = include
CROSS_COMPILE =

all: tinyplay tinycap tinymix

tinyplay: mixer.o pcm.o tinyplay.o
	$(CROSS_COMPILE)gcc mixer.o pcm.o tinyplay.o  -o tinyplay

tinycap: mixer.o pcm.o tinycap.o
	$(CROSS_COMPILE)gcc mixer.o pcm.o tinycap.o  -o tinycap

tinymix: mixer.o pcm.o tinymix.o
	$(CROSS_COMPILE)gcc mixer.o pcm.o tinymix.o  -o tinymix

.c.o:
	$(CROSS_COMPILE)gcc $(CFLAGS) $< -I$(INC)

tags:
	ctags -R .
cscope:
	cscope -Rbq

clean:
	-rm -rf *.o tinyplay tinycap \
		tinymix tags cscope.*
