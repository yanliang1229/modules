INCLUDE := -I../
CFLAGS += -g 

source := $(notdir $(shell find . -name '*.c'))
objects := $(patsubst %.c,%.o,$(source))

all:main.o

main.o: $(objects)
	$(LD) -r  -o $@ $^

%.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< 

.PHONY : clean
clean:
	rm -f $(objects) main.o

