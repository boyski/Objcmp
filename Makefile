.PHONY: all clean dist zip

NAME		= objcmp
TARGETS		= $(NAME)
OBJCMP_OBJS	= objcmp.o zipfile.o
ALL_OBJS	= $(OBJCMP_OBJS)

CC = gcc
CFLAGS = -g -W -Wall
RM = rm -f

all: $(TARGETS)

clean:
	$(RM) $(TARGETS) $(ALL_OBJS) *.obj *.exe *.a

objcmp: $(OBJCMP_OBJS)
	$(CC) -o $@ $(CFLAGS) $(OBJCMP_OBJS)

dist: clean
	cd .. && gtar -czvf /tmp/$(NAME).tar.gz $(NAME)

zip: clean
	cd .. && zip -r /tmp/$(NAME).zip $(NAME)
