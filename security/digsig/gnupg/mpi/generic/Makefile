all: obj 

CFLAGS= -DHAVE_CONFIG_H

INCLUDS= -I. -I.. -I../../include

%.o: %.c 
	gcc $(INCLUDS) $(CFLAGS) -c $< -o $@

OBJ= mpih-add1.o mpih-lshift.o mpih-mul1.o mpih-mul2.o mpih-mul3.o mpih-rshift.o mpih-sub1.o udiv-w-sdiv.o 

obj: $(OBJ) 

clean: 
	rm *.o *.a 
