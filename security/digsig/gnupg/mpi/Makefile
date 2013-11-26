all: generic obj lib 

CFLAGS= -g -DHAVE_CONFIG_H

INCLUDS= -I.

%.o: %.c 
	gcc $(INCLUDS) $(CFLAGS) -c $< -o $@

OBJ= mpi-add.o mpi-bit.o mpi-cmp.o mpi-div.o mpi-gcd.o mpih-cmp.o mpih-div.o mpih-mul.o mpi-inline.o mpi-inv.o mpi-mpow.o mpi-mul.o mpi-pow.o mpi-scan.o mpiutil.o mpicoder.o 

generic:
	make -C generic all

obj: $(OBJ) 

lib: $(OBJ)
	ar cru libMPI.a $(OBJ) generic/*.o
clean: 
	rm generic/*.o *.o *.a 
