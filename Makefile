obj-m := digsig_verif.o
digsig_verif-objs := ./dsi_sig_verify.o ./dsi_extract_mpi.o ./digsig.o ./gnupg/mpi/generic/mpih-lshift.o \
	./gnupg/mpi/generic/mpih-mul1.o ./gnupg/mpi/generic/mpih-mul2.o \
	./gnupg/mpi/generic/mpih-mul3.o ./gnupg/mpi/generic/mpih-rshift.o \
	./gnupg/mpi/generic/mpih-sub1.o ./gnupg/mpi/generic/udiv-w-sdiv.o \
	./gnupg/mpi/generic/mpih-add1.o ./gnupg/mpi/mpicoder.o ./gnupg/mpi/mpi-add.o \
	./gnupg/mpi/mpi-bit.o ./gnupg/mpi/mpi-div.o ./gnupg/mpi/mpi-cmp.o ./gnupg/mpi/mpi-gcd.o \
	./gnupg/mpi/mpih-cmp.o ./gnupg/mpi/mpih-div.o ./gnupg/mpi/mpih-mul.o ./gnupg/mpi/mpi-inline.o \
	./gnupg/mpi/mpi-inv.o ./gnupg/mpi/mpi-mpow.o ./gnupg/mpi/mpi-mul.o ./gnupg/mpi/mpi-pow.o \
	./gnupg/mpi/mpi-scan.o ./gnupg/mpi/mpiutil.o ./gnupg/cipher/rsa-verify.o

clean:
	@find . \
	\( -name '*.[oas]' -o -name '*.ko' -o -name '.*.cmd' \
	-o -name '.*.d' -o -name '.*.tmp' -o -name '*.mod.c' \) \
	-type f -print | xargs rm -f

tags:
	rm -f TAGS
	@find . | xargs etags -a

EXTRA_CFLAGS += -DDSI_DEBUG -DDSI_DIGSIG_DEBUG 
