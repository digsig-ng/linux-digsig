digsig-ltm =

obj-m := digsig_verif.o
digsig_verif-objs := digsig.o dsi_sysfs.o digsig_cache.o digsig_revocation.o

ifdef digsig-ltm
digsig_verif-objs += dsi_sig_verify_ltm.o dsi_pkcs1.o dsi_ltm_rsa.o \
	ltm/bncore.o ltm/bn_mp_init.o ltm/bn_mp_clear.o ltm/bn_mp_exch.o ltm/bn_mp_grow.o \
	ltm/bn_mp_shrink.o \
	ltm/bn_mp_clamp.o ltm/bn_mp_zero.o  ltm/bn_mp_set.o \
	ltm/bn_mp_set_int.o ltm/bn_mp_init_size.o ltm/bn_mp_copy.o \
	ltm/bn_mp_init_copy.o ltm/bn_mp_abs.o ltm/bn_mp_neg.o ltm/bn_mp_cmp_mag.o \
	ltm/bn_mp_cmp.o ltm/bn_mp_cmp_d.o \
	ltm/bn_mp_rshd.o ltm/bn_mp_lshd.o ltm/bn_mp_mod_2d.o ltm/bn_mp_div_2d.o \
	ltm/bn_mp_mul_2d.o ltm/bn_mp_div_2.o \
	ltm/bn_mp_mul_2.o ltm/bn_s_mp_add.o ltm/bn_s_mp_sub.o ltm/bn_fast_s_mp_mul_digs.o \
	ltm/bn_s_mp_mul_digs.o \
	ltm/bn_fast_s_mp_mul_high_digs.o ltm/bn_s_mp_mul_high_digs.o \
	ltm/bn_fast_s_mp_sqr.o ltm/bn_s_mp_sqr.o \
	ltm/bn_mp_add.o ltm/bn_mp_sub.o ltm/bn_mp_karatsuba_mul.o \
	ltm/bn_mp_mul.o ltm/bn_mp_karatsuba_sqr.o \
	ltm/bn_mp_sqr.o ltm/bn_mp_div.o ltm/bn_mp_mod.o ltm/bn_mp_add_d.o \
	ltm/bn_mp_sub_d.o ltm/bn_mp_mul_d.o \
	ltm/bn_mp_div_d.o ltm/bn_mp_mod_d.o ltm/bn_mp_expt_d.o ltm/bn_mp_addmod.o \
	ltm/bn_mp_submod.o \
	ltm/bn_mp_mulmod.o ltm/bn_mp_sqrmod.o ltm/bn_mp_gcd.o ltm/bn_mp_lcm.o \
	ltm/bn_fast_mp_invmod.o ltm/bn_mp_invmod.o \
	ltm/bn_mp_reduce.o ltm/bn_mp_montgomery_setup.o ltm/bn_fast_mp_montgomery_reduce.o \
	ltm/bn_mp_montgomery_reduce.o \
	ltm/bn_mp_exptmod_fast.o ltm/bn_mp_exptmod.o ltm/bn_mp_2expt.o ltm/bn_mp_n_root.o \
	ltm/bn_mp_jacobi.o ltm/bn_reverse.o \
	ltm/bn_mp_count_bits.o ltm/bn_mp_read_unsigned_bin.o ltm/bn_mp_read_signed_bin.o \
	ltm/bn_mp_to_unsigned_bin.o \
	ltm/bn_mp_to_signed_bin.o ltm/bn_mp_unsigned_bin_size.o ltm/bn_mp_signed_bin_size.o  \
	ltm/bn_mp_xor.o ltm/bn_mp_and.o ltm/bn_mp_or.o \
	ltm/bn_mp_montgomery_calc_normalization.o \
	ltm/bn_mp_dr_is_modulus.o ltm/bn_mp_dr_setup.o ltm/bn_mp_reduce_setup.o \
	ltm/bn_mp_toom_mul.o ltm/bn_mp_toom_sqr.o ltm/bn_mp_div_3.o ltm/bn_s_mp_exptmod.o \
	ltm/bn_mp_reduce_2k.o ltm/bn_mp_reduce_is_2k.o ltm/bn_mp_reduce_2k_setup.o \
	ltm/bn_mp_cnt_lsb.o ltm/bn_error.o \
	ltm/bn_mp_init_multi.o ltm/bn_mp_clear_multi.o ltm/bn_mp_dr_reduce.o \
	ltm/bn_mp_toradix.o ltm/bn_mp_radix_smap.o
EXTRA_CFLAGS += -DDSI_DEBUG -DDSI_DIGSIG_DEBUG -DDIGSIG_LOG -DDIGSIG_LTM -DDSI_REVOCATION -I $(obj)/ltm -I $(obj)
else
digsig_verif-objs += dsi_sig_verify.o ./gnupg/mpi/generic/mpih-lshift.o \
	./gnupg/mpi/generic/mpih-mul1.o ./gnupg/mpi/generic/mpih-mul2.o \
	./gnupg/mpi/generic/mpih-mul3.o ./gnupg/mpi/generic/mpih-rshift.o \
	./gnupg/mpi/generic/mpih-sub1.o ./gnupg/mpi/generic/udiv-w-sdiv.o \
	./gnupg/mpi/generic/mpih-add1.o ./gnupg/mpi/mpicoder.o ./gnupg/mpi/mpi-add.o \
	./gnupg/mpi/mpi-bit.o ./gnupg/mpi/mpi-div.o ./gnupg/mpi/mpi-cmp.o ./gnupg/mpi/mpi-gcd.o \
	./gnupg/mpi/mpih-cmp.o ./gnupg/mpi/mpih-div.o ./gnupg/mpi/mpih-mul.o ./gnupg/mpi/mpi-inline.o \
	./gnupg/mpi/mpi-inv.o ./gnupg/mpi/mpi-mpow.o ./gnupg/mpi/mpi-mul.o ./gnupg/mpi/mpi-pow.o \
	./gnupg/mpi/mpi-scan.o ./gnupg/mpi/mpiutil.o ./gnupg/cipher/rsa-verify.o
EXTRA_CFLAGS += -DDSI_DEBUG -DDSI_DIGSIG_DEBUG -DDSI_EXEC_ONLY -DDIGSIG_LOG -DDSI_REVOCATION
endif
clean:
	@find . \
	\( -name '*.[oas]' -o -name '*.ko' -o -name '.*.cmd' -o -name '*~'\
	-o -name '.*.d' -o -name '.*.tmp' -o -name '*.mod.c' \) \
	-type f -print | xargs rm -f

tags:
	rm -f TAGS
	@find . -name \*.[ch] | xargs etags -a
