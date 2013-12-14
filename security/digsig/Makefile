# Makefile for DigSig security module

obj-$(CONFIG_SECURITY_DIGSIG) := digsig.o

digsig-y := dsi_sysfs.o digsig_cache.o digsig_revocation.o dsi_sig_verify.o

ccflags-y := -DDIGSIG_DEBUG -DDIGSIG_LOG -DDIGSIG_REVOCATION

