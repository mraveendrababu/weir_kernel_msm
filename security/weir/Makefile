#
# Makefile for the WEIR LSM
#

obj-$(CONFIG_SECURITY_WEIR) := weir.o

weir-y := weir_lsm.o weir_iface.o weir_list.o weir_netlink.o

EXTRA_CFLAGS += -Isecurity/weir/include
