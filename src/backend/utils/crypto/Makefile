#-------------------------------------------------------------------------
#
# Makefile--
#    Makefile for utils/crypto
#
# IDENTIFICATION
#    src/backend/utils/crypto/Makefile
#
#-------------------------------------------------------------------------

subdir = src/backend/utils/crypto
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

OBJS = rijndael.o

include $(top_srcdir)/src/backend/common.mk

rijndael.o: rijndael.tbl

rijndael.tbl:
	$(CC) $(CPPFLAGS) $(CFLAGS) -DPRINT_TABS rijndael.c -o gen-rtab
	./gen-rtab > rijndael.tbl
