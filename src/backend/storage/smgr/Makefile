#-------------------------------------------------------------------------
#
# Makefile--
#    Makefile for storage/smgr
#
# IDENTIFICATION
#    src/backend/storage/smgr/Makefile
#
#-------------------------------------------------------------------------

subdir = src/backend/storage/smgr
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

OBJS = encryption.o md.o rijndael.o smgr.o smgrtype.o xts.o

include $(top_srcdir)/src/backend/common.mk

rijndael.o: rijndael.tbl

rijndael.tbl:
	$(CC) $(CPPFLAGS) $(CFLAGS) -DPRINT_TABS rijndael.c -o gen-rtab
	./gen-rtab > rijndael.tbl

clean:
	rm -f gen-rtab rijndael.tbl
