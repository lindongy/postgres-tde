#-------------------------------------------------------------------------
#
# Makefile for src/bin/pg_resetwal
#
# Copyright (c) 1998-2017, PostgreSQL Global Development Group
#
# src/bin/pg_resetwal/Makefile
#
#-------------------------------------------------------------------------

PGFILEDESC = "pg_resetwal - reset PostgreSQL WAL log"
PGAPPICON=win32

subdir = src/bin/pg_resetwal
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

override CPPFLAGS := -DFRONTEND $(CPPFLAGS)

OBJS= pg_resetwal.o encryption.o xts.o rijndael.o $(WIN32RES)
SMGR_DIR=$(top_srcdir)/src/backend/storage/smgr

all: pg_resetwal

pg_resetwal: $(OBJS) | submake-libpgport
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

encryption.c xts.c: % : $(SMGR_DIR)/%
	rm -f $@ && $(LN_S) $< .

# rijndael.c is treated specially because its dependency on rijndael.tbl
# cannot be handled simply by adding rijndael.tbl to OBJS (no implicit rule
# exists for *.tbl).
#
# If better approach is found, apply it also to the other applications in
# "src/bin".
rijndael.c: $(SMGR_DIR)/rijndael.c rijndael.tbl
	rm -f $@ && $(LN_S) $< .

rijndael.tbl: $(SMGR_DIR)/rijndael.tbl
	rm -f $@ && $(LN_S) $< .

install: all installdirs
	$(INSTALL_PROGRAM) pg_resetwal$(X) '$(DESTDIR)$(bindir)/pg_resetwal$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/pg_resetwal$(X)'

clean distclean maintainer-clean:
	rm -f pg_resetwal$(X) $(OBJS) encryption.c rijndael.c rijndael.tbl \
xts.c
