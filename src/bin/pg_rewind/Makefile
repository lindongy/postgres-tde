#-------------------------------------------------------------------------
#
# Makefile for src/bin/pg_rewind
#
# Portions Copyright (c) 2013-2017, PostgreSQL Global Development Group
#
# src/bin/pg_rewind/Makefile
#
#-------------------------------------------------------------------------

PGFILEDESC = "pg_rewind - synchronize a data directory with another one forked from"
PGAPPICON = win32

subdir = src/bin/pg_rewind
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

override CPPFLAGS := -I$(libpq_srcdir) -DFRONTEND $(CPPFLAGS)
override LDFLAGS := $(libpq_pgport) $(LDFLAGS)

OBJS	= pg_rewind.o parsexlog.o xlogreader.o datapagemap.o timeline.o \
	fetch.o file_ops.o copy_fetch.o libpq_fetch.o filemap.o logging.o \
	encryption.o xts.o rijndael.o $(WIN32RES)

SMGR_DIR=$(top_srcdir)/src/backend/storage/smgr

EXTRA_CLEAN = xlogreader.c

all: pg_rewind

pg_rewind: $(OBJS) | submake-libpq submake-libpgport
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

xlogreader.c: % : $(top_srcdir)/src/backend/access/transam/%
	rm -f $@ && $(LN_S) $< .

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
	$(INSTALL_PROGRAM) pg_rewind$(X) '$(DESTDIR)$(bindir)/pg_rewind$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/pg_rewind$(X)'

clean distclean maintainer-clean:
	rm -f pg_rewind$(X) $(OBJS) xlogreader.c encryption.c xts.c \
rijndael.c rijndael.tbl
	rm -rf tmp_check

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)
