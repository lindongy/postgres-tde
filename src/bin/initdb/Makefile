#-------------------------------------------------------------------------
#
# Makefile for src/bin/initdb
#
# Portions Copyright (c) 1996-2017, PostgreSQL Global Development Group
# Portions Copyright (c) 1994, Regents of the University of California
#
# src/bin/initdb/Makefile
#
#-------------------------------------------------------------------------

PGFILEDESC = "initdb - initialize a new database cluster"
PGAPPICON=win32

subdir = src/bin/initdb
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

override CPPFLAGS := -DFRONTEND -I$(libpq_srcdir) -I$(top_srcdir)/src/timezone $(CPPFLAGS)

# note: we need libpq only because fe_utils does
override LDFLAGS := -L$(top_builddir)/src/fe_utils -lpgfeutils $(libpq_pgport) $(LDFLAGS)

# use system timezone data?
ifneq (,$(with_system_tzdata))
override CPPFLAGS += '-DSYSTEMTZDIR="$(with_system_tzdata)"'
endif

OBJS=	initdb.o findtimezone.o localtime.o encnames.o encryption.o xts.o \
rijndael.o $(WIN32RES)

SMGR_DIR=$(top_srcdir)/src/backend/storage/smgr

all: initdb

initdb: $(OBJS) | submake-libpq submake-libpgport submake-libpgfeutils
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

# We used to pull in all of libpq to get encnames.c, but that
# exposes us to risks of version skew if we link to a shared library.
# Do it the hard way, instead, so that we're statically linked.

encnames.c: % : $(top_srcdir)/src/backend/utils/mb/%
	rm -f $@ && $(LN_S) $< .

# Likewise, pull in localtime.c from src/timezones

localtime.c: % : $(top_srcdir)/src/timezone/%
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
	$(INSTALL_PROGRAM) initdb$(X) '$(DESTDIR)$(bindir)/initdb$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/initdb$(X)'

clean distclean maintainer-clean:
	rm -f initdb$(X) $(OBJS) encnames.c localtime.c encryption.c xts.c \
rijndael.c rijndael.tbl
	rm -rf tmp_check

# ensure that changes in datadir propagate into object file
initdb.o: initdb.c $(top_builddir)/src/Makefile.global

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)
