# src/bin/pg_waldump/Makefile

PGFILEDESC = "pg_waldump - decode and display WAL"
PGAPPICON=win32

subdir = src/bin/pg_waldump
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS = pg_waldump.o compat.o xlogreader.o rmgrdesc.o encryption.o \
	$(RMGRDESCOBJS) encryption.o xts.o rijndael.o $(WIN32RES)

SMGR_DIR=$(top_srcdir)/src/backend/storage/smgr

override CPPFLAGS := -DFRONTEND $(CPPFLAGS)

RMGRDESCSOURCES = $(sort $(notdir $(wildcard $(top_srcdir)/src/backend/access/rmgrdesc/*desc.c)))
RMGRDESCOBJS = $(patsubst %.c,%.o,$(RMGRDESCSOURCES))


all: pg_waldump

pg_waldump: $(OBJS) | submake-libpgport
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

xlogreader.c: % : $(top_srcdir)/src/backend/access/transam/%
	rm -f $@ && $(LN_S) $< .

$(RMGRDESCSOURCES): % : $(top_srcdir)/src/backend/access/rmgrdesc/%
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
	$(INSTALL_PROGRAM) pg_waldump$(X) '$(DESTDIR)$(bindir)/pg_waldump$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/pg_waldump$(X)'

clean distclean maintainer-clean:
	rm -f pg_waldump$(X) $(OBJS) $(RMGRDESCSOURCES) xlogreader.c \
encryption.c xts.c rijndael.c rijndael.tbl
