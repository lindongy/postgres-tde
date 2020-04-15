#-------------------------------------------------------------------------
#
# Makefile for the pl/pgsql_sec procedural language
#
# plpgsql_sec-12.x/Makefile
#
#-------------------------------------------------------------------------

# Shared library parameters
MODULE_big = plpgsql_sec

OBJS = pl_comp.o pl_handler.o

EXTENSION = plpgsql_sec
DATA = plpgsql_sec.control plpgsql_sec--1.0.sql plpgsql_sec--unpackaged--1.0.sql
DOCS = README.plpgsql_sec
EXTRA_CLEAN = *~ nls.mk plerrcodes.h generate-plerrcodes.pl

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/plpgsql_sec
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

override CPPFLAGS := -I$(top_srcdir)/src/pl/plpgsql/src/ $(CPPFLAGS)

ifeq ($(OS), Linux)
	SHLIB_LINK = $(filter -lintl, $(LIBS)) $(BE_DLLLIBS)
endif

ifeq ($(OS), Darwin)
	SHLIB_LINK = $(filter -lintl, $(LIBS)) $(BE_DLLLIBS) -bundle -flat_namespace -undefined suppress
endif

rpath :=

$(srcdir)/nls.mk:
	cp $(top_builddir)/src/pl/plpgsql/src/nls.mk $(srcdir)

# Force these dependencies to be known even without dependency info built:
pl_handler.o pl_comp.o pl_exec.o pl_funcs.o pl_scanner.o: plpgsql_sec.h \
plerrcodes.h $(srcdir)/nls.mk

$(srcdir)/generate-plerrcodes.pl:
	cp $(top_builddir)/src/pl/plpgsql/src/generate-plerrcodes.pl $(srcdir)

#generate plerrcodes.h from src/backend/utils/errcodes.txt
$(srcdir)/plerrcodes.h: $(top_builddir)/src/backend/utils/errcodes.txt $(srcdir)/generate-plerrcodes.pl
	$(PERL) $(srcdir)/generate-plerrcodes.pl $< > $@
