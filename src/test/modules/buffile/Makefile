PG_CONFIG ?= pg_config
MODULE_big = buffile
OBJS = buffile.o $(WIN32RES)
PGFILEDESC = "buffile_test"

EXTENSION = buffile
DATA = buffile--1.0.sql

REGRESS = test_00 test_01 test_02 test_03 test_04 test_05 test_06 test_07 \
test_08 test_09 test_10 test_11

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
