## Process this file with automake to produce Makefile.in

TESTS = tests_jsaes
check_PROGRAMS = tests_jsaes
tests_jsaes_SOURCES = tests_main.c tests_aes.c $(top_builddir)/src/aes_tests.h $(top_builddir)/src/aes.h $(top_builddir)/src/aesutils.h
tests_jsaes_CFLAGS = -Wall -g3 -std=c99 -I$(top_builddir)/src -I$(top_builddir)/tests
tests_jsaes_LDADD = $(top_builddir)/src/libjsaes.a

