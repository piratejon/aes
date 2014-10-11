## Process this file with automake to produce Makefile.in

lib_LIBRARIES = libjsaes.a
libjsaes_a_SOURCES = aes.c aes.h aesutils.h aes_test.h

bin_PROGRAMS = jsaes
jsaes_SOURCES = aes_main.c
jsaes_CFLAGS = -DTESTING -Weverything -g3
jsaes_LDADD = libjsaes.a

