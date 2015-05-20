# As suggested by libtoolize
ACLOCAL_AMFLAGS = -I config

AM_CFLAGS = -Wall -Werror

WARNING_CFLAGS = -Wall -Wformat -W -Werror
WARNING_CXXFLAGS = -fvisibility-inlines-hidden

noinst_PROGRAMS = src/main

src_main_SOURCES = src/main.cpp
src_main_CXXFLAGS = $(OLA_CFLAGS)
src_main_LDADD = $(OLA_LIBS)
