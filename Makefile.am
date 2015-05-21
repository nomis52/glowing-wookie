# As suggested by libtoolize
ACLOCAL_AMFLAGS = -I config

AM_CFLAGS = -Wall -Werror

WARNING_CFLAGS = -Wall -Wformat -W -Werror
WARNING_CXXFLAGS = -fvisibility-inlines-hidden


# LIBRARIES
##################################################
noinst_LTLIBRARIES = src/libdnssd.la

src_libdnssd_la_SOURCES = \
    src/DiscoveryAgent.cpp \
    src/DiscoveryAgent.h \
    src/MasterEntry.cpp \
    src/MasterEntry.h
src_libdnssd_la_LIBADD =

if HAVE_DNSSD
src_libdnssd_la_SOURCES += \
    src/BonjourDiscoveryAgent.cpp \
    src/BonjourDiscoveryAgent.h \
    src/BonjourIOAdapter.cpp \
    src/BonjourIOAdapter.h \
    src/BonjourRegistration.cpp \
    src/BonjourRegistration.h \
    src/BonjourResolver.cpp \
    src/BonjourResolver.h
endif

if HAVE_AVAHI
src_libdnssd_la_SOURCES += \
    src/AvahiOlaClient.cpp \
    src/AvahiOlaClient.h \
    src/AvahiDiscoveryAgent.cpp \
    src/AvahiDiscoveryAgent.h \
    src/AvahiHelper.cpp \
    src/AvahiHelper.h \
    src/AvahiOlaPoll.cpp \
    src/AvahiOlaPoll.h
src_libdnssd_la_LIBADD += $(avahi_LIBS)
endif


# PROGRAMS
##################################################
noinst_PROGRAMS = src/master src/client

src_client_SOURCES = src/client.cpp
src_client_CXXFLAGS = $(OLA_CFLAGS)
src_client_LDADD = $(OLA_LIBS) \
                 src/libdnssd.la

src_master_SOURCES = src/master.cpp
src_master_CXXFLAGS = $(OLA_CFLAGS)
src_master_LDADD = $(OLA_LIBS) \
                   src/libdnssd.la
