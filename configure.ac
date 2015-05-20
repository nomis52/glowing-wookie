#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([glowing-wookie], [0.0.1], [])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign])
AC_LANG_PUSH([C++])

AC_PROG_CXX

# pkg-config
PKG_PROG_PKG_CONFIG
AS_IF([test -z "$PKG_CONFIG"],
      [AC_MSG_ERROR([Missing pkg-config, please install it])])

# OLA
PKG_CHECK_MODULES(
  OLA,
  [libola],
  [],
  [AC_MSG_ERROR([Missing OLA, please install])])

# DNS-SD support
# We use either avahi or the Apple DNS-SD library.

# dns_sd
AC_CHECK_HEADER(
  [dns_sd.h],
  [AC_SEARCH_LIBS(DNSServiceRegister, [dns_sd], [have_dnssd="yes"])])

AS_IF([test "x$have_dnssd" = xyes],
      [AC_DEFINE([HAVE_DNSSD], [1], [Defined to use Bonjour DNS_SD])])
AM_CONDITIONAL([HAVE_DNSSD], [test "x$have_dnssd" = xyes])

# Avahi
PKG_CHECK_MODULES(
  avahi,
  [avahi-client],
  [have_avahi="yes"],
  [true])

AS_IF([test "x$have_avahi" = xyes],
      [AC_DEFINE([HAVE_AVAHI], [1], [Defined to use Avahi])])
AM_CONDITIONAL([HAVE_AVAHI], [test "x$have_avahi" = xyes])

# Output
#####################################################
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo \
"-------------------------------------------------------
${PACKAGE_NAME} Version ${PACKAGE_VERSION}

Prefix: '${prefix}'
Compiler: '${CXX} ${CXXFLAGS} ${CPPFLAGS}'
Linker: '${LD} ${LDFLAGS} ${LIBS}'

Now type 'make'
-------------------------------------------------------"
