AC_INIT(pam_rps,0.1)
AM_INIT_AUTOMAKE(foreign)
AC_PROG_CC
if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Wextra"
fi
AC_PROG_LIBTOOL
AM_MAINTAINER_MODE
AC_CHECK_HEADERS(security/pam_modules.h)
AC_CONFIG_HEADER(src/config.h)
AC_OUTPUT(Makefile src/Makefile)
