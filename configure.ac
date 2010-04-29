AC_INIT(pam_rps,0.1)
AM_INIT_AUTOMAKE(foreign)
AC_PROG_CC
if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Wextra"
fi
LT_INIT(disable-static)
AM_MAINTAINER_MODE
AC_CHECK_HEADERS(security/pam_modules.h security/pam_appl.h)
if test x$ac_cv_header_security_pam_modules_h != xyes ; then
	AC_ERROR(security/pam_modules.h not found)
fi
if test x$ac_cv_header_security_pam_appl_h != xyes ; then
	AC_ERROR(security/pam_appl.h not found)
fi
AC_CHECK_FUNC(pam_get_item,,AC_CHECK_LIB(pam,pam_get_item))
AC_CONFIG_HEADER(src/config.h)
AC_OUTPUT(Makefile src/Makefile src/pam_rps.8)
