man_MANS = pam_rps.8
securitydir = $(libdir)/security
security_LTLIBRARIES = pam_rps.la
pam_rps_la_LDFLAGS = -module -avoid-version -export-symbols-regex='pam_sm_.*'
noinst_PROGRAMS = pam_rps
pam_rps_SOURCES = main.c
pam_rps_LDADD = pam_rps.lo
