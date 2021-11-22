
AM_CFLAGS = @BUILD_CFLAGS@ 
lib_LTLIBRARIES = libsqlite3.la
libsqlite3_la_SOURCES = sqlite3.c spellfix.c
libsqlite3_la_CFLAGS = -DSQLITE_CORE $(AM_CFLAGS) -I$(top_srcdir)/include
libsqlite3_la_LDFLAGS = -no-undefined -version-info 8:6:8
