AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = config.rpath mkinstalldirs system.h depcomp

SUBDIRS = cfg fd logger rt support tnl vnd

sbin_PROGRAMS = tincd

tincd_SOURCES = process.c tincd.c

tincd_LDADD = cfg/libcfg.a fd/libfd.a logger/liblogger.a rt/librt.a support/libsupport.a tnl/libtnl.a vnd/libvnd.a -lgnutls

ACLOCAL_AMFLAGS = -I m4 

AM_CFLAGS = @CFLAGS@ -DCONFDIR=\"$(sysconfdir)\" -DLOCALEDIR=\"$(localedir)\" -DLOCALSTATEDIR=\"$(localstatedir)\"

ChangeLog:
	svn log > ChangeLog

svn-clean: maintainer-clean
	svn status --no-ignore | sed -n 's/^[?I] \+//p' | tr '\012' '\0' | xargs -r0 rm -rf

release:
	rm -f ChangeLog
	$(MAKE) ChangeLog
	echo "Please edit the NEWS file now..."
	/usr/bin/editor NEWS
	$(MAKE) dist
