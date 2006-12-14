AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = config.rpath mkinstalldirs system.h depcomp

SUBDIRS = m4

ACLOCAL_AMFLAGS = -I m4 

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
