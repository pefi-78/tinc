AC_PREREQ(2.59)
AC_INIT
AC_CONFIG_SRCDIR([tincd.c])
AM_INIT_AUTOMAKE(tinc, 2.0-svn)
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE

dnl Include the macros from the m4/ directory
dnl AM_ACLOCAL_INCLUDE(m4)

dnl AM_GNU_GETTEXT([external])
dnl AM_GNU_GETTEXT_VERSION(0.14.1)

AC_DEFINE([_GNU_SOURCE], 1, [Enable GNU extenstions])
AC_DEFINE([__USE_BSD], 1, [Enable BSD extensions])

dnl ALL_LINGUAS="nl"

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

AC_ISC_POSIX

dnl Check and set OS

AC_CANONICAL_HOST

case $host_os in
  *linux*)
    AC_DEFINE(HAVE_LINUX, 1, [Linux])
  ;;
  *freebsd*)
    AC_DEFINE(HAVE_FREEBSD, 1, [FreeBSD])
  ;;
  *darwin*)
    AC_DEFINE(HAVE_DARWIN, 1, [Darwin (MacOS/X)])
  ;;
  *solaris*)
    AC_DEFINE(HAVE_SOLARIS, 1, [Solaris/SunOS])
  ;;
  *openbsd*)
    AC_DEFINE(HAVE_OPENBSD, 1, [OpenBSD])
  ;;
  *netbsd*)
    AC_DEFINE(HAVE_NETBSD, 1, [NetBSD])
  ;;
  *cygwin*)
    AC_DEFINE(HAVE_CYGWIN, 1, [Cygwin])
  ;;
  *mingw*)
    AC_DEFINE(HAVE_MINGW, 1, [MinGW])
    LIBS="$LIBS -lws2_32"
  ;;
  *)
    AC_MSG_ERROR("Unknown operating system.")
  ;;
esac

AC_CACHE_SAVE

if test -d /sw/include ; then
  CPPFLAGS="$CPPFLAGS -I/sw/include"
fi
if test -d /sw/lib ; then
  LIBS="$LIBS -L/sw/lib"
fi

dnl Checks for libraries.

dnl Checks for header files.
dnl We do this in multiple stages, because unlike Linux all the other operating systems really suck and don't include their own dependencies.

AC_HEADER_STDC
AC_CHECK_HEADERS([stdbool.h syslog.h sys/file.h sys/ioctl.h sys/param.h sys/time.h sys/socket.h sys/wait.h sys/mman.h netdb.h arpa/inet.h])
AC_CHECK_HEADERS([net/if.h net/ethernet.h net/if_arp.h netinet/in_systm.h netinet/in.h netinet/in6.h],
  [], [],
  [#ifdef HAVE_SYS_TYPES_H
   #include <sys/types.h>
   #endif
   #ifdef HAVE_NETDB_H
   #include <netdb.h>
   #endif
   #ifdef HAVE_ARPA_INET_H
   #include <arpa/inet.h>
   #endif
   #ifdef HAVE_SYS_SOCKET_H
   #include <sys/socket.h>
   #endif
  ]
)
AC_CHECK_HEADERS([netinet/if_ether.h netinet/ip.h netinet/ip6.h],
  [], [],
  [#ifdef HAVE_SYS_TYPES_H
   #include <sys/types.h>
   #endif
   #ifdef HAVE_NETDB_H
   #include <netdb.h>
   #endif
   #ifdef HAVE_ARPA_INET_H
   #include <arpa/inet.h>
   #endif
   #ifdef HAVE_SYS_SOCKET_H
   #include <sys/socket.h>
   #endif
   #ifdef HAVE_NET_IF_H
   #include <net/if.h>
   #endif
   #ifdef HAVE_NETINET_IN_SYSTM_H
   #include <netinet/in_systm.h>
   #endif
   #ifdef HAVE_NETINET_IN_H
   #include <netinet/in.h>
   #endif
   #ifdef HAVE_NETINET_IN6_H
   #include <netinet/in6.h>
   #endif
   #ifdef HAVE_NET_ETHERNET_H
   #include <net/ethernet.h>
   #endif
   #ifdef HAVE_NET_IF_ARP_H
   #include <net/if_arp.h>
   #endif
  ]
)
AC_CHECK_HEADERS([netinet/tcp.h netinet/ip_icmp.h netinet/icmp6.h],
  [], [],
  [#ifdef HAVE_SYS_TYPES_H
   #include <sys/types.h>
   #endif
   #ifdef HAVE_NETDB_H
   #include <netdb.h>
   #endif
   #ifdef HAVE_ARPA_INET_H
   #include <arpa/inet.h>
   #endif
   #ifdef HAVE_SYS_SOCKET_H
   #include <sys/socket.h>
   #endif
   #ifdef HAVE_NET_IF_H
   #include <net/if.h>
   #endif
   #ifdef HAVE_NETINET_IN_SYSTM_H
   #include <netinet/in_systm.h>
   #endif
   #ifdef HAVE_NETINET_IN_H
   #include <netinet/in.h>
   #endif
   #ifdef HAVE_NETINET_IP_H
   #include <netinet/ip.h>
   #endif
   #ifdef HAVE_NETINET_IN6_H
   #include <netinet/in6.h>
   #endif
   #ifdef HAVE_NETINET_IP6_H
   #include <netinet/ip6.h>
   #endif
   #ifdef HAVE_NET_ETHERNET_H
   #include <net/ethernet.h>
   #endif
   #ifdef HAVE_NET_IF_ARP_H
   #include <net/if_arp.h>
   #endif
   #ifdef HAVE_NETINET_IF_ETHER_H
   #include <netinet/if_ether.h>
   #endif
  ]
)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl tinc_ATTRIBUTE(__malloc__)

AC_CHECK_TYPES([socklen_t, struct ether_header, struct arphdr, struct ether_arp, struct in_addr, struct addrinfo, struct ip, struct icmp, struct in6_addr, struct sockaddr_in6, struct ip6_hdr, struct icmp6_hdr, struct nd_neighbor_solicit, struct nd_opt_hdr], , ,
  [#ifdef HAVE_SYS_TYPES_H
   #include <sys/types.h>
   #endif
   #ifdef HAVE_NETDB_H
   #include <netdb.h>
   #endif
   #ifdef HAVE_ARPA_INET_H
   #include <arpa/inet.h>
   #endif
   #ifdef HAVE_SYS_SOCKET_H
   #include <sys/socket.h>
   #endif
   #ifdef HAVE_NET_IF_H
   #include <net/if.h>
   #endif
   #ifdef HAVE_NETINET_IN_SYSTM_H
   #include <netinet/in_systm.h>
   #endif
   #ifdef HAVE_NETINET_IN_H
   #include <netinet/in.h>
   #endif
   #ifdef HAVE_NETINET_IP_H
   #include <netinet/ip.h>
   #endif
   #ifdef HAVE_NETINET_TCP_H
   #include <netinet/tcp.h>
   #endif
   #ifdef HAVE_NETINET_IN6_H
   #include <netinet/in6.h>
   #endif
   #ifdef HAVE_NETINET_IP6_H
   #include <netinet/ip6.h>
   #endif
   #ifdef HAVE_NET_ETHERNET_H
   #include <net/ethernet.h>
   #endif
   #ifdef HAVE_NET_IF_ARP_H
   #include <net/if_arp.h>
   #endif
   #ifdef HAVE_NETINET_IF_ETHER_H
   #include <netinet/if_ether.h>
   #endif
   #ifdef HAVE_NETINET_IP_ICMP_H
   #include <netinet/ip_icmp.h>
   #endif
   #ifdef HAVE_NETINET_ICMP6_H
   #include <netinet/icmp6.h>
   #endif
  ]
)

dnl Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_ALLOCA
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([asprintf daemon fchmod flock ftime fork get_current_dir_name gettimeofday mlockall putenv random select strdup strerror strsignal strtol system unsetenv vsyslog])
dnl jm_FUNC_MALLOC
dnl jm_FUNC_REALLOC

dnl Support for SunOS

AC_CHECK_FUNC(socket, [], [
  AC_CHECK_LIB(socket, connect)
])
AC_CHECK_FUNC(gethostbyname, [], [
  AC_CHECK_LIB(nsl, gethostbyname)
])

AC_CHECK_FUNCS([freeaddrinfo gai_strerror getaddrinfo getnameinfo inet_aton])

AC_CACHE_SAVE

dnl These are defined in files in m4/

dnl case $host_os in
dnl  *linux*)
dnl    tinc_TUNTAP
dnl  ;;
dnl esac

dnl tinc_OPENSSL
dnl tinc_ZLIB
dnl tinc_LZO

AM_PATH_LIBGNUTLS([1.0.4], [], [AC_MSG_ERROR([GNUTLS library not found.]); break])

dnl Check if support for jumbograms is requested 
dnl AC_ARG_ENABLE(jumbograms,
dnl  AS_HELP_STRING(--enable-jumbograms,enable support for jumbograms (packets up to 9000 bytes)),
dnl  [ AC_DEFINE(ENABLE_JUMBOGRAMS, 1, [Support for jumbograms (packets up to 9000 bytes)]) ]
dnl )

dnl Check if checkpoint tracing has to be enabled
dnl AC_ARG_ENABLE(tracing,
dnl  AS_HELP_STRING(--enable-tracing,enable checkpoint tracing (debugging only)),
dnl  [ AC_DEFINE(ENABLE_TRACING, 1, [Checkpoint tracing]) ]
dnl )

dnl AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile doc/tincd.8 doc/tinc.conf.5 doc/tincinclude.texi lib/Makefile po/Makefile.in m4/Makefile])
AC_CONFIG_FILES([Makefile cfg/Makefile fd/Makefile logger/Makefile rt/Makefile support/Makefile tnl/Makefile vnd/Makefile])

AC_OUTPUT
