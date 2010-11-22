AC_INIT([scaffold-stack], 0.1, [scaffold@lists.cs.princeton.edu])

dnl support for cross compiling
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AM_CONFIG_HEADER(config.h)

dnl Clear CFLAGS and CXXFLAGS
CFLAGS=
CXXFLAGS=

dnl Set some decent default flags
CFLAGS="$CFLAGS -Wall -O2"
CXXFLAGS="$CXXFLAGS -Wall -O2"
EXTRA_DEFINES=

top_dir=${PWD}
AC_SUBST(top_dir)

dnl In the future, we might want to override the SCAFFOLD_DIR,
dnl but for now, just go with default values.
SCAFFOLD_DIR=${ac_default_prefix}
SCAFFOLD_INCLUDE_DIR="${SCAFFOLD_DIR}/include"
SCAFFOLD_LIB_DIR="${SCAFFOLD_DIR}/lib"
SCAFFOLD_LDFLAGS="-L${SCAFFOLD_LIB_DIR}"
AC_SUBST(SCAFFOLD_DIR)
AC_SUBST(SCAFFOLD_LIB_DIR)
AC_SUBST(SCAFFOLD_INCLUDE_DIR)
AC_SUBST(SCAFFOLD_LDFLAGS)

dnl Put in config.h
AC_DEFINE_UNQUOTED([SCAFFOLD_LDFLAGS], "${SCAFFOLD_LDFLAGS}", [Library and include paths for Scaffold])


dnl Preset $prefix and $exec_prefix.
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'

dnl Option to set debugging
AC_ARG_ENABLE([debug],
AS_HELP_STRING([--enable-debug],[Turn on debugging]),
[case "${enableval}" in
  yes) debug=yes ;;
  no)  debug=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],[debug=no])

AM_CONDITIONAL([DEBUG], [test x$debug = xyes])

if test x$debug = xyes
then      
     EXTRA_DEFINES="${EXTRA_DEFINES} -DENABLE_DEBUG"
     CFLAGS="$CFLAGS -g"  
     CXXFLAGS="$CXXFLAGS -g"
fi

dnl Option to set gprof
AC_ARG_ENABLE([gprof],
[ --enable-gprof	enable gprof],
enable_gprof=$enableval, enable_gprof=no)

if test "$enable_gprof" = "yes" ; then
   CFLAGS="$CFLAGS -pg"
   CXXFLAGS="$CXXFLAGS -pg"
fi

AC_ARG_ENABLE([native_api],
AS_HELP_STRING([--enable-native-api],[Use native kernel sockets API for clients]),
[case "${enableval}" in
  yes) native_api=yes ;;
  no)  native_api=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-native-api]) ;;
esac],[native_api=no])

AM_CONDITIONAL([NATIVE_API], [test x$native_api = xyes])

AC_ARG_ENABLE([unittest],
AS_HELP_STRING([--enable-unittest],[Turn on unit test support]),
[case "${enableval}" in
  yes) unittest=yes ;;
  no)  unittest=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-unittest]) ;;
esac],[unittest=no])

AM_CONDITIONAL([UNITTEST], [test x$unittest = xyes])

AC_ARG_ENABLE([kernel],
AS_HELP_STRING([--disable-kernel],[Disable kernel module]),
[case "${enableval}" in
  yes) kernel=yes ;;
  no)  kernel=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-kernel]) ;;
esac],[kernel=yes])

AM_CONDITIONAL([LINUX_KERNEL], [test x$kernel = xyes])

dnl Check for OpenSSL and development headers
#AC_CHECK_LIB(crypto,DSA_sign,
#                [AC_CHECK_HEADERS([openssl/rsa.h],,AC_MSG_ERROR(You have openssl but not the development headers))],AC_MSG_ERROR(openssl library is not found...),)

#CPPFLAGS="${SAVE_CPPFLAGS}"
#CFLAGS="${SAVE_CFLAGS}"
#LDFLAGS="${SAVE_LDFLAGS}"
#EXTRA_CFLAGS=
dnl export these variable (so Makefile substitutions
dnl can be made. 
CPPFLAGS="${CPPFLAGS} ${EXTRA_DEFINES}"
#CFLAGS="${CFLAGS} ${EXTRA_DEFINES}"
#CXXFLAGS="${CXXFLAGS} ${EXTRA_DEFINES}"

AC_SUBST(EXTRA_DEFINES)
#AC_SUBST(CFLAGS)
#AC_SUBST(CXXFLAGS)
#AC_SUBST(LDFLAGS)
#AC_SUBST(CPPFLAGS)

dnl
dnl Output
dnl

AC_CONFIG_FILES([Makefile
	src/Makefile
	src/stack/Makefile
	src/stack/Kbuild
	src/libscaffold/Makefile
	src/scafd/Makefile
	src/test/Makefile
	])

AC_OUTPUT

echo
#echo "Build user level.........................$userlevel"
echo "Build kernel module......................$kernel"
#echo "Build unit tests.........................$unittest"
#echo "Use native sockets API for clients.......$native_api"
echo "Enable debug output......................$debug"
#echo "Enable GPROF.............................$enable_gprof"
echo
