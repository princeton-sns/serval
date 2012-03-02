AC_INIT([Serval], 0.1, [serval@lists.cs.princeton.edu])
AC_CONFIG_MACRO_DIR([m4])

# Use the silent-rules feature when possible.
m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])
AM_SILENT_RULES([yes])

# support for cross compiling
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
CFLAGS="$CFLAGS -Wall"
CXXFLAGS="$CXXFLAGS -Wall"
EXTRA_DEFINES=
KERNEL_EXTRA_CFLAGS=

top_dir=${PWD}
AC_SUBST(top_dir)

# Check for platform
serval_os_linux=no
serval_os_unix=no
PLATFORM=

AC_MSG_CHECKING([for Linux])
case $host in
  *-*-linux*)
	serval_os_linux=yes
	serval_os_unix=yes
	PLATFORM=linux
	;;
esac
AC_MSG_RESULT([$serval_os_linux])

serval_os_bsd=no
serval_os_macosx=no

AC_MSG_CHECKING([for MacOS X])
case $host in
  *-*-darwin*)
	serval_os_macosx=yes
	serval_os_bsd=yes
	serval_os_unix=yes
	PLATFORM=darwin
	;;
esac

AC_MSG_RESULT([$serval_os_macosx])

# Set some automake variables
AM_CONDITIONAL(OS_LINUX, [test x$serval_os_linux = xyes])
AM_CONDITIONAL(OS_MACOSX, [test x$serval_os_macosx = xyes])
AM_CONDITIONAL(OS_BSD, [test x$serval_os_bsd = xyes])
AM_CONDITIONAL(OS_UNIX, [test x$serval_os_unix = xyes])

# Platform define could be set here or detected in platform.h header
#if test x$serval_os_linux = xyes
#then
#	CPPFLAGS="${CPPFLAGS} -DOS_LINUX"
#fi
#if test x$serval_os_macosx = xyes
#then
#	CPPFLAGS="${CPPFLAGS} -DOS_MACOSX"
#fi

dnl In the future, we might want to override the SERVAL_DIR,
dnl but for now, just go with default values.
SERVAL_DIR=${ac_default_prefix}
SERVAL_INCLUDE_DIR="${SERVAL_DIR}/include"
SERVAL_LIB_DIR="${SERVAL_DIR}/lib"
SERVAL_LDFLAGS="-L${SERVAL_LIB_DIR}"
AC_SUBST(SERVAL_DIR)
AC_SUBST(SERVAL_LIB_DIR)
AC_SUBST(SERVAL_INCLUDE_DIR)
AC_SUBST(SERVAL_LDFLAGS)

dnl Put in config.h
AC_DEFINE_UNQUOTED([SERVAL_LDFLAGS], "${SERVAL_LDFLAGS}", [Library and include paths for Serval])

dnl Check for OpenSSL development headers
AX_CHECK_OPENSSL(have_ssl=yes, have_ssl=no)
AM_CONDITIONAL([HAVE_SSL], [test x$have_ssl = xyes])

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
     CFLAGS="$CFLAGS -g -O0 -fno-inline"  
     CXXFLAGS="$CXXFLAGS -g -O0 -fno-inline"
     KERNEL_EXTRA_CFLAGS="$KERNEL_EXTRA_CFLAGS -g3 -ggdb3 -fno-inline"
else
     CFLAGS="$CFLAGS -O2"  
     CXXFLAGS="$CXXFLAGS -O2"
     KERNEL_EXTRA_CFLAGS="$KERNEL_EXTRA_CFLAGS -O2"
fi

dnl Option to set gprof
AC_ARG_ENABLE([gprof],
[ --enable-gprof	enable gprof],
enable_gprof=$enableval, enable_gprof=no)

if test "$enable_gprof" = "yes" ; then
   CFLAGS="$CFLAGS -pg"
   CXXFLAGS="$CXXFLAGS -pg"
fi

dnl Check for Java

dnl Allow the user to force Java bindings
AC_ARG_ENABLE([java_bindings], 
AS_HELP_STRING([--disable-java-bindings], [Disable libhaggle Java bindings]),
[case "${enableval}" in
  yes) java_bindings=yes ;;
  no)  java_bindings=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --disable-java-bindings]) ;;
esac],[java_bindings=yes])

have_jni=no;
JAVAC=

dnl Check for Java JDK
AC_JAVA_OPTIONS
AC_CHECK_JAVA_HOME
AC_PROG_JAVAC

AC_MSG_CHECKING(for jni.h)

if test x"$JAVAC" != x;
then
	dnl Check for JNI headers
	AC_JNI_INCLUDE_DIR

	JAVA_INCLUDE=

	for jni_inc in $JNI_INCLUDE_DIRS
	do
		JAVA_INCLUDE="$JAVA_INCLUDE -I$jni_inc"
	done

	if test "x$JAVA_INCLUDE" = 'x';
	then
		have_jni=no
	else
		have_jni=yes
	fi
fi

AC_MSG_RESULT([$have_jni])

AC_SUBST(JAVA_INCLUDE)

dnl Check if we support java bindings
if test x$java_bindings = xyes; 
then
   	if test x$have_jni = xno; 
	then
   	   	AC_MSG_NOTICE([Java bindings require jni.h. Please check your JAVA_HOME paths(or set --with-java-home).])
		java_bindings=no
	else
		if test "x$JAVAC" = 'x'; 
		then
			AC_MSG_NOTICE([Java bindings require java and javac. Check your PATH or or JAVA_HOME.])
			java_bindings=no
		fi
	fi
fi

AM_CONDITIONAL([ENABLE_JAVA_BINDINGS], [test x$java_bindings = xyes])

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
  *) AC_MSG_ERROR([bad value ${enableval} for --disable-kernel]) ;;
esac],[kernel=yes])

AM_CONDITIONAL([ENABLE_LINUX_MODULE], [test x$kernel = xyes && test x$serval_os_linux = xyes])

AC_ARG_ENABLE([usermode],
AS_HELP_STRING([--disable-usermode],[Disable user mode stack]),
[case "${enableval}" in
  yes) usermode=yes ;;
  no)  usermode=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --disable-usermode]) ;;
esac],[usermode=yes])

AM_CONDITIONAL([ENABLE_USERMODE], [test x$usermode = xyes])

dnl export these variable (so Makefile substitutions
dnl can be made. 
CPPFLAGS="${CPPFLAGS} ${EXTRA_DEFINES}"
#CFLAGS="${CFLAGS} ${EXTRA_DEFINES}"
#CXXFLAGS="${CXXFLAGS} ${EXTRA_DEFINES}"

AC_SUBST(EXTRA_DEFINES)
AC_SUBST(KERNEL_EXTRA_CFLAGS)

dnl
dnl Output
dnl

AC_CONFIG_FILES([Makefile
	src/Makefile
	src/common/Makefile
	src/stack/Makefile
	src/stack/Kbuild	
	src/libservalctrl/Makefile
	src/libserval/Makefile
	src/servd/Makefile
	src/translator/Makefile
	src/tools/Makefile
	src/test/Makefile
	src/javasock/Makefile
	src/javasock/java/Makefile	
	src/javasock/jni/Makefile
	])

AC_OUTPUT

echo
echo "Build user-mode stack.....................$usermode"
echo "Build Linux kernel module.................$kernel"
#echo "Build unit tests.........................$unittest"
echo "Enable debug output.......................$debug"
echo "Enable Java bindings......................$java_bindings"
#echo "Enable GPROF.............................$enable_gprof"
echo
