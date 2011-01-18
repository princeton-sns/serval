AC_INIT([serval-stack], 0.1, [serval@lists.cs.princeton.edu])

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

# Check for platform
serval_os_linux=no
PLATFORM=

AC_MSG_CHECKING([for Linux])
case $host in
  *-*-linux*)
	serval_os_linux=yes
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
	PLATFORM=darwin
	;;
esac

AC_MSG_RESULT([$serval_os_macosx])

serval_os_iphoneos=no

AC_MSG_CHECKING([for iPhoneOS])
case $host in
  arm-*-darwin*)
	serval_os_iphoneos=yes
	PLATFORM=darwin
	;;
esac

AC_MSG_RESULT([$serval_os_iphoneos])

# Set some automake variables
AM_CONDITIONAL(OS_LINUX, [test x$serval_os_linux = xyes])
AM_CONDITIONAL(OS_MACOSX, [test x$serval_os_macosx = xyes])
AM_CONDITIONAL(OS_BSD, [test x$serval_os_bsd = xyes])
AM_CONDITIONAL(OS_IPHONEOS, [test x$serval_os_iphoneos = xyes])

# Platform define could be set here or detected in platform.h header
#if test x$serval_os_linux = xyes
#then
#	CPPFLAGS="${CPPFLAGS} -DOS_LINUX"
#fi
#if test x$serval_os_macosx = xyes
#then
#	CPPFLAGS="${CPPFLAGS} -DOS_MACOSX"
#fi
#if test x$serval_os_iphoneos = xyes
#then
#	CPPFLAGS="${CPPFLAGS} -DOS_IPHONEOS"
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

dnl Check for Java
java_bindings=no;
have_jni=no;

AC_ARG_VAR([JAVA_HOME], [Java Runtime Environment (JRE) location])

dnl Allow the user to set the JAVA_HOME dir?
AC_ARG_WITH(java-home,
	    AS_HELP_STRING([--with-java-home=DIR],[DIR to look for Java headers]),
	    [JAVA_HOME=$withval],)

dnl Default to some qualified path guessing...
java_dirs="/usr /usr/local /usr/lib/jvm/java-5-sun /usr/lib/jvm/java-6-sun /usr/lib/jvm/java-6-openjdk /usr/lib/jvm/java /System/Library/Frameworks/JavaVM.framework/Versions/Current /System/Library/Frameworks/JavaVM.framework /opt /mingw"
java_inc_dirs="include include/libgcj Headers"

AC_CHECK_PROG(JAVA, javac, javac)
AC_MSG_CHECKING([for jni.h])

dnl Try to locate jni.h
for java_dir in $JAVA_HOME $java_dirs;
do
	for java_inc_dir in $java_inc_dirs
	do
		#AC_MSG_RESULT("${java_dir}/${java_inc_dir}/jni.h")	
		if test -r "${java_dir}/${java_inc_dir}/jni.h"; 
		then
			have_jni=yes
			java_bindings=yes
			JAVA_PATH=${java_dir}
  			break
       		fi
	done
	if test x$have_jni = xyes;
	then
		break
	fi
done

AC_MSG_RESULT([$have_jni])

JAVA_INCLUDE="-I${JAVA_PATH}/${java_inc_dir} -I${JAVA_PATH}/${java_inc_dir}/${PLATFORM}"

AC_SUBST(JAVA_INCLUDE)

dnl Allow the user to force Java bindings
AC_ARG_ENABLE([java_bindings], 
AS_HELP_STRING([--disable-java-bindings], [Disable libhaggle Java bindings]),
[case "${enableval}" in
  yes) java_bindings=yes ;;
  no)  java_bindings=no ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --disable-java-bindings]) ;;
esac],)

dnl Java bindings were detected or was forced
if test x$java_bindings = xyes; 
then
   	if test x$have_jni = xno; 
	then
   	   	AC_MSG_ERROR([Java bindings require jni.h. Please check your JAVA_HOME paths(or set --with-java-home).])
	else
		if test "x$JAVA" == 'x'; 
		then
			AC_MSG_ERROR([Java bindings require java and javac. Check your PATH or disable with --disable-java-bindings])
		fi
	fi
fi

AM_CONDITIONAL([JAVA_BINDINGS], [test x$java_bindings = xyes])

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

AM_CONDITIONAL([LINUX_KERNEL], [test x$kernel = xyes && test x$serval_os_linux = xyes])

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
	src/libserval/Makefile
	src/libstack/Makefile
	src/servd/Makefile
	src/test/Makefile
	src/javasock/Makefile
	src/javasock/jni/Makefile
	src/javasock/java/edu/princeton/cs/sns/serval/Makefile
	])

AC_OUTPUT

echo
#echo "Build user level.........................$userlevel"
echo "Build Linux kernel module.................$kernel"
#echo "Build unit tests.........................$unittest"
echo "Enable debug output.......................$debug"
#echo "Enable GPROF.............................$enable_gprof"
echo
