# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

AC_INIT([RT-Firewire],[0.1.0],[Zhang Yuchen <y.zhang-4@student.utwente.nl>])
AC_CONFIG_HEADERS([config/rt-firewire_config_pre.h])
AC_CONFIG_AUX_DIR([config/autoconf])
AC_CONFIG_MACRO_DIR([config/m4])
AC_CONFIG_SRCDIR([stack/ieee1394_core.c])
AC_PREFIX_DEFAULT([/usr/local/rt-firewire])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_PROG_INSTALL

CFLAGS=${CFLAGS:--s}

# Checks for programs.
AC_ARG_WITH(CC,
    AS_HELP_STRING([--with-cc=compiler], [use specific C compiler]),
    [case "$withval" in
    "" | y | ye | yes | n | no)
	AC_MSG_ERROR([*** You must supply an argument to --with-cc.]) ;;
    esac
    CC="$withval"])
AC_PROG_CC

AC_DEFINE_UNQUOTED(CONFIG_RTFW_BUILD_STRING, "$build", [Build system alias])
RTFW_BUILD_STRING="$build"
AC_DEFINE_UNQUOTED(CONFIG_RTFW_HOST_STRING, "$host", [Host system alias])
RTFW_HOST_STRING="$host"
AC_DEFINE_UNQUOTED(CONFIG_RTFW_COMPILER, "`$CC -v 2>&1 | tail -n 1`" , [Compiler])

AM_INIT_AUTOMAKE([foreign no-exeext dist-bzip2])
AM_MAINTAINER_MODE
AC_PROG_LIBTOOL
AM_PROG_AS
AC_SUBST(LD)


dnl ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
dnl ++++++++++++ copied from rtai 3.0 +++ start ++++++++++++++++++++++++++
dnl ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

case "$host" in
    i*86*-*)
	RTFW_TARGET_ARCH=i386
	wanted_kernel_arch=CONFIG_X86
        ;;
#    arm-*)
#	RTFW_TARGET_ARCH=arm
#	wanted_kernel_arch=CONFIG_ARM
#        ;;
    powerpc-*|ppc-*)
	RTFW_TARGET_ARCH=ppc
	wanted_kernel_arch=CONFIG_PPC
        ;;
#    mips-*|mipsel-*)
#	RTFW_TARGET_ARCH=mips
#	wanted_kernel_arch=CONFIG_MIPS
#        ;;
#    cris-*)
#	RTFW_TARGET_ARCH=cris
#	dnl There is no non-ambiguous CONFIG_ETRAX|CRIS symbol
#	dnl so use the root device definition.
#	wanted_kernel_arch=CONFIG_ETRAX_ROOT_DEVICE
#        ;;
    *)
	AC_MSG_ERROR([*** Sorry - Unsupported architecture])
	;;
esac

dnl ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
dnl ++++++++++++ copied from rtai-3.0 +++ end ++++++++++++++++++++++++++++
dnl ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#
# define helper function
#
AC_DEFUN([AC_CHECK_LIBRARY],
    [ac_save_LIBS="$LIBS"
    LIBS="$$3 $ac_save_LIBS"
    AC_CHECK_LIB($1,$2)
    $3=`echo "$LIBS" | sed "s% $ac_save_LIBS$%%"`
    LIBS="$ac_save_LIBS"])


# Checks for libraries.
# FIXME: Replace `main' with a function in `-lncurses':
AC_CHECK_LIBRARY(ncurses, main, NCURSES_LIBS)
AM_CONDITIONAL(CONFIG_NCURSES,[test x"${NCURSES_LIBS}" != x""])
AC_SUBST(NCURSES_LIBS)


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_C_VOLATILE

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([inet_ntoa memset socket strchr strerror])


dnl ======================================================================
dnl		rtai sources
dnl ======================================================================

AC_ARG_WITH(rtai,
    AS_HELP_STRING([--with-rtai=RTAI], [path to configured RTAI 24.1.x sources, or installation of RTAI 3, 4 or fusion ]),
    [case "${withval}" in
    "" | y | ye | yes | n | no)
	AC_MSG_ERROR([You must supply an argument to --with-rtai.]) ;;
    esac],
    with_rtai="/usr/src/rtai")


dnl ======================================================================
dnl =========== try to find rtai-24.1.x ==================================
dnl ======================================================================
#
# try to find rtai-24.1.x
# set CONFIG_RTFW_RTAI_24 to 'n' to prevent it
#
unset CONFIG_RTFW_RTAI_24

# first check if there is a Makefile, this means probably rtai-24.1.x
if test x"$CONFIG_RTFW_RTAI_24" \!= x"n"; then
    AC_MSG_CHECKING([for RTAI 24.1.x source tree])
    if test \! -f $with_rtai/Makefile; then
	CONFIG_RTFW_RTAI_24=n
	AC_MSG_RESULT([no])
    fi
fi

# check for the right Makefile
if test "$CONFIG_RTFW_RTAI_24" != "n"; then
    if test "`sed -n -e \"s/^PROJECT = \(.*\)/\1/p\" ${with_rtai}/Makefile`" = "RTAI"; then
	RTAI_DIR=$with_rtai
    	AC_MSG_RESULT([$RTAI_DIR])
    else
 	CONFIG_RTFW_RTAI_24=n
	AC_MSG_RESULT([no])
    fi
fi

#
# if we've gone so far, we think that the user gives us a rtai-24.1.x source dir
# if the following checks, (not configured rtai, kernel, etc) fail, this will be fatal,
# so we simply stop checking
#

if test x"$CONFIG_RTFW_RTAI_24" \!= x"n"; then
    AC_MSG_CHECKING([for configured RTAI 24.1.x])
    if test -f ${RTAI_DIR}/.buildvars -a -f ${RTAI_DIR}/.config; then
	AC_MSG_RESULT([yes])
    else
	AC_MSG_ERROR([*** No configured RTAI found in $RTAI_DIR])
    fi

# source (load) the rtai configuration
    . ${RTAI_DIR}/.config

    CONFIG_RTFW_RTAI_VERSION=24

    RTAI_LINUX_DIR=`sed -n -e "s/^LINUXDIR=\(.*\)/\1/p" $RTAI_DIR/.buildvars`

#
# make some checks on the kernel
#
# __N_O_T_E__ the if expression ends after the checks copied from RTAI-unstable....
#

dnl ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
dnl ++++++++++++ copied from rtai 3.0 +++ start ++++++++++++++++++++++++++
dnl ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

AC_MSG_CHECKING([for Linux source tree])

if test \! -r ${RTAI_LINUX_DIR}/Makefile; then
   echo
   AC_MSG_ERROR([*** No Linux kernel tree in ${RTAI_LINUX_DIR}])
fi

eval linux_`grep '^EXTRAVERSION =' $RTAI_LINUX_DIR/Makefile | sed -e 's, ,,g'`
eval linux_`grep '^PATCHLEVEL =' $RTAI_LINUX_DIR/Makefile | sed -e 's, ,,g'`
eval linux_`grep '^SUBLEVEL =' $RTAI_LINUX_DIR/Makefile | sed -e 's, ,,g'`
eval linux_`grep '^VERSION =' $RTAI_LINUX_DIR/Makefile | sed -e 's, ,,g'`

dnl Load Linux kernel configuration now, before config symbols are tested.
if test \! -r ${RTAI_LINUX_DIR}/.config; then
   AC_MSG_ERROR([*** $RTAI_LINUX_DIR is not configured])
fi

. $RTAI_LINUX_DIR/.config

RTAI_LINUX_VERSION="$linux_VERSION.$linux_PATCHLEVEL.$linux_SUBLEVEL.$linux_EXTRAVERSION"
AC_MSG_RESULT([$RTAI_LINUX_DIR (kernel ${RTAI_LINUX_VERSION}${CONFIG_SMP:+-SMP})])

dnl
dnl Identify the base technology used.
dnl

unset CONFIG_RTAI_RTHAL
unset CONFIG_RTAI_ADEOS

AC_MSG_CHECKING([for RTAI base technology])

if test -r $RTAI_LINUX_DIR/include/linux/adeos.h; then
    AC_MSG_RESULT([Adeos])
    CONFIG_RTAI_ADEOS=y
elif test x${CONFIG_RTHAL} = xy; then
    dnl This test has a flaw. Only x86 forcibly defines CONFIG_RTHAL
    dnl as a result of having applied the RTAI patch. Other platforms
    dnl like PPC for instance leave it as an option, so the kernel is
    dnl patched, but the RTAI support has been configured out.
    dnl This is the reason why the error message remains ambiguous.
    dnl We should definitely have _one_ common way of identifying the
    dnl RTHAL signature inside a kernel tree, that does not rely on
    dnl the Makefile's EXTRAVERSION variable, because it happened that
    dnl some people change its value manually to suit their needs...
    if test "$CONFIG_X86" = y; then
       AC_MSG_RESULT([legacy RTHAL])
    else
       AC_MSG_RESULT([RTHAL])
    fi
    CONFIG_RTAI_RTHAL=y
    dnl Need Adeos to run Xenomai in native mode.
    unset CONFIG_RTAI_XENOMAI
else
    echo
    AC_MSG_ERROR([*** RTAI patch not applied/enabled in $RTAI_LINUX_DIR])
fi

case "$RTAI_LINUX_VERSION" in
    2.4.*)
        ;;
    *)
	AC_MSG_ERROR([*** Unsupported kernel version $RTAI_LINUX_VERSION])
	;;
esac

dnl
dnl Perform a few sanity checks.
dnl

arch_select=`eval echo \\$$wanted_kernel_arch`
if test x$arch_select = x; then
   echo
   echo "************************************************************"
   echo " The target RTAI architecture ($RTFW_TARGET_ARCH) does not match"
   echo " the kernel architecture selected in $RTAI_LINUX_DIR"
   echo " (i.e. $wanted_kernel_arch is undefined)"
   echo "************************************************************"
   exit 1
fi

if test x${CONFIG_MODULES} = x ; then
  AC_MSG_ERROR([*** Please set CONFIG_MODULES for $RTAI_LINUX_DIR and rebuild your kernel])
fi

if test x${CONFIG_MODVERSIONS} = xy ; then
  AC_MSG_ERROR([*** Please unset CONFIG_MODVERSIONS for $RTAI_LINUX_DIR and rebuild your kernel])
fi

if test x${CONFIG_RTAI_ADEOS} = xy -a x${CONFIG_ADEOS_CORE} = x; then
   AC_MSG_ERROR([*** Please activate the Adeos support (General menu) in $RTAI_LINUX_DIR and rebuild your kernel])
fi

if test x${CONFIG_RTAI_RTHAL} = xy -a x${CONFIG_RTHAL} = x; then
   AC_MSG_ERROR([*** Please activate the RTAI support in $RTAI_LINUX_DIR and rebuild your kernel])
fi


dnl ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
dnl ++++++++++++ copied from rtai-3.0 +++ end ++++++++++++++++++++++++++++
dnl ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
fi

dnl ===========	end of rtai 24.1.x detection =============================


dnl ======================================================================
dnl =========== try to find rtai-3 =======================================
dnl ======================================================================
#
# try to find rtai-3 or newer but don't look for them, if...
# ...we've already found rtai-24.1.x
#
if test x"$CONFIG_RTFW_RTAI_24" \!= x"n"; then
    CONFIG_RTFW_RTAI_3=n
else
    unset CONFIG_RTFW_RTAI_3
fi

#
# the presence of rtai-config is a good indication for rtai >= 3
#
if test x"$CONFIG_RTFW_RTAI_3" \!= x"n"; then
    AC_MSG_CHECKING([for RTAI 3 installation])
    RTAI_CONFIG="${with_rtai}/bin/rtai-config"
    if test -x ${RTAI_CONFIG}; then
        RTAI_DIR="`echo ${with_rtai} | sed -e s,[/]*$,,`"	# strip trailing slashes
	AC_MSG_RESULT([${RTAI_DIR}])
    else
	CONFIG_RTFW_RTAI_3=n
	AC_MSG_RESULT([no])
    fi
fi

#
# from now we think we've found RTAI-3, so if we got en error
# it will be fatal, thus exit with AC_MSG_ERROR
#

if test x"$CONFIG_RTFW_RTAI_3" \!= x"n"; then
#
# check if rtai-3 is installed with DESTDIR
# e.g.: 'make DESTDIR=/foo install'
#
    AC_MSG_CHECKING([for RTAI DESTDIR])
    RTFW_RTAI_PREFIX="`${RTAI_CONFIG} --prefix | sed -e s,[/]*$,,`"		# strip trailing slashes
    if test "${RTFW_RTAI_PREFIX}" \!= "${RTAI_DIR}"; then
	RTFW_RTAI_DESTDIR="`echo ${RTAI_DIR} | sed -e s,${RTFW_RTAI_PREFIX}$,,`"
	export DESTDIR="${RTFW_RTAI_DESTDIR}"

	RTFW_RTAI_PREFIX="`${RTAI_CONFIG} --prefix | sed -e s,[/]*$,,`"	# strip trailing slashes
	if test "${RTFW_RTAI_PREFIX}" = "${RTAI_DIR}"; then
	    AC_MSG_RESULT([${DESTDIR}])
	else
	    AC_MSG_ERROR([*** Cannot identify DESTDIR])
	fi
    else
	AC_MSG_RESULT([none])
    fi

    AC_MSG_CHECKING([for RTAI version])
    CONFIG_RTFW_RTAI_3_VERSION="`${RTAI_CONFIG} --version`"

    case "$CONFIG_RTFW_RTAI_3_VERSION" in
    3.0*)
	CONFIG_RTFW_RTAI_VERSION=30
	;;
    3.1*)
	CONFIG_RTFW_RTAI_VERSION=31
	;;
    3.2*)
	CONFIG_RTFW_RTAI_VERSION=32
	;;
    0.6.6-fusion)
	CONFIG_RTFW_RTAI_VERSION=066
	;;
    0.6.7-fusion)
	CONFIG_RTFW_RTAI_VERSION=067
	;;
    0.6.8-fusion)
	CONFIG_RTFW_RTAI_VERSION=068
	;;
    *)
	AC_MSG_ERROR([*** Unsupported RTAI version $CONFIG_RTFW_RTAI_3_VERSION in $RTAI_DIR])
	;;
    esac
    AC_MSG_RESULT([${CONFIG_RTFW_RTAI_3_VERSION}])

    AC_MSG_CHECKING([for RTAI config file])
    CONFIG_RTFW_RTAI_CONFIG_FILE="${RTAI_DIR}/share/rtai/config-rtai-${CONFIG_RTFW_RTAI_3_VERSION}"
    if test \! -f ${CONFIG_RTFW_RTAI_CONFIG_FILE}; then
	CONFIG_RTFW_RTAI_CONFIG_FILE="`${RTAI_CONFIG} --config`"
	if test \! -f $CONFIG_RTFW_RTAI_CONFIG_FILE; then
	    AC_MSG_ERROR([*** RTAI configuration file not found])
	fi
    fi
    AC_MSG_RESULT([${CONFIG_RTFW_RTAI_CONFIG_FILE}])

# source (load) the rtai configuration
    . ${CONFIG_RTFW_RTAI_CONFIG_FILE}

    case "$CONFIG_RTFW_RTAI_VERSION" in
        30 | 31)	# ---> RTAI 3.x <---

	    # check for semas, needed by RTFW
	    AC_MSG_CHECKING([for RTAI semaphores])
	    case "${CONFIG_RTAI_SEM}" in
		y | m) AC_MSG_RESULT([${CONFIG_RTAI_SEM}]) ;;
		*) AC_MSG_ERROR([*** Please enable semaphores in RTAI]) ;;
	    esac

	    # check for RT malloc, needed by RTFW
	    AC_MSG_CHECKING([for RTAI malloc])
	    case "${CONFIG_RTAI_MALLOC}" in
		y | m) AC_MSG_RESULT([${CONFIG_RTAI_MALLOC}]) ;;
		*) AC_MSG_ERROR([*** Please enable real-time malloc in RTAI]) ;;
	    esac

	    # check for fifos, needed by RTFW-examples
	    AC_MSG_CHECKING([for RTAI fifos])
	    case "${CONFIG_RTAI_FIFOS}" in
		y | m) AC_MSG_RESULT([${CONFIG_RTAI_FIFOS}]) ;;
		*) AC_MSG_ERROR([*** Please enable fifos in RTAI]) ;;
	    esac

	    ;;

	06*)	# ---> FUSION <---

	    # check for native RTAI skin, needed by RTFW
	    AC_MSG_CHECKING([for RTAI native skin])
	    case "${CONFIG_RTAI_SKIN_NATIVE}" in
	        y) AC_MSG_RESULT([${CONFIG_RTAI_SKIN_NATIVE}]) ;;
		*) AC_MSG_ERROR([*** Please enable native RTAI skin]) ;;
	    esac

	    # check for semas, needed by RTFW
	    AC_MSG_CHECKING([for RTAI Semaphores])
	    case "${CONFIG_RTAI_OPT_NATIVE_SEM}" in
		y) AC_MSG_RESULT([${CONFIG_RTAI_OPT_NATIVE_SEM}]) ;;
		*) AC_MSG_ERROR([*** Please enable semaphores in RTAI]) ;;
	    esac

	    # malloc support is built-in for RTAI 4

	    # check for pipes, needed by RTFW
	    AC_MSG_CHECKING([for RTAI pipes])
	    case "${CONFIG_RTAI_OPT_NATIVE_PIPE}" in
		y) AC_MSG_RESULT([${CONFIG_RTAI_OPT_NATIVE_PIPE}]) ;;
		*) AC_MSG_ERROR([*** Please enable pipes in RTAI]) ;;
	    esac

	    # check for mutexes, needed by RTFW
	    AC_MSG_CHECKING([for RTAI mutexes])
	    case "${CONFIG_RTAI_OPT_NATIVE_MUTEX}" in
	        y) AC_MSG_RESULT([${CONFIG_RTAI_OPT_NATIVE_MUTEX}]) ;;
		*) AC_MSG_ERROR([*** Please enable mutexes in RTAI]) ;;
	    esac

	    ;;

	*)		# ---> oops <----
	    AC_MSG_ERROR([*** internal error])
	    ;;
    esac

# get linux kernel tree and version
    AC_MSG_CHECKING([for Linux source tree])
    RTAI_LINUX_DIR="`${RTAI_CONFIG} --linux-dir`"
    RTAI_LINUX_VERSION="`${RTAI_CONFIG} --linux-version`"

    AC_MSG_RESULT([$RTAI_LINUX_DIR (kernel ${RTAI_LINUX_VERSION}${CONFIG_SMP:+-SMP})])
fi

dnl ===========	end of rtai 3 detection ==================================


#
# now let's see wich version of rtai we've found
# exit with error if there isn't any version
#
case "$CONFIG_RTFW_RTAI_VERSION" in
    24)
	AC_DEFINE(CONFIG_RTAI_24, 1, [We build for rtai 24.1.x])
	;;
    30)
	AC_DEFINE(CONFIG_RTAI_30, 1, [We build for rtai 3.0rx])
	;;
    31)
	AC_DEFINE(CONFIG_RTAI_31, 1, [We build for rtai 3.1rx])
	;;
    32)
	AC_DEFINE(CONFIG_RTAI_32, 1, [We build for rtai 3.2rx])
	;;
    06*)
	AC_DEFINE(CONFIG_FUSION_06, 1, [We build for fusion 0.6.x])
	;;
    *)
	AC_MSG_ERROR([*** No RTAI found in $with_rtai])
	;;
esac


dnl ======================================================================
dnl		check linux version
dnl ======================================================================

case "${RTAI_LINUX_VERSION}" in
    2.4.*)
	RTAI_LINUX_VERSION_SUBLEVEL="`echo ${RTAI_LINUX_VERSION} | sed -e 's/[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\).*/\1/'`"
	if test ${RTAI_LINUX_VERSION_SUBLEVEL} -le 18; then
	    AC_MSG_ERROR([*** Unsupported kernel version $RTAI_LINUX_VERSION - please upgrade at least to 2.4.19])
	fi
	;;
    2.6.*)
	AC_MSG_ERROR([*** sorry, Linux platform 2.6 is not supported yet])
	;;
    *)
	AC_MSG_ERROR([*** Unsupported kernel version $RTAI_LINUX_VERSION])
	;;
esac



dnl ======================================================================
dnl		import settings from RTAI
dnl ======================================================================

# kbuild (linux 2.6) or not
case "${RTAI_LINUX_VERSION}" in
    2.4.*)
	unset CONFIG_KBUILD
	;;
    2.6.*)
	CONFIG_KBUILD=y
	;;
    *)
	AC_MSG_ERROR([*** internal error])
	;;
esac
AM_CONDITIONAL(CONFIG_KBUILD,[test "$CONFIG_KBUILD" = y])

# common stuff
case "${CONFIG_RTFW_RTAI_VERSION}" in
    24)
	RTAI_USER_CFLAGS="-I$RTAI_DIR/include -I$RTAI_DIR/lxrt/include"
	CONFIG_RTFW_RTAI_ARCH="`sed -n -e "s/^ARCH=\(.*\)/\1/p" $RTAI_DIR/.buildvars`"
	;;
    30 | 31 | 32)
	RTAI_USER_CFLAGS="`${RTAI_CONFIG} --lxrt-cflags`"
	CONFIG_RTFW_RTAI_ARCH="`${RTAI_CONFIG} --arch`"
	;;
    06*)
	RTAI_USER_CFLAGS="`${RTAI_CONFIG} --fusion-cflags`"
	CONFIG_RTFW_RTAI_ARCH="`${RTAI_CONFIG} --arch`"
	;;
    *)
	AC_MSG_ERROR([*** internal error])
	;;
esac


if test "$CONFIG_KBUILD" = "y"; then
    case "${CONFIG_RTFW_RTAI_VERSION}" in
	24 | 30)
	    AC_MSG_ERROR([*** internal error])
	    ;;
	31 | 32)
	    RTAI_KMOD_CFLAGS="`${RTAI_CONFIG} --lxrt-cflags`"
	    ;;
	06*)
	    RTAI_KMOD_CFLAGS="`${RTAI_CONFIG} --fusion-cflags`"
	    ;;
	*)
	    AC_MSG_ERROR([*** internal error])
	    ;;
    esac
else
    case "${CONFIG_RTFW_RTAI_VERSION}" in
	24)
	    RTAI_KMOD_CFLAGS="`sed -n -e "s/^CFLAGS=\(.*\)/\1/p" $RTAI_DIR/.buildvars` -I$RTAI_DIR/include -DEXPORT_SYMTAB -Wall"
	    ;;
	30 | 31 | 32)
	    RTAI_KMOD_CFLAGS="`${RTAI_CONFIG} --module-cflags`"
	    ;;
	06*)
	    AC_MSG_ERROR([*** internal error])
	    ;;
	*)
	    AC_MSG_ERROR([*** internal error])
	    ;;
    esac
fi


dnl ======================================================================
dnl		architecture tests....
dnl ======================================================================

AC_MSG_CHECKING([for RTAI target arch])
AC_MSG_RESULT([${CONFIG_RTFW_RTAI_ARCH}])

AC_MSG_CHECKING([for RTFW target arch])
AC_MSG_RESULT([${RTFW_TARGET_ARCH}])

if test x"${RTFW_TARGET_ARCH}" != x"${CONFIG_RTFW_RTAI_ARCH}"; then
    AC_MSG_ERROR([*** RTAI and RTFW target architectures are not the same])
fi

case "${CONFIG_RTFW_RTAI_ARCH}" in
    i386)
	AC_DEFINE(CONFIG_ARCH_I386, 1,[we are building for x86])
	;;
    ppc)
	AC_DEFINE(CONFIG_ARCH_PPC, 1, [we are building for powerpc])
	;;
#    arm)
#	AC_DEFINE(CONFIG_ARCH_ARM, 1, [we are trying to build for arm])
#	;;
#    cris)
#	AC_DEFINE(CONFIG_ARCH_CRIS, 1, [we are trying to build for cris])
#	;;
    *)
	AC_MSG_ERROR([*** unsupported architecture])
	;;
esac

AC_SUBST(RTFW_TARGET_ARCH)


dnl ======================================================================
dnl		crosscompiling
dnl ======================================================================

AC_MSG_CHECKING([for CROSS_COMPILE])
if test "${CROSS_COMPILE}" = ""; then
    CROSS_COMPILE="`echo ${CC} | sed s/gcc//`"

    if test "${CROSS_COMPILE}gcc" \!= "${CC}"; then
	CROSS_COMPILE=""
	AC_MSG_RESULT([Cannot identify CROSS_COMPILE - assuming none - set manually if needed])
    else
	if test "${CROSS_COMPILE}" = ""; then
	    AC_MSG_RESULT([none])
	else
	    AC_MSG_RESULT([${CROSS_COMPILE}])
	fi
    fi
else
    AC_MSG_RESULT([${CROSS_COMPILE}])
fi
AC_SUBST(CROSS_COMPILE)


dnl ======================================================================
dnl		decide to build for 2.4 or 2.6 kernel
dnl ======================================================================

if test x$CONFIG_KBUILD = x; then
    RTFW_MODULE_EXT=.o
    RTFW_KBUILD_ENV=
    RTFW_KBUILD_CMD=
    RTFW_KBUILD_CLEAN=
else
    RTFW_MODULE_EXT=.ko
    RTFW_KBUILD_ENV='src2obj = $(patsubst %.$(1),%.o,$(filter %.$(1),$(call notdir,$(2))))'
    RTFW_KBUILD_CMD="											\
	@for src in \$(filter-out FORCE, \$^); do							\
	    if test \\! -r \`basename \$\$src\`; then							\
		\$(LN_S) \$\$src;									\
	    fi;												\
	done;												\
	\$(MAKE) -C $RTAI_LINUX_DIR									\
		CROSS_COMPILE=\$(CROSS_COMPILE)								\
		ARCH=\$(RTFW_TARGET_ARCH)								\
		M=\"\`pwd\`\"										\
		V=\$(V)											\
		rtai_dir=\"${RTFW_RTAI_PREFIX}\"							\
		top_srcdir=\"\`cd \$(top_srcdir) && pwd\`\"						\
		top_builddir=\"\`cd \$(top_builddir) && pwd\`\"						\
		srcdir=\"\`cd \$(srcdir) && pwd\`\"							\
		build_objs='\$(call src2obj,c,\$^)'							\
		build_target='\$(basename \$@)'								\
		modules											\
		"
   RTFW_KBUILD_CLEAN="											\
	@rm -f *.ko *.mod.c .*.cmd *.o;									\
	for src in \$^; do										\
	    if test -h \`basename \$\$src\`; then							\
		rm -f \`basename \$\$src\`;								\
	    fi;												\
	done;												\
	if test -d .tmp_versions; then									\
	    rm -rf .tmp_versions;									\
	fi;												\
	"
   dnl === Hack to suppress undefined symbol warnings during MODPOST stage ===
   if test -e $RTAI_LINUX_DIR/Module.symvers; then
	mv $RTAI_LINUX_DIR/Module.symvers $RTAI_LINUX_DIR/Module.symvers.let_modpost_be_quiet
   fi
   if test -e $RTAI_LINUX_DIR/vmlinux; then
	mv $RTAI_LINUX_DIR/vmlinux $RTAI_LINUX_DIR/vmlinux.let_modpost_be_quiet
   fi
fi

AC_MSG_CHECKING([for kernel module extension])
AC_MSG_RESULT([$RTFW_MODULE_EXT])

AC_SUBST(RTFW_MODULE_EXT)
AC_SUBST(RTFW_KBUILD_ENV)
AC_SUBST(RTFW_KBUILD_CMD)
AC_SUBST(RTFW_KBUILD_CLEAN)

bs_kmodext=$RTFW_MODULE_EXT
bs_kcompile="make -C $RTAI_LINUX_DIR ARCH=$RTFW_TARGET_ARCH CROSS_COMPILE=$CROSS_COMPILE V=1 M=`pwd` SUBDIRS=`pwd` modules"


dnl ======================================================================
dnl		RTAI header checks
dnl ======================================================================

ac_save_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${ac_save_CPPFLAGS} ${RTAI_KMOD_CFLAGS}"

# Working around some Autoconf ugliness here: names of variables
# stored into the cache are canonicalized, turning /'s into _'s. So if
# you need to match X_Y.h and X/Y.h as different filenames, you are
# toast. Whichever comes first will be cached as "X_Y_h" and the
# second one will never get checked in the fs, but simply
# uncached. This applies to rtai_sem.h and rtai/sem.h for instance.
# To prevent this, we must only check a single set of non-conflicting
# headers, depending on the RTAI version which has been
# identified. (rpm)
if test "${CONFIG_KBUILD}" = "y"; then	# building against linux-2.6
    case "${CONFIG_RTFW_RTAI_VERSION}" in
        24 | 30)
	    AC_MSG_ERROR([*** internal error])
	    ;;
	31 | 32)
		AC_CHECK_HEADERS([rtai_sem.h rtai_malloc.h rtai_fifos.h],
		[],
		[AC_MSG_ERROR([*** header not found or working, please check RTAI installation])],
		[
#include <linux/kernel.h>
		])
            ;;
	06*)
	    AC_CHECK_HEADERS([rtai/sem.h rtai/mutex.h rtai/pipe.h],
		[],
		[AC_MSG_ERROR([*** header not found or working, please check RTAI installation])],
		[
#include <linux/kernel.h>
		])
	    ;;
	*)
	    AC_MSG_ERROR([*** internal error])
	    ;;
    esac
else					# building against linux-2.4
    case "${CONFIG_RTFW_RTAI_VERSION}" in
        24)		# mandatory RTAI-24 headers
	    AC_CHECK_HEADERS([rtai_lxrt_user.h rtai_declare.h],
	    [],
	    [AC_MSG_ERROR([*** header not found or working, please check RTAI installation])],
            [
#include <linux/kernel.h>
            ])
	    ;;
	30 | 31 | 32)	# mandatory RTAI-3 headers
	    AC_CHECK_HEADERS([rtai_sem.h rtai_malloc.h],
	    [],
	    [AC_MSG_ERROR([*** header not found or working, please check RTAI installation])],
            [
#include <linux/kernel.h>
            ])
	    ;;
	06*)
	    AC_MSG_ERROR([*** internal error])
	    ;;
	*)
	    AC_MSG_ERROR([*** internal error])
	    ;;
    esac
fi

CPPFLAGS="${ac_save_CFLAGS}"


dnl ======================================================================
dnl		Installation directory for modules
dnl ======================================================================

AC_MSG_CHECKING([for module installation directory])

AC_ARG_WITH(module-dir,
    AS_HELP_STRING([--with-module-dir=<module-dir>], [Installation directory for modules]),
    [case "${withval}" in
    "" | y | ye | yes | n | no)
	AC_MSG_ERROR([You must supply an argument to --with-module-dir.]) ;;
    esac],
    with_module_dir='${exec_prefix}/modules')
RTFW_MODULE_DIR="$with_module_dir"
AC_MSG_RESULT([$RTFW_MODULE_DIR])
AC_SUBST(RTFW_MODULE_DIR)


dnl ======================================================================
dnl		check for NEWLXRT
dnl ======================================================================
AC_MSG_CHECKING([for RTAI NEWLXRT enabled])
case "${CONFIG_RTFW_RTAI_VERSION}" in
    24)
	case "$CONFIG_RTAI_NEWLXRT" in
	    y | m) CONFIG_NEWLXRT=yes ;;
	    *) CONFIG_NEWLXRT=no ;;
	esac
	;;
    30 | 31 | 32)
	case "${CONFIG_RTAI_SCHED_LXRT}" in
	    y | m) CONFIG_NEWLXRT=yes ;;
	    *) CONFIG_NEWLXRT=no ;;
	esac
	;;
    06*) CONFIG_NEWLXRT=no
	;;
    *)
	AC_MSG_ERROR([*** internal error])
	;;
esac
AC_MSG_RESULT([${CONFIG_NEWLXRT}])
AM_CONDITIONAL(CONFIG_NEWLXRT,[test "$CONFIG_NEWLXRT" = "yes"])
if test "$CONFIG_NEWLXRT" = "yes"; then
   AC_DEFINE(CONFIG_NEWLXRT, 1, [RTAI LXRT])
fi

dnl ======================================================================
dnl		hac^H^H^Hfix problem with multible defined symbols problem
dnl		shamelessly stolen from RTAI-3.1 tnx to Philippe
dnl ======================================================================

dnl CAUTION: We need to have the CONFIG_RTFW_XX symbols always defined when
dnl the configuration header is read, but we want the Autoconf-produced
dnl symbols to be defined only when compiling RTFW. This way, we won't
dnl pollute the namespace with the latter when our configuration header is
dnl indirectly included by a client application. To achieve this, we ask
dnl autoheader to produce the following header structure:
dnl #define CONFIG_XX
dnl #define CONFIG_XX ...
dnl #ifdef __IN_RTFW__
dnl <Autoconf-defined symbols>
dnl #endif /* __IN_RTFW__ */
dnl This is quite a hack since we have to rely on the fact that
dnl all Autoconf-generated symbols are lexicographically sorted
dnl after CONFIG_RTFW_XX ones, but, well...

dnl Use a key which will cause the verbatim string to be put after
dnl all CONFIG_RTFW_XX symbols, but still before any Autoconf-generated
dnl symbol, hence CONFIG_RTFW___.
AH_VERBATIM(CONFIG_RTFW___,[#ifdef __IN_RTFW__])

dnl Now we can close the conditional section, right after all
dnl Autoconf-generated symbols have been listed.
AH_BOTTOM([#endif /* __IN_RTFW__ */])


RTAI_KMOD_CFLAGS="-D__IN_RTFW__ $RTAI_KMOD_CFLAGS"
RTAI_USER_CFLAGS="-D__IN_RTFW__ $RTAI_USER_CFLAGS"
AC_SUBST(RTAI_KMOD_CFLAGS)
AC_SUBST(RTAI_USER_CFLAGS)


dnl ======================================================================
dnl		generate output
dnl ======================================================================

AC_CONFIG_FILES([GNUmakefile include/GNUmakefile	highlevel/GNUmakefile highlevel/bis1394/GNUmakefile highlevel/eth1394/GNUmakefile drivers/GNUmakefile drivers/ohci/GNUmakefile rtskbuff/GNUmakefile rtpc/GNUmakefile rt_serv/GNUmakefile stack/GNUmakefile tools/GNUmakefile])
   
AC_OUTPUT

dnl ======================================================================
dnl             generate include/rt-firewire_config.h
dnl ======================================================================

AC_MSG_NOTICE([creating include/rt-firewire_config.h])
sed -e "s/ PACKAGE/ RTFW_PACKAGE/" -e "s/ VERSION/ RTFW_VERSION/" \
    config/rt-firewire_config_pre.h > include/rt-firewire_config.h.new
if cmp -s nclude/rt-firewire_config.h.new include/rt-firewire_config.h; then
    rm include/rt-firewire_config.h.new
    AC_MSG_NOTICE([include/rt-firewire_config.h is unchanged])
else
    mv include/rt-firewire_config.h.new include/rt-firewire_config.h
fi
