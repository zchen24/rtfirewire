# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

AC_INIT([RT-FireWire],[0.1.0],[rtfirewire-devel@lists.berlios.de])
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
# AC_PROG_CC

AC_DEFINE_UNQUOTED(CONFIG_RTFW_BUILD_STRING, "$build", [Build system alias])
RTFW_BUILD_STRING="$build"
AC_DEFINE_UNQUOTED(CONFIG_RTFW_HOST_STRING, "$host", [Host system alias])
RTFW_HOST_STRING="$host"
AC_DEFINE_UNQUOTED(CONFIG_RTFW_COMPILER, "`$CC -v 2>&1 | tail -n 1`" , [Compiler])

AM_INIT_AUTOMAKE([foreign no-exeext dist-bzip2])
AM_MAINTAINER_MODE
AC_PROG_LIBTOOL
AC_PROG_RANLIB
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
#   powerpc-*|ppc-*)
#	RTFW_TARGET_ARCH=ppc
#	wanted_kernel_arch=CONFIG_PPC
#        ;;
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

dnl ======================================================================
dnl             RT-extension sources
dnl ======================================================================

AC_ARG_WITH(rtext,
    AS_HELP_STRING([--with-rtext=RT-EXTENSION], [installation path of RTAI or Xenomai]),
    [case "${withval}" in
        "" | y | ye | yes | n | no)
            AC_MSG_ERROR([You must supply an argument to --with-rtext.]) ;;
        *)
            CONFIG_RTEXT_DIR=${withval} ;;
    esac])

dnl ======================================================================
dnl             try to find RT-Extension
dnl ======================================================================

AC_MSG_CHECKING([for RT-extension installation])
RTAI_CONFIG="${CONFIG_RTEXT_DIR}/bin/rtai-config"
if test -x "${RTAI_CONFIG}"; then
    RTAI_DIR="`cd ${CONFIG_RTEXT_DIR} && pwd`"   # let the shell normalize the path
    XENO_DIR=
    AC_MSG_RESULT([${RTAI_DIR} (RTAI)])
else
    XENO_CONFIG="${CONFIG_RTEXT_DIR}/bin/xeno-config"
    if test -x "${XENO_CONFIG}"; then
        RTAI_DIR=
        XENO_DIR="`cd ${CONFIG_RTEXT_DIR} && pwd`"   # let the shell normalize the path
        AC_MSG_RESULT([${XENO_DIR} (Xenomai)])
    else
        AC_MSG_ERROR([*** No RT-extension found in $CONFIG_RTEXT_DIR])
    fi
fi

#
# from now we think we've found some RT-extension, so if we got an error
# it will be fatal, thus exit with AC_MSG_ERROR
#

if test "$RTAI_DIR" \!= ""; then
    #
    # check if RTAI is installed with DESTDIR
    # e.g.: 'make DESTDIR=/foo install'
    #
    AC_MSG_CHECKING([for RTAI DESTDIR])
    RTFW_RTEXT_PREFIX="`cd \`${RTAI_CONFIG} --prefix\` && pwd`"        # let the shell normalize the path
    if test "${RTFW_RTEXT_PREFIX}" \!= "${RTAI_DIR}"; then
        RTAI_DESTDIR="`cd \`echo ${RTAI_DIR} | sed -e s,${RTFW_RTEXT_PREFIX}$,,\` && pwd`"
        export DESTDIR="${RTAI_DESTDIR}"

        RTFW_RTEXT_PREFIX="`cd \`${RTAI_CONFIG} --prefix\` && pwd`"    # let the shell normalize the path
        if test "${RTFW_RTEXT_PREFIX}" = "${RTAI_DIR}"; then
            AC_MSG_RESULT([${DESTDIR}])
        else
            AC_MSG_ERROR([*** Cannot identify DESTDIR])
        fi
    else
        AC_MSG_RESULT([none])
    fi

    AC_MSG_CHECKING([for RTAI version])
    RTAI_VERSION="`${RTAI_CONFIG} --version`"

    case "$RTAI_VERSION" in
        magma)
            CONFIG_RTFW_RTEXT_VERSION=rtai-3x
            AC_DEFINE(CONFIG_RTAI_3x, 1, [We build for RTAI 3.x])
            ;;
        *)
            AC_MSG_ERROR([*** Unsupported RTAI version $RTAI_VERSION in $RTAI_DIR])
            ;;
    esac
    AC_MSG_RESULT([${RTAI_VERSION}])

    AC_MSG_CHECKING([for RTAI config file])
    RTAI_CONFIG_FILE="${RTAI_DIR}/share/rtai/config-rtai-${RTAI_VERSION}"
    if test \! -f ${RTAI_CONFIG_FILE}; then
        RTAI_CONFIG_FILE="`${RTAI_CONFIG} --config`"
        if test \! -f $RTAI_CONFIG_FILE; then
            AC_MSG_ERROR([*** RTAI configuration file not found])
        fi
    fi
    AC_MSG_RESULT([${RTAI_CONFIG_FILE}])

    # source (load) the rtai configuration
    . ${RTAI_CONFIG_FILE}

elif test "$XENO_DIR" \!= ""; then
    #
    # check if Xenomai is installed with DESTDIR
    # e.g.: 'make DESTDIR=/foo install'
    #
    AC_MSG_CHECKING([for Xenomai DESTDIR])
    RTFW_RTEXT_PREFIX="`cd \`${XENO_CONFIG} --prefix\` && pwd`"        # let the shell normalize the path
    if test "${RTFW_RTEXT_PREFIX}" \!= "${XENO_DIR}"; then
        XENO_DESTDIR="`cd \`echo ${XENO_DIR} | sed -e s,${RTFW_RTEXT_PREFIX}$,,\` && pwd`"
        export DESTDIR="${XENO_DESTDIR}"

        RTFW_RTEXT_PREFIX="`cd \`${XENO_CONFIG} --prefix\` && pwd`"    # let the shell normalize the path
        if test "${RTFW_RTEXT_PREFIX}" = "${XENO_DIR}"; then
            AC_MSG_RESULT([${DESTDIR}])
        else
            AC_MSG_ERROR([*** Cannot identify DESTDIR])
        fi
    else
        AC_MSG_RESULT([none])
    fi

    AC_MSG_CHECKING([for Xenomai version])
    XENO_VERSION="`${XENO_CONFIG} --version`"

    case "$XENO_VERSION" in
        1.9.9 | 2.*)
            CONFIG_RTFW_RTEXT_VERSION=xeno-2x
            AC_DEFINE(CONFIG_XENO_2x, 1, [We build for Xenomai 2.x])
            ;;
        *)
            AC_MSG_ERROR([*** Unsupported Xenomai version $XENO_VERSION in $XENO_DIR])
            ;;
    esac
    AC_MSG_RESULT([${XENO_VERSION}])

    AC_MSG_CHECKING([for Xenomai config file])
    XENO_CONFIG_FILE="`${XENO_CONFIG} --config`"
    if test \! -f $XENO_CONFIG_FILE; then
        AC_MSG_ERROR([*** Xenomai configuration file not found])
    fi
    AC_MSG_RESULT([${XENO_CONFIG_FILE}])

    # source (load) the Xenomai configuration
    . ${XENO_CONFIG_FILE}

else
    AC_MSG_ERROR([*** internal error])
fi

AM_CONDITIONAL(CONFIG_RTAI,[test "$RTAI_DIR" \!= ""])
AM_CONDITIONAL(CONFIG_XENO,[test "$XENO_DIR" \!= ""])

case "$CONFIG_RTFW_RTEXT_VERSION" in
    rtai-3x) # ---> RTAI 3.x <---

        # check for semas, needed by rt-firewire
        AC_MSG_CHECKING([for RTAI semaphores])
        case "${CONFIG_RTAI_SEM}" in
            y | m) AC_MSG_RESULT([${CONFIG_RTAI_SEM}]) ;;
            *) AC_MSG_ERROR([*** Please enable semaphores in RTAI]) ;;
        esac

        # check for RT malloc, needed by rt-firewire
        AC_MSG_CHECKING([for RTAI malloc])
        case "${CONFIG_RTAI_MALLOC}" in
            y | m) AC_MSG_RESULT([${CONFIG_RTAI_MALLOC}]) ;;
            *) AC_MSG_ERROR([*** Please enable real-time malloc in RTAI]) ;;
        esac

        # check for fifos, needed by rt-firewire examples
        AC_MSG_CHECKING([for RTAI fifos])
        case "${CONFIG_RTAI_FIFOS}" in
            y | m) AC_MSG_RESULT([${CONFIG_RTAI_FIFOS}]) ;;
            *) AC_MSG_ERROR([*** Please enable fifos in RTAI]) ;;
        esac

        # get linux kernel tree and version
        AC_MSG_CHECKING([for Linux source tree])
        RTEXT_LINUX_DIR="`${XENO_CONFIG} --linux-dir`"
        RTEXT_LINUX_VERSION="`${XENO_CONFIG} --linux-version`"

        ;;

    xeno-2x) # ---> Xenomai 2.x <---

        # check for RTDM skin, needed by rt-firewire
        AC_MSG_CHECKING([for RTDM skin])
        case "${CONFIG_XENO_SKIN_RTDM}" in
            y) AC_MSG_RESULT([${CONFIG_XENO_SKIN_RTDM}]) ;;
            *) AC_MSG_ERROR([*** Please enable RTDM skin]) ;;
        esac

        # check for pipes, needed by rt-firewire
#        AC_MSG_CHECKING([for RTAI pipes])
#        case "${CONFIG_RTAI_OPT_NATIVE_PIPE}" in
#            y) AC_MSG_RESULT([${CONFIG_RTAI_OPT_NATIVE_PIPE}]) ;;
#            *) AC_MSG_ERROR([*** Please enable pipes in RTAI]) ;;
#        esac

        # get linux kernel tree and version
        AC_MSG_CHECKING([for Linux source tree])
        RTEXT_LINUX_DIR="`${XENO_CONFIG} --linux-dir`"
        RTEXT_LINUX_VERSION="`${XENO_CONFIG} --linux-version`"

        ;;

    *)              # ---> oops <----
        AC_MSG_ERROR([*** internal error])
        ;;
esac

#source (load) the kernel configuration
. ${RTEXT_LINUX_DIR}/.config

AC_MSG_RESULT([$RTEXT_LINUX_DIR (kernel ${RTEXT_LINUX_VERSION}${CONFIG_SMP:+-SMP})])

dnl =========== end of RT-extension detection ============================


dnl ======================================================================
dnl		check linux version
dnl ======================================================================

case "${RTEXT_LINUX_VERSION}" in
    2.4.*)
	RTEXT_LINUX_VERSION_SUBLEVEL="`echo ${RTEXT_LINUX_VERSION} | sed -e 's/[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\).*/\1/'`"
	if test ${RTEXT_LINUX_VERSION_SUBLEVEL} -le 18; then
		AC_MSG_ERROR([*** Unsupported kernel version $RTEXT_LINUX_VERSION - please upgrade at least to 2.4.19])
	fi
	;;
    2.6.*)
	;;
    *)
	AC_MSG_ERROR([*** Unsupported kernel version $RTEXT_LINUX_VERSION])
	;;
esac

dnl ======================================================================
dnl		import settings from RT-Extension
dnl ======================================================================

# kbuild (linux 2.6) or not
case "${RTEXT_LINUX_VERSION}" in
    2.6.*)
	CONFIG_KBUILD=y
	;;
    *)
	AC_MSG_ERROR([*** internal error])
	;;
esac
AM_CONDITIONAL(CONFIG_KBUILD,[test "$CONFIG_KBUILD" = y])


# common stuff
case "${CONFIG_RTFW_RTEXT_VERSION}" in
    rtai-3x)
        RTEXT_USER_CFLAGS="`${RTAI_CONFIG} --lxrt-cflags`"
        CONFIG_RTNET_RTEXT_ARCH="`${RTAI_CONFIG} --arch`"
        ;;
    xeno-2x)
        RTEXT_USER_CFLAGS="`${XENO_CONFIG} --xeno-cflags`"
        CONFIG_RTFW_RTEXT_ARCH="`${XENO_CONFIG} --arch`"
        RTEXT_LIBRARIES="`${XENO_CONFIG} --library-dir`"
        RTFW_RTEXT_SYMBOLS="`${XENO_CONFIG} --symbol-dir`"
        ;;
    *)
        AC_MSG_ERROR([*** internal error])
        ;;
esac

if test "$CONFIG_KBUILD" = "y"; then
    case "${CONFIG_RTFW_RTEXT_VERSION}" in
        rtai-3x)
            RTEXT_KMOD_CFLAGS="`${RTAI_CONFIG} --module-cflags`"
            ;;
        xeno-2x)
            RTEXT_KMOD_CFLAGS="`${XENO_CONFIG} --module-cflags`"
            ;;
        *)
            AC_MSG_ERROR([*** internal error])
            ;;
    esac
else
    case "${CONFIG_RTFW_RTEXT_VERSION}" in
        rtai-3x)
            RTEXT_KMOD_CFLAGS="`${RTAI_CONFIG} --module-cflags`"
            ;;
        xeno-2x)
            AC_MSG_ERROR([*** internal error])
            ;;
        *)
            AC_MSG_ERROR([*** internal error])
            ;;
    esac
fi

dnl ======================================================================
dnl             architecture tests....
dnl ======================================================================

AC_MSG_CHECKING([for RT-extension target arch])
AC_MSG_RESULT([${CONFIG_RTFW_RTEXT_ARCH}])

AC_MSG_CHECKING([for RT-FireWire target arch])
AC_MSG_RESULT([${RTFW_TARGET_ARCH}])		

if test x"${RTFW_TARGET_ARCH}" != x"${CONFIG_RTFW_RTEXT_ARCH}"; then
    AC_MSG_ERROR([*** RT-extension and RT-FireWire target architectures are not the same])
fi

case "${CONFIG_RTFW_RTEXT_ARCH}" in
    i386)
        AC_DEFINE(CONFIG_ARCH_I386, 1,[we are building for x86])
        ;;
#   ppc)
#      AC_DEFINE(CONFIG_ARCH_PPC, 1, [we are building for powerpc])
#		;;
#	arm)
#		AC_DEFINE(CONFIG_ARCH_ARM, 1, [we are building for arm])
#		;;
#    cris)
#       AC_DEFINE(CONFIG_ARCH_CRIS, 1, [we are trying to build for cris])
#       ;;
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
	\$(MAKE) -C $RTEXT_LINUX_DIR									\
		CROSS_COMPILE=\$(CROSS_COMPILE)								\
		ARCH=\$(RTFW_TARGET_ARCH)								\
		M=\"\`pwd\`\"										\
		V=\$(V)											\
		rtext_dir=\"${RTFW_RTEXT_PREFIX}\"							\
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
   if test -e $RTEXT_LINUX_DIR/Module.symvers; then
	mv $RTEXT_LINUX_DIR/Module.symvers $RTEXT_LINUX_DIR/Module.symvers.let_modpost_be_quiet
   fi
   if test -e $RTEXT_LINUX_DIR/vmlinux; then
	mv $RTEXT_LINUX_DIR/vmlinux $RTFW_LINUX_DIR/vmlinux.let_modpost_be_quiet
   fi
fi

AC_MSG_CHECKING([for kernel module extension])
AC_MSG_RESULT([$RTFW_MODULE_EXT])

AC_SUBST(RTFW_MODULE_EXT)
AC_SUBST(RTFW_KBUILD_ENV)
AC_SUBST(RTFW_KBUILD_CMD)
AC_SUBST(RTFW_KBUILD_CLEAN)

bs_kmodext=$RTFW_MODULE_EXT
bs_kcompile="make -C $RTEXT_LINUX_DIR ARCH=$RTFW_TARGET_ARCH CROSS_COMPILE=$CROSS_COMPILE V=1 M=`pwd` SUBDIRS=`pwd` modules"

dnl ======================================================================
dnl             header checks
dnl ======================================================================

ac_save_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${ac_save_CPPFLAGS} ${RTEXT_KMOD_CFLAGS}"

# Working around some Autoconf ugliness here: names of variables
# stored into the cache are canonicalized, turning /'s into _'s. So if
# you need to match X_Y.h and X/Y.h as different filenames, you are
# toast. Whichever comes first will be cached as "X_Y_h" and the
# second one will never get checked in the fs, but simply
# uncached. This applies to rtai_sem.h and rtai/sem.h for instance.
# To prevent this, we must only check a single set of non-conflicting
# headers, depending on the RTAI version which has been
# identified. (rpm)

BS_CHECK_KHEADERS([rtdm/rtdm.h rtdm/rtdm_driver.h],
    [],
    [AC_MSG_ERROR([*** header not found or working, please check RTAI installation])],
    [
#include <linux/kernel.h>
    ])

if test "${CONFIG_KBUILD}" = "y"; then  # building against linux-2.6
    case "${CONFIG_RTFW_RTEXT_VERSION}" in
        rtai-3x)
            BS_CHECK_KHEADERS([rtai_sem.h rtai_malloc.h rtai_fifos.h],
                [],
                [AC_MSG_ERROR([*** header not found or working, please check RTAI installation])],
                [
#include <linux/kernel.h>
                ])
            ;;
        xeno-2x)
            # nothing further to do
            ;;
        *)
            AC_MSG_ERROR([*** internal error])
            ;;
    esac
else                                  # building against linux-2.4
    case "${CONFIG_RTFW_RTEXT_VERSION}" in
        rtai-3x)    # mandatory RTAI-3 headers
            AC_CHECK_HEADERS([rtai_sem.h rtai_malloc.h],
            [],
            [AC_MSG_ERROR([*** header not found or working, please check RTAI installation])],
            [
#include <linux/kernel.h>
            ])
            ;;
        xeno-2x)
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
dnl             check for LXRT
dnl ======================================================================
case "${CONFIG_RTFW_RTEXT_VERSION}" in
    rtai-3x)
        AC_MSG_CHECKING([for RTAI 3.x LXRT enabled])
        case "${CONFIG_RTAI_SCHED_LXRT}" in
            y | m) CONFIG_RTFW_LXRT=y ;;
            *) CONFIG_RTFW_LXRT=n ;;
        esac
        AC_MSG_RESULT([${CONFIG_RTFW_LXRT}])

        AC_MSG_CHECKING([for CONFIG_REGPARM activated in Linux Kernel])
        if test "${CONFIG_RTFW_LXRT}" = "y" -a "${CONFIG_REGPARM}" = "y"; then
            AC_MSG_WARN([

        *** LXRT interface for RT-FireWire disabled ***
        Please unset CONFIG_RTFW_LXRT for
        ${RTEXT_LINUX_DIR}
        and rebuild your kernel in order to build LXRT interface for RT-FireWire

        ])
            CONFIG_RTFW_LXRT=n
        else
            AC_MSG_RESULT([${CONFIG_REGPARM:-n}])
        fi
        ;;
    xeno-2x) CONFIG_RTNET_LXRT=n
        ;;
    *)
        AC_MSG_ERROR([*** internal error])
        ;;
esac

AM_CONDITIONAL(CONFIG_RTFW_LXRT,[test "$CONFIG_RTFW_LXRT" = "y"])
if test "$CONFIG_RTFW_LXRT" = "y"; then
    AC_DEFINE(CONFIG_RTFW_LXRT, 1, [RTAI LXRT])
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


RTEXT_KMOD_CFLAGS="-D__IN_RTFW__ $RTEXT_KMOD_CFLAGS"
RTEXT_USER_CFLAGS="-D__IN_RTFW__ $RTEXT_USER_CFLAGS"
AC_SUBST(RTEXT_KMOD_CFLAGS)
AC_SUBST(RTEXT_USER_CFLAGS)

dnl ======================================================================
dnl		create links to Makefiles used by linux-2.6.x
dnl ======================================================================
AC_MSG_NOTICE([creating links to Makefiles used by linux-2.6.x])
if test x$CONFIG_KBUILD = xy; then
    for DIR in \
	stack \
	highlevel/bis1394 \
	drivers/ohci \
	drivers/sim \
	rtpkbuff \
	rt_serv \
	rtpc \
	; do
	    AC_CONFIG_LINKS(${DIR}/Makefile:${DIR}/Makefile.kbuild)
	done
fi

dnl ======================================================================
dnl		generate output
dnl ======================================================================
AC_MSG_NOTICE([generating output])

AC_CONFIG_FILES([GNUmakefile \
		include/GNUmakefile \
		highlevel/GNUmakefile \
		highlevel/bis1394/GNUmakefile \
		drivers/GNUmakefile \
		drivers/ohci/GNUmakefile \
		drivers/sim/GNUmakefile \
		rtpkbuff/GNUmakefile \
		rtpc/GNUmakefile \
		rt_serv/GNUmakefile \
		stack/GNUmakefile \
		tools/GNUmakefile \
		])
   
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
