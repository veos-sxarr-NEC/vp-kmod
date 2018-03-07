#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([vp-kmod], [1.0.1])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_SUBST(RELEASE)
AC_SUBST([with_kernel], [`uname -r`])
AC_SUBST([with_kernel_mod], [/lib/modules/$with_kernel/extra])
AC_SUBST([KERNEL_SRC], [/lib/modules/$with_kernel/build])
AC_SUBST([KERNEL_MOD], [$with_kernel_mod])
AC_ARG_WITH([release-id], [AS_HELP_STRING([--with-release-id],
            [Specify release id])],
            [RELEASE=${with_release_id}],
            [RELEASE="1"])
AC_DEFINE_UNQUOTED([RELEASE], ["$RELEASE"], [Release Date])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LN_S
LT_INIT
AC_SUBST([LIBTOOL_DEPS])

# Checks for libraries.
# (none)

# Checks for header files.
AC_CHECK_HEADERS([linux/kernel.h])
AC_C_INLINE

# Checks for typedefs, structures, and compiler characteristics.
# Chardev may or may not use these types, I'm just including them
# for illustrative purposes.

# Checks for library functions.
# (none)

# Final output
AC_CONFIG_FILES([Makefile
		 vp-kmod.spec])
AC_OUTPUT
