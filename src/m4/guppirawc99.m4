# serial 1 guppirawc99.m4
AC_DEFUN([AX_CHECK_GUPPIRAWC99], [
  AC_PREREQ([2.65])dnl

  AC_ARG_WITH([guppirawc99],
            AC_HELP_STRING([--with-guppirawc99=DIR],
                           [Location of GUPPIRAWC99 install directory]),
            [
              GUPPIRAWC99DIR="$withval"
              has_guppiraw=1
            ],
            [
              GUPPIRAWC99DIR=""
              has_guppiraw=0
            ])


  if test $has_guppiraw = 0; then
    AC_MSG_NOTICE([Library GUPPIRAWC99 not provided. GUPPIRAW will not be linked.])
    guppirawc99_enabled=0;
  else
    # test guppirawc99 before enabling

    AC_CHECK_FILE([${GUPPIRAWC99DIR}/include/guppirawc99.h],
                  # Found
                  AC_SUBST(GUPPIRAWC99_INCDIR,${GUPPIRAWC99DIR}/include),
                  # Not found there, check GUPPIRAWC99DIR
                  AC_CHECK_FILE([${GUPPIRAWC99DIR}/../include/guppirawc99.h],
                                # Found
                                AC_SUBST(GUPPIRAWC99_INCDIR,${GUPPIRAWC99DIR}/../include),
                                # Not found there, error
                                AC_MSG_ERROR([guppirawc99.h header file not found])
                  )
    )

    AC_CHECK_FILE([${GUPPIRAWC99DIR}/lib/libguppirawc99.so],
                  # Found
                  GUPPIRAWC99_LIBDIR="${GUPPIRAWC99DIR}/lib",
                  # Not found there
                  AC_CHECK_FILE([${GUPPIRAWC99DIR}/lib/x86_64-linux-gnu/libguppirawc99.so],
                                # Found
                                GUPPIRAWC99_LIBDIR="${GUPPIRAWC99DIR}/lib/x86_64-linux-gnu/",
                                # Not found there, error
                                AC_MSG_ERROR([libguppirawc99.so not found])
                  )
    )

    # orig_LDFLAGS="${LDFLAGS}"
    # LDFLAGS="${orig_LDFLAGS} -L${GUPPIRAWC99_LIBDIR}/"
    # AC_CHECK_LIB([guppirawc99], [guppiraw_write_block_arbitrary],
    #             # Found
    #             AC_SUBST(GUPPIRAWC99_LIBDIR,${GUPPIRAWC99_LIBDIR}/),
    #             # Not found there, check under lib
    #             AC_MSG_ERROR([GUPPIRAWC99 library invalid under $GUPPIRAWC99_LIBDIR/])
    # )
    # LDFLAGS="${orig_LDFLAGS}"
    AC_SUBST(GUPPIRAWC99_LIBDIR,${GUPPIRAWC99_LIBDIR}/)

    guppirawc99_enabled=1;
  fi

  AS_IF([test $guppirawc99_enabled = 1],
    [
      AM_CONDITIONAL(GUPPIRAWC99_ENABLED, true)
      AC_DEFINE(GUPPIRAWC99_ENABLED,[],[Use GUPPIRAWC99])
      AC_MSG_NOTICE([GUPPIRAWC99 will be enabled.])
    ],
    [
      AM_CONDITIONAL(GUPPIRAWC99_ENABLED, false)
    ]
  )
])
