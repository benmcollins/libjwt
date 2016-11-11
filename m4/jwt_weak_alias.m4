dnl This tests whether weak aliases are supported.
AC_DEFUN([WEAK_ALIAS_SUPPORT],
[AC_CACHE_CHECK(whether weak aliases are supported, ac_cv_weak_alias_support,
[AC_TRY_COMPILE([
int get_value(int *value) {
  return *value;
}
int get_value_alias(int *high) __attribute__((__weak__,alias("get_value")));
],
[],
ac_cv_weak_alias_support=yes,
ac_cv_weak_alias_support=no)])
if test $ac_cv_weak_alias_support = no; then
  AC_DEFINE(NO_WEAK_ALIASES,1,[Define if weak aliases are not supported])
fi
])
