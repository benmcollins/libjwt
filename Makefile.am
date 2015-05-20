ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include libjwt tests

include $(top_srcdir)/doxygen.mk

clean-local: clean-coverage
	-rm -rf doxygen-doc

if HAVE_GCOV

.PHONY: clean-gcda
clean-gcda:
	@echo Removing old coverage results
	-find -name '*.gcda' -o -name '*.gcno' -print | xargs -r rm

.PHONY: coverage generate-coverage clean-coverage
coverage: clean-gcda
	-$(MAKE) $(AM_MAKEFLAGS) -k check
	$(MAKE) $(AM_MAKEFLAGS) generate-coverage

generate-coverage:
	@echo Collecting coverage data
	$(LCOV) --directory $(top_builddir) --capture --output-file coverage.info --no-checksum --compat-libtool
	LANG=C $(GENHTML) --prefix $(top_builddir) --output-directory coveragereport --title "Code Coverage" --legend --show-details coverage.info

clean-coverage: clean-gcda
	-$(LCOV) --directory $(top_builddir) -z
	-rm -rf coverage.info coveragereport

else

clean-coverage:

endif # HAVE_GCOV
