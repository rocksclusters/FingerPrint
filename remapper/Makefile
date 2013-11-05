# The default target of this Makefile is...
all::

# CFLAGS and LDFLAGS are for the users to override from the command line.

CFLAGS = -g -O2 -Wall
LDFLAGS =
ALL_CFLAGS = $(CPPFLAGS) $(CFLAGS)
ALL_LDFLAGS = $(LDFLAGS)
STRIP ?= strip


prefix = /opt/rocks/bin
bindir_relative = bin
bindir = $(prefix)/$(bindir_relative)
mandir = $(prefix)/share/man
infodir = $(prefix)/share/info

export prefix bindir

CC = cc
AR = ar
RM = rm -f
DIFF = diff
TAR = tar
INSTALL = install
RPMBUILD = rpmbuild
PTHREAD_LIBS = -lpthread
PTHREAD_CFLAGS =


PROGRAM_OBJS = 
PROGRAM_OBJS += remapper.o

PROGRAMS += $(patsubst %.o,%$X,$(PROGRAM_OBJS))

# what 'all' will build and 'install' will install in 
# excluding programs for built-in commands
ALL_PROGRAMS = $(PROGRAMS)


ifndef SHELL_PATH
	SHELL_PATH = /bin/sh
endif


ifneq (,$(INLINE))
	BASIC_CFLAGS += -Dinline=$(INLINE)
endif


ifndef CC_LD_DYNPATH
	ifdef NO_R_TO_GCC_LINKER
		# Some gcc does not accept and pass -R to the linker to specify
		# the runtime dynamic library path.
		CC_LD_DYNPATH = -Wl,-rpath,
	else
		CC_LD_DYNPATH = -R
	endif
endif


QUIET_SUBDIR0  = +$(MAKE) -C # space to separate -C and subdir
QUIET_SUBDIR1  =

ifneq ($(findstring $(MAKEFLAGS),w),w)
PRINT_DIR = --no-print-directory
else # "make -w"
NO_SUBDIR = :
endif

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC       = @echo '   ' CC $@;
	QUIET_LINK     = @echo '   ' LINK $@;
	QUIET_BUILT_IN = @echo '   ' BUILTIN $@;
	QUIET_SUBDIR0  = +@subdir=
	QUIET_SUBDIR1  = ;$(NO_SUBDIR) echo '   ' SUBDIR $$subdir; \
			 $(MAKE) $(PRINT_DIR) -C $$subdir
	export V
	export QUIET_GEN
	export QUIET_BUILT_IN
endif
endif

### Build rules


all:: $(ALL_PROGRAMS)
ifneq (,$X)
	$(QUIET_BUILT_IN)$(foreach p,$(patsubst %$X,%,$(filter %$X,$(ALL_PROGRAMS))), test -d '$p' -o '$p' -ef '$p$X' || $(RM) '$p';)
endif

strip: $(PROGRAMS)
	$(STRIP) $(STRIP_OPTS) $^

### Target-specific flags and dependencies

# The generic compilation pattern rule and automatically
# computed header dependencies (falling back to a dependency on
# LIB_H) are enough to describe how most targets should be built,
# but some targets are special enough to need something a little
# different.
#
# - When a source file "foo.c" #includes a generated header file,
#   we need to list that dependency for the "foo.o" target.
#
#   We also list it from other targets that are built from foo.c
#   like "foo.sp" and "foo.s", even though that is easy to forget
#   to do because the generated header is already present around
#   after a regular build attempt.
#
# - Some code depends on configuration kept in makefile
#   variables. The target-specific variable EXTRA_CPPFLAGS can
#   be used to convey that information to the C preprocessor
#   using -D options.
#
#   The "foo.o" target should have a corresponding dependency on
#   a file that changes when the value of the makefile variable
#   changes.  For example, targets making use of the
#   $(REMAPPER_VERSION) variable depend on REMAPPER-VERSION-FILE.
#
#   Technically the ".sp" and ".s" targets do not need this
#   dependency because they are force-built, but they get the
#   same dependency for consistency. This way, you do not have to
#   know how each target is implemented. And it means the
#   dependencies here will not need to change if the force-build
#   details change some day.




OBJECTS := $(PROGRAM_OBJS) 

dep_files := $(foreach f,$(OBJECTS),$(dir $f).depend/$(notdir $f).d)
dep_dirs := $(addsuffix .depend,$(sort $(dir $(OBJECTS))))


ifneq ($(COMPUTE_HEADER_DEPENDENCIES),yes)
ifndef CHECK_HEADER_DEPENDENCIES
dep_dirs =
missing_dep_dirs =
dep_args =
endif
endif

C_OBJ := $(OBJECTS)

.SUFFIXES:

ifdef PRINT_HEADER_DEPENDENCIES
$(C_OBJ): %.o: %.c FORCE
	echo $^

ifndef CHECK_HEADER_DEPENDENCIES
$(error cannot print header dependencies during a normal build. \
Please set CHECK_HEADER_DEPENDENCIES and try again)
endif
endif

ifndef PRINT_HEADER_DEPENDENCIES
ifdef CHECK_HEADER_DEPENDENCIES
$(C_OBJ): %.o: %.c $(dep_files) FORCE
	@set -e; echo CHECK $@; \
	missing_deps="$(missing_deps)"; \
	if test "$$missing_deps"; \
	then \
		echo missing dependencies: $$missing_deps; \
		false; \
	fi

endif
endif

ifndef CHECK_HEADER_DEPENDENCIES
$(C_OBJ): %.o: %.c $(missing_dep_dirs)
	$(QUIET_CC)$(CC) -o $*.o -c $(dep_args) $(ALL_CFLAGS) $(EXTRA_CPPFLAGS) $<
endif

%.s: %.c FORCE
	$(QUIET_CC)$(CC) -o $@ -S $(ALL_CFLAGS) $(EXTRA_CPPFLAGS) $<

%$X: %.o  $(REMAPPERLIBS)
	        $(QUIET_LINK)$(CC) $(ALL_CFLAGS) -o $@ $(ALL_LDFLAGS) $(filter %.o,$^) $(LIBS)



ifdef USE_COMPUTED_HEADER_DEPENDENCIES
# Take advantage of gcc's on-the-fly dependency generation
# See <http://gcc.gnu.org/gcc-3.0/features.html>.
dep_files_present := $(wildcard $(dep_files))
ifneq ($(dep_files_present),)
include $(dep_files_present)
endif
else
# Dependencies on header files, for platforms that do not support
# the gcc -MMD option.
#
# Dependencies on automatically generated headers such as common-cmds.h
# should _not_ be included here, since they are necessary even when
# building an object for the first time.

$(OBJECTS): $(LIB_H)
endif

tags: FORCE
	$(RM) tags
	$(FIND_SOURCE_FILES) | xargs ctags -a


### Maintainer's dist rules

remapper.spec: remapper.spec.in REMAPPER-VERSION-FILE
	sed -e 's/@@VERSION@@/$(REMAPPER_VERSION)/g' < $< > $@+
	mv $@+ $@

REMAPPER_TARNAME = remapper-$(REMAPPER_VERSION)
dist: remapper.spec remapper-archive$(X) configure
	./remapper-archive --format=tar \
		--prefix=$(REMAPPER_TARNAME)/ HEAD^{tree} > $(REMAPPER_TARNAME).tar
	@mkdir -p $(REMAPPER_TARNAME)
	@cp remapper.spec configure $(REMAPPER_TARNAME)
	@echo $(REMAPPER_VERSION) > $(REMAPPER_TARNAME)/version
	$(TAR) rf $(REMAPPER_TARNAME).tar \
		$(REMAPPER_TARNAME)/remapper.spec \
		$(REMAPPER_TARNAME)/version \
	@$(RM) -r $(REMAPPER_TARNAME)
	gzip -f -9 $(REMAPPER_TARNAME).tar

rpm: dist
	$(RPMBUILD) \
		--define "_source_filedigest_algorithm md5" \
		--define "_binary_filedigest_algorithm md5" \
		-ta $(REMAPPER_TARNAME).tar.gz


### Cleaning rules

distclean: clean
	$(RM) somefile


clean: 
	$(RM) *.o *.res 
	$(RM) $(ALL_PROGRAMS) $X

.PHONY: all install clean strip
.PHONY: FORCE cscope


