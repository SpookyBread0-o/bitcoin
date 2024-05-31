package=libevent
$(package)_version=fc9bfd210d289d1565cf03e3d9d2e85f50f5b144
$(package)_download_path=https://github.com/libevent/libevent/archive
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=5457907404df32dd35436004f3b94e64b3cdf1320c274411803404933732788c
$(package)_build_subdir=build

# When building for Windows, we set _WIN32_WINNT to target the same Windows
# version as we do in configure. Due to quirks in libevents build system, this
# is also required to enable support for ipv6. See #19375.
define $(package)_set_vars
  $(package)_config_opts=-DEVENT__DISABLE_BENCHMARK=ON -DEVENT__DISABLE_OPENSSL=ON
  $(package)_config_opts+=-DEVENT__DISABLE_SAMPLES=ON -DEVENT__DISABLE_REGRESS=ON
  $(package)_config_opts+=-DBUILD_TESTING=OFF -DEVENT__LIBRARY_TYPE=STATIC
  $(package)_cppflags_mingw32=-D_WIN32_WINNT=0x0601
  $(package)_config_opts_debug+=-DEVENT__DISABLE_DEBUG_MODE=ON

  ifeq ($(NO_HARDEN),)
  $(package)_cppflags+=-D_FORTIFY_SOURCE=3
  endif
endef

define $(package)_config_cmds
  $($(package)_cmake) -S .. -B .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm include/ev*.h && \
  rm include/event2/*_compat.h
endef
