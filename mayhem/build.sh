#!/usr/bin/env bash
#
# mayhem/build.sh — build SSSD's fuzz harnesses and the cmocka tests test.sh runs.
#
# Two out-of-tree autotools builds under build/ (gitignored by upstream's .gitignore):
#   build/fuzz  the project sanitized ($SANITIZER_FLAGS + SanCov + DWARF 3); the harnesses link its
#               libsss_certmap / libsss_idmap / libsss_util shared libs via an rpath into build/fuzz.
#   build/test  the project with normal flags; builds the upstream cmocka suites test.sh runs.
# Re-runnable (configure only when its Makefile is missing) and offline (deps are apt packages).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

CONFIGURE_OPTS=(
    --without-manpages --without-python3-bindings --without-selinux
    --disable-cifs-idmap-plugin --without-nfsv4-idmapd-plugin --without-samba
    --with-passkey --disable-systemtap
)

# autoreconf output (configure, Makefile.in, ...) is gitignored upstream, so it is regenerated
# after a `git clean -ffdX`.
[ -x configure ] || autoreconf -if

# SanCov for the project libraries only when the sanitizer build is on (fuzzer-no-link needs no
# runtime of its own: the harness link brings libFuzzer).
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
case "$LIB_FUZZING_ENGINE" in *fuzzer*) FUZZ_CFLAGS="$FUZZ_CFLAGS -fsanitize=fuzzer-no-link";; esac

# 1) Sanitized project build (only the libraries the harnesses use).
mkdir -p build/fuzz
if [ ! -f build/fuzz/Makefile ]; then
    (cd build/fuzz && ../../configure CC="$CC" CFLAGS="$FUZZ_CFLAGS" LDFLAGS="$SANITIZER_FLAGS" --enable-static \
        "${CONFIGURE_OPTS[@]}")
fi
make -C build/fuzz -j"$MAYHEM_JOBS" libsss_certmap.la libsss_idmap.la libsss_util.la libsss_debug.la libsss_cert.la

# 2) Harnesses: a libFuzzer binary and a run-once -standalone reproducer each.
B="$SRC/build/fuzz"
HCFLAGS=(-I"$B" -I"$SRC/src" -I"$SRC" -include "$B/config.h" $(pkg-config --cflags talloc tevent ldb dhash))
HLDFLAGS=(-L"$B/.libs" -Wl,-rpath,"$B/.libs")
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

build_harness() {
    local name="$1"; shift
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${HCFLAGS[@]}" -c "$SRC/mayhem/harnesses/$name.c" -o "$B/$name.o"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$name.o" "$B/lsan_off.o" \
        "${HLDFLAGS[@]}" "$@" -o "$SRC/$name"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/standalone_main.o" "$B/$name.o" "$B/lsan_off.o" \
        "${HLDFLAGS[@]}" "$@" -o "$SRC/$name-standalone"
}
build_harness fuzz_certmap_rule -lsss_certmap -ltalloc
build_harness fuzz_certmap_cert -lsss_certmap -ltalloc
build_harness fuzz_idmap_sid -lsss_idmap
build_harness fuzz_authtok -lsss_util -lsss_debug -ltalloc
build_harness fuzz_cert_ssh -lsss_cert -lsss_util -lsss_debug -ltalloc

# 2b) Responder harnesses (PAM, NSS). Each links the same responder objects as upstream's cmocka
#     test program (pam-srv-tests: src/tests/cmocka/test_pam_srv.c, nss-srv-tests: test_nss_srv.c)
#     minus the test itself, the cmocka data-provider mocks and the sbus-backed pamsrv_dp.c, which
#     mayhem/harnesses/pam_dp_stubs.c replaces; resp_fuzz_common.c holds their shared set-up and
#     per-input reset. The object and library list is read from the generated Makefile's link rule
#     of that test program, so it follows upstream.
# SSSD's private libraries each carry a copy of src/util/debug.c, so loading several of them as
# shared objects is an ASan ODR violation (debug_prg_name): link them from their static archives
# (configure --enable-static above). libsss_certmap/libsss_idmap hide their copy behind a version
# script and stay shared. libtool moves -Wl,--start-group away from the archives and drops a repeated
# archive, so the archives are given a second time by absolute path to resolve their cross references.
PAM_HCFLAGS=(-DHAVE_CONFIG_H -I"$B" -I"$B/src" -I"$SRC/src" -I"$SRC" -I"$SRC/src/sss_client"
    -isystem /usr/include/mit-krb5 $(pkg-config --cflags talloc tevent ldb dhash dbus-1)
    -DMEMBEROF_SO="\"$B/.libs/memberof.so\"" -DRESP_FUZZ_SCRATCH="\"$B/fuzz-scratch\""
    -DRESP_FUZZ_LDB_MODULES="\"$B/fuzz-ldb-modules\"")
PAM_SYSLIBS="$(pkg-config --libs talloc tevent ldb dhash dbus-1 ini_config) -ltdb -lpopt -lcap -lpcre2-8 -lcrypto -lunistring -lgssapi_krb5 -ljansson -lpam -lcmocka"
make -C "$B" -j"$MAYHEM_JOBS" memberof.la libsss_cert.la
# Run-time dirs of the responder harnesses, made here so the harness needs no writable /tmp or
# working directory: the scratch dir for its confdb/sysdb (world-writable, in case Mayhem runs the
# binary as another user) and the ldb module dir with SSSD's memberof module.
mkdir -p "$B/fuzz-scratch" "$B/fuzz-ldb-modules"
chmod 1777 "$B/fuzz-scratch"
ln -sfn "$B/.libs/memberof.so" "$B/fuzz-ldb-modules/memberof.so"
for f in pam_dp_stubs resp_fuzz_common; do
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${PAM_HCFLAGS[@]}" -c "$SRC/mayhem/harnesses/$f.c" -o "$B/$f.o"
done
build_responder_harness() {
    local name="$1" prog="$2"; shift 2   # remaining args: objects of $prog to leave out
    local link objs las libs="" again="" l
    link=$(make -s -C "$B" -n "$prog" | grep -- "-o $prog" | tail -n1)
    objs=$(printf '%s\n' $link | grep '^src/.*\.o$' | grep -v "${@/#/-e}" | tr '\n' ' ')
    las=$(printf '%s\n' $link | grep '\.la$' | tr '\n' ' ')
    las="$las ${NSS_EXTRA_LIBS:-}"
    make -C "$B" -j"$MAYHEM_JOBS" $objs $las
    for l in $las; do
        case "$l" in
            *libsss_certmap.la|*libsss_idmap.la) libs="$libs $l" ;;
            *) libs="$libs $(dirname "$l")/.libs/$(basename "$l" .la).a"
               again="$again $B/$(dirname "$l")/.libs/$(basename "$l" .la).a" ;;
        esac
    done
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${PAM_HCFLAGS[@]}" -c "$SRC/mayhem/harnesses/$name.c" -o "$B/$name.o"
    (cd "$B" && ./libtool --tag=CC --mode=link $CXX -no-install $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
        -o "$SRC/$name" $name.o pam_dp_stubs.o resp_fuzz_common.o lsan_off.o $objs \
        $libs .libs/libsss_cert.a $again $PAM_SYSLIBS)
    (cd "$B" && ./libtool --tag=CC --mode=link $CXX -no-install $SANITIZER_FLAGS $DEBUG_FLAGS \
        -o "$SRC/$name-standalone" standalone_main.o $name.o pam_dp_stubs.o resp_fuzz_common.o lsan_off.o $objs \
        $libs .libs/libsss_cert.a $again $PAM_SYSLIBS)
}
build_responder_harness fuzz_pam_cmd pam-srv-tests 'test_pam_srv\.o$' 'common_mock_resp_dp\.o$' 'pamsrv_dp\.o$'
# nss-srv-tests gets bin_to_ldap_filter_value (used by sysdb_ops.c) from libsss_certmap via a shared libsss_cert.
make -C "$B" -j"$MAYHEM_JOBS" libsss_certmap.la
NSS_EXTRA_LIBS=libsss_certmap.la build_responder_harness fuzz_nss_cmd nss-srv-tests 'test_nss_srv\.o$' 'common_mock_resp_dp\.o$'

# 3) Test build with the project's normal flags: upstream's cmocka suites for the fuzzed code.
mkdir -p build/test
if [ ! -f build/test/Makefile ]; then
    (cd build/test && env -u CFLAGS -u LDFLAGS ../../configure CC="$CC" \
        CFLAGS="-O2 -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" "${CONFIGURE_OPTS[@]}")
fi
# the certmap tests include headers generated from the committed test CA keys (openssl, softhsm2)
make -C build/test test_CA
make -C build/test -j"$MAYHEM_JOBS" sss_certmap_test test_sss_idmap test-authtok
