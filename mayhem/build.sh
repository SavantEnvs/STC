#!/usr/bin/env bash
#
# mayhem/build.sh — build STC's fuzz harnesses (sanitized) and its own test suite (normal flags).
# Runs inside the commit image as `mayhem` in /mayhem; re-runnable and offline (no dependencies
# beyond libc/libm).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) The library itself, instrumented: every translation unit upstream's Makefile puts into
#    libstc.a (LIB_LIST), compiled with the sanitizer + DWARF-3 flags into build-fuzz/ (gitignored
#    by upstream's `build*/`).
LIB_LIST="cstr_core cstr_misc cstr_io cstr_utf8 utf8_misc cregex csview cspan fmt random stc_core"
FUZZ_CFLAGS="-std=c11 -O1 -Iinclude $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
mkdir -p build-fuzz/obj
objs=()
for f in $LIB_LIST; do
  $CC $FUZZ_CFLAGS -c "src/$f.c" -o "build-fuzz/obj/$f.o"
  objs+=("build-fuzz/obj/$f.o")
done
rm -f build-fuzz/libstc_fuzz.a
ar rcs build-fuzz/libstc_fuzz.a "${objs[@]}"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o build-fuzz/obj/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build-fuzz/obj/standalone_main.o

# 2) Each harness twice: libFuzzer binary and run-once standalone reproducer.
for h in cregex cstr csview seqcont assoc fmt cbits; do
  $CC $FUZZ_CFLAGS -c "mayhem/harnesses/fuzz_$h.c" -o "build-fuzz/obj/fuzz_$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build-fuzz/obj/fuzz_$h.o" \
      build-fuzz/obj/lsan_off.o build-fuzz/libstc_fuzz.a -lm -o "/mayhem/fuzz_$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS build-fuzz/obj/standalone_main.o "build-fuzz/obj/fuzz_$h.o" \
      build-fuzz/obj/lsan_off.o build-fuzz/libstc_fuzz.a -lm -o "/mayhem/fuzz_$h-standalone"
done

# 3) Upstream's own test suite (tests/*_test.c via ctest.h) with upstream's normal Makefile flags,
#    into build/Linux_<cc>/ — test.sh runs it.
env -u CFLAGS -u LDFLAGS make -j"$MAYHEM_JOBS" --no-print-directory CC="$CC" lib-slow
env -u CFLAGS -u LDFLAGS make -j"$MAYHEM_JOBS" --no-print-directory CC="$CC" "build/$(uname)_$CC/tests/test_all"
