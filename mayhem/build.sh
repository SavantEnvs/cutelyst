#!/usr/bin/env bash
#
# mayhem/build.sh — build Cutelyst's fuzz harnesses (sanitized) and its QtTest suite (normal flags).
#
# Runs inside the commit image as `mayhem` in /mayhem; the base image exports CC/CXX,
# SANITIZER_FLAGS, LIB_FUZZING_ENGINE, STANDALONE_FUZZ_MAIN. Qt 6 comes from Debian's packages
# (installed in mayhem/Dockerfile); nothing is fetched here, so a re-run is air-gapped.
#
# Outputs:
#   build-fuzz/<target> and build-fuzz/<target>-standalone   (Mayhemfiles point at these)
#   build-tests/                                              (upstream ctest suite, run by test.sh)
#
# Upstream adds `-stdlib=libc++` to CMAKE_CXX_FLAGS when the compiler is clang, but Debian's Qt is
# built against libstdc++; `-stdlib=libstdc++` in CMAKE_CXX_FLAGS_<CONFIG> comes later on every
# compile and link line, so it wins and keeps the ABI consistent with Qt. No upstream file is edited.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Relaxed UBSan check (only when sanitizers are on): `alignment`. The server reads big-endian
# integers straight out of its byte buffers (Cutelyst/Server/protocol.h net_be32/net_be16,
# used by the HTTP/2 SETTINGS/PRIORITY and FastCGI name/value-length parsers), so every HTTP/2
# SETTINGS frame is a misaligned load — harmless on x86, and it would stop every input there.
# ASan and the rest of UBSan stay on and halting.
FUZZ_SAN_FLAGS="$SANITIZER_FLAGS"
[ -z "$FUZZ_SAN_FLAGS" ] || FUZZ_SAN_FLAGS="$FUZZ_SAN_FLAGS -fno-sanitize=alignment"

common=(
  -DBUILD_SHARED_LIBS=OFF
  -DBUILD_EXAMPLES=OFF
  -DBUILD_DOCS=OFF
  -DUSE_MIMALLOC=OFF
  -DUSE_JEMALLOC=OFF
)

# QT_FORCE_ASSERTS: Qt6::Core adds QT_NO_DEBUG for every non-Debug config, which would compile out
# all of Cutelyst's Q_ASSERT/Q_ASSERT_X (and Qt's inline container bounds asserts). Forcing them
# on keeps those contract checks live; the harnesses' quiet message handler turns qFatal into abort().
#
# 1) Fuzz build: upstream libraries (Core, Server, StaticSimple, Validator, ...) as static libs,
#    compiled with the sanitizers + SanCov, and the harnesses from mayhem/CMakeLists.txt.
cmake -S mayhem -B build-fuzz \
  -DCMAKE_BUILD_TYPE=Fuzz \
  -DCMAKE_C_FLAGS="$FUZZ_SAN_FLAGS -fsanitize=fuzzer-no-link" \
  -DCMAKE_CXX_FLAGS="$FUZZ_SAN_FLAGS -fsanitize=fuzzer-no-link -DQT_FORCE_ASSERTS" \
  -DCMAKE_C_FLAGS_FUZZ="-O1 $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS_FUZZ="-O1 $DEBUG_FLAGS -stdlib=libstdc++" \
  -DBUILD_TESTS=OFF \
  -DFUZZ_ENGINE_FLAGS="$LIB_FUZZING_ENGINE" \
  -DSTANDALONE_MAIN="$STANDALONE_FUZZ_MAIN" \
  -DLSAN_OFF_SRC="$SRC/mayhem/lsan_off.cc" \
  "${common[@]}"
cmake --build build-fuzz -j"$MAYHEM_JOBS"

# 2) Test build: upstream's QtTest suite as upstream CI runs it (Debug, so Q_ASSERTs are live;
#    the plugins BUILD_ALL would add that have tests: CSRFProtection, StaticCompressed, Memcached —
#    testmemcached starts its own memcached from the Dockerfile's apt package). No sanitizers.
cmake -S . -B build-tests \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_CXX_FLAGS_DEBUG="-g -stdlib=libstdc++" \
  -DBUILD_TESTS=ON \
  -DPLUGIN_CSRFPROTECTION=ON \
  -DPLUGIN_STATICCOMPRESSED=ON \
  -DPLUGIN_MEMCACHED=ON \
  "${common[@]}"
cmake --build build-tests -j"$MAYHEM_JOBS"
