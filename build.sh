#!/bin/sh
# ETAP 参考实现与接口验证构建脚本
# 依赖系统自带 gcc（本机为 GCC 14.2）；不要求 make/cmake。
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"
CFLAGS="-std=c11 -O2 -g -Wall -Wextra -pthread -I$ROOT"

# -fPIC so the same object can be linked into libetap.so and the test binary.
gcc $CFLAGS -fPIC -c "$ROOT/src/etap.c" -o "$BUILD/etap.o"
gcc $CFLAGS -shared -fPIC "$BUILD/etap.o" -o "$BUILD/libetap.so"
gcc $CFLAGS "$ROOT/tests/test_etap.c" "$BUILD/etap.o" -o "$BUILD/test_etap"
echo "已生成 $BUILD/test_etap"
echo "已生成 $BUILD/libetap.so"
