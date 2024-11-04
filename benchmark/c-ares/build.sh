#!/bin/bash

if [ -z $WORKDIR ]; then
    WORKDIR=./workspace
fi
# | workspace
#   | src (required)
#     | c-ares (repo)
#   | build
#   | lib (required)
#     | libcares.a
#   | include (optional)
#     | ares.h
#     | ares_build.h
#     | ...
#   | corpus (optional)
#   | dict (optional)

mkdir -p $WORKDIR
# to absolute path
WORKDIR=`realpath $WORKDIR`
pushd $WORKDIR

SRCDIR=$WORKDIR/src
mkdir -p $SRCDIR && pushd $SRCDIR
# clone the project
git clone https://github.com/c-ares/c-ares
# specify the version
pushd c-ares
git checkout v1.34.2

BUILDIR=$WORKDIR/build
mkdir -p $BUILDIR && pushd $BUILDIR
# build
FLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CC=clang
export CXX=clang++
export CFLAGS="$CFLAGS $FLAGS"
export CXXFLAGS="$CXXFLAGS $FLAGS"
cmake -DCARES_STATIC=ON -DCARES_COVERAGE=ON $SRCDIR/c-ares
make -j 4

mkdir install
cmake --install . --prefix `realpath ./install`

# copy library
mkdir -p $WORKDIR/lib
cp ./install/lib/libcares.so $WORKDIR/lib

# copy header files
mkdir -p $WORKDIR/include
cp ./install/include/*.h $WORKDIR/include/

# $SRCDIR/c-ares
popd

# copy corpus
mkdir -p $WORKDIR/corpus
cp ./test/fuzzinput/* ./test/fuzznames/* $WORKDIR/corpus

# $SRCDIR
popd
# $WORKDIR
popd

popd
