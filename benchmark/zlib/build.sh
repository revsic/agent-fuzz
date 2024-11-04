#!/bin/bash

if [ -z $WORKDIR ]; then
    WORKDIR=./workspace
fi
# | workspace
#   | src (required)
#     | zlib (repo)
#   | build
#   | lib (required)
#     | libz.a
#   | include (optional)
#     | zconf.h
#     | zlib.h
#   | corpus (optional)
#   | dict (optional)

mkdir -p $WORKDIR
# to absolute path
WORKDIR=`realpath $WORKDIR`
pushd $WORKDIR

SRCDIR=$WORKDIR/src
mkdir -p $SRCDIR && pushd $SRCDIR
# clone the project
git clone https://github.com/madler/zlib
# specify the version
pushd zlib
git checkout v1.3.1

BUILDIR=$WORKDIR/build
mkdir -p $BUILDIR && pushd $BUILDIR
# build
FLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CC=clang
export CXX=clang++
export CFLAGS="$CFLAGS $FLAGS"
export CXXFLAGS="$CXXFLAGS $FLAGS"
cmake $SRCDIR/zlib
make -j 4

mkdir -p $WORKDIR/lib
cp libz.a $WORKDIR/lib

# copy header files
mkdir -p $WORKDIR/include
cp zconf.h $WORKDIR/include
cp $SRCDIR/zlib/zlib.h $WORKDIR/include

# $SRCDIR/zlib
popd

# copy corpus
mkdir -p $WORKDIR/corpus
cp *.* $WORKDIR/corpus
zip $WORKDIR/corpus/corpus.zip *.*

# $SRCDIR
popd
# $WORKDIR
popd

popd
