#!/bin/bash

if [ -z $WORKDIR ]; then
    WORKDIR=./workspace
fi
# | workspace
#   | src (required)
#     | libtiff (repo)
#   | build
#   | lib (required)
#     | libtiff.so
#   | include (optional)
#     | tiff.h
#     | tiffconf.h
#     | ...
#   | corpus (optional)
#     | 32bpp-None-jpeg.tiff
#     | ...
#   | dict (optional)
#     | tiff.dict

mkdir -p $WORKDIR
# to absolute path
WORKDIR=`realpath $WORKDIR`
pushd $WORKDIR

SRCDIR=$WORKDIR/src
mkdir -p $SRCDIR && pushd $SRCDIR
# clone the project
git clone https://gitlab.com/libtiff/libtiff
# specify the version
pushd libtiff
git checkout v4.7.0

BUILDIR=$WORKDIR/build
mkdir -p $BUILDIR && pushd $BUILDIR
# build
FLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CC=clang
export CXX=clang++
export CFLAGS="$CFLAGS $FLAGS"
export CXXFLAGS="$CXXFLAGS $FLAGS"
cmake -DBUILD_SHARED_LIBS=ON $SRCDIR/libtiff
make -j 4

mkdir install
cmake --install . --prefix `realpath ./install`

# copy library
mkdir -p $WORKDIR/lib
cp ./install/lib/libtiff.so $WORKDIR/lib

# copy header files
mkdir -p $WORKDIR/include
cp ./install/include/* $WORKDIR/include
# $SRCDIR/libtiff
popd

# copy corpus
mkdir -p $WORKDIR/corpus
cp test/images/*.tiff $WORKDIR/corpus
# $SRCDIR
popd

# download tiff dict
mkdir -p $WORKDIR/dict
pushd $WORKDIR/dict
wget https://raw.githubusercontent.com/rc0r/afl-fuzz/refs/heads/master/dictionaries/tiff.dict
# $SRCDIR
popd

# $WORKDIR
popd

popd
