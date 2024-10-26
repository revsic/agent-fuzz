#!/bin/bash

if [ -z $WORKDIR ]; then
    WORKDIR=./workspace
fi
# | workspace
#   | src (required)
#     | aom (repo)
#   | build
#   | lib (required)
#     | libaom.so
#   | include (optional)
#     | aom
#       | aom_codec.h
#       | ...
#   | corpus (optional)
#     | ...
#   | dict (optional)

mkdir -p $WORKDIR
# to absolute path
WORKDIR=`realpath $WORKDIR`
pushd $WORKDIR

SRCDIR=$WORKDIR/src
mkdir -p $SRCDIR && pushd $SRCDIR
# clone the project
git clone https://aomedia.googlesource.com/aom
# specify the version
pushd aom
git checkout v3.10.0

BUILDIR=$WORKDIR/build
mkdir -p $BUILDIR && pushd $BUILDIR
# build
FLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CC=clang
export CXX=clang++
export CFLAGS="$CFLAGS $FLAGS"
export CXXFLAGS="$CXXFLAGS $FLAGS"
cmake -DBUILD_SHARED_LIBS=ON $SRCDIR/aom
make -j 4

mkdir install
cmake --install . --prefix `realpath ./install`

# copy library
mkdir -p $WORKDIR/lib
cp ./install/lib/libaom.so $WORKDIR/lib

# copy header files
mkdir -p $WORKDIR/include/aom
cp ./install/include/aom/* $WORKDIR/include/aom

# $SRCDIR/aom
popd

# copy corpus
mkdir -p $WORKDIR/corpus
pushd $WORKDIR/corpus
# download
wget https://storage.googleapis.com/aom-test-data/fuzzer/dec_fuzzer_seed_corpus.zip 
# unzip
unzip dec_fuzzer_seed_corpus.zip
mv testdata/* .
# clean
rm dec_fuzzer_seed_corpus.zip
rmdir testdata
# $SRCDIR
popd

# $WORKDIR
popd

popd
