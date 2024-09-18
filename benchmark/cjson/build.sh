#!/bin/bash

PROJECT="cjson"
# | workspace
#   | src
#     | cJSON (repo)
#   | build
#   | lib
#     | libcjson.a
#   | include
#     | cJSON.h
#   | corpus
#   | dict
#     | json.dict

WORKDIR=./$PROJECT/workspace
mkdir -p $WORKDIR
# to absolute path
WORKDIR=`realpath $WORKDIR`
pushd $WORKDIR

SRCDIR=$WORKDIR/src
mkdir -p $SRCDIR && pushd $SRCDIR
# clone the project
git clone https://github.com/DaveGamble/cJSON
# specify the version
pushd cJSON
git checkout v1.7.18

BUILDIR=$WORKDIR/build
mkdir -p $BUILDIR && pushd $BUILDIR
# build
FLAGS="-g -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer-no-link -fno-sanitize=undefined,address"
export CC=clang
export CXX=clang++
export CFLAGS="$CFLAGS $FLAGS"
export CXXFLAGS="$CXXFLAGS $FLAGS"
cmake -DBUILD_SHARED_AND_STATIC_LIBS=ON -DENABLE_CJSON_TEST=OFF $SRCDIR/cJSON
make -j 4

mkdir -p $WORKDIR/lib
cp libcjson.a $WORKDIR/lib
# $SRCDIR/cJSON
popd

pwd

# copy header files
mkdir -p $WORKDIR/include
cp cJSON.h $WORKDIR/include

# copy corpus
mkdir -p $WORKDIR/corpus
cp fuzzing/inputs/* $WORKDIR/corpus

# copy dict
mkdir -p $WORKDIR/dict
cp fuzzing/json.dict $WORKDIR/dict

# $SRCDIR
popd
# $WORKDIR
popd

popd
