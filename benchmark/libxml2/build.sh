#!/bin/bash

if [ -z $WORKDIR ]; then
    WORKDIR=./workspace
fi
# | workspace
#   | src (required)
#     | libxml2 (repo)
#   | build
#   | lib (required)
#     | libxml2.a
#   | include (optional)
#     | libxml
#       | c14n.h
#       | catalog.h
#       | ...
#   | corpus (optional)
#     | 4rects.xml
#     | 21.xml
#     | ...
#   | dict (optional)
#     | xml.dict

mkdir -p $WORKDIR
# to absolute path
WORKDIR=`realpath $WORKDIR`
pushd $WORKDIR

SRCDIR=$WORKDIR/src
mkdir -p $SRCDIR && pushd $SRCDIR
# clone the project
git clone https://github.com/GNOME/libxml2
# specify the version
pushd libxml2
git reset --hard HEAD
git checkout v2.9.4

BUILDIR=$WORKDIR/build
mkdir -p $BUILDIR && pushd $BUILDIR
# build
FLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CC=clang
export CFLAGS="$CFLAGS $FLAGS"
# prepare install directory
mkdir install
# build
$SRCDIR/libxml2/autogen.sh \
    --srcdir=$SRCDIR/libxml2 \
    --prefix=`realpath ./install` \
    --without-debug \
    --without-http \
    --without-python \
    --with-zlib \
    --with-lzma
make -j 4
make install

# copy library
mkdir -p $WORKDIR/lib
cp install/lib/libxml2.so $WORKDIR/lib

# copy header files
mkdir -p $WORKDIR/include
cp -r install/include/libxml2/libxml/ $WORKDIR/include

# $SRCDIR/libxml2
popd

# copy corpus
mkdir -p $WORKDIR/corpus
find test -type f -name "*.xml" | xargs -I {} cp {} ${WORKDIR}/corpus
# $SRCDIR
popd

# download xml dict
mkdir -p $WORKDIR/dict
pushd $WORKDIR/dict
wget https://raw.githubusercontent.com/rc0r/afl-fuzz/refs/heads/master/dictionaries/xml.dict
# $SRCDIR
popd

# $WORKDIR
popd

popd
