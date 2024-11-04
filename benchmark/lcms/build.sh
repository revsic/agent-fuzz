#!/bin/bash

if [ -z $WORKDIR ]; then
    WORKDIR=./workspace
fi
# | workspace
#   | src (required)
#     | Little-CMS (repo)
#   | build
#   | lib (required)
#     | liblcms2.so
#   | include (optional)
#     | lcms2.h
#     | lcms2_plugin.h
#   | corpus (optional)
#     | new.icc
#     | ....
#   | dict (optional)
#     | icc.dict

mkdir -p $WORKDIR
# to absolute path
WORKDIR=`realpath $WORKDIR`
pushd $WORKDIR

SRCDIR=$WORKDIR/src
mkdir -p $SRCDIR && pushd $SRCDIR
# clone the project
git clone https://github.com/mm2/Little-CMS
# specify the version
pushd Little-CMS
git checkout lcms2.16

BUILDIR=$WORKDIR/build
mkdir -p $BUILDIR && pushd $BUILDIR
# build
FLAGS="-g -fprofile-instr-generate -fcoverage-mapping"
export CC=clang
export CXX=clang++
export CFLAGS="$CFLAGS $FLAGS"
export CXXFLAGS="$CXXFLAGS $FLAGS"
# prepare install directory
mkdir install
# build
$SRCDIR/Little-CMS/autogen.sh \
    --srcdir=$SRCDIR/Little-CMS \
    --prefix=`realpath ./install`

make -j 4
make install

# copy library
mkdir -p $WORKDIR/lib
cp ./install/lib/liblcms2.so $WORKDIR/lib

# copy header files
mkdir -p $WORKDIR/include
cp ./install/include/*.h $WORKDIR/include/

# $SRCDIR/Little-CMS
popd

# copy corpus
mkdir -p $WORKDIR/corpus
cp ./testbed/*.icc $WORKDIR/corpus
# $SRCDIR
popd

# download dict
mkdir -p $WORKDIR/dict
pushd $WORKDIR/dict
wget https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/refs/heads/stable/dictionaries/icc.dict
# $SRCDIR
popd

# $WORKDIR
popd

popd
