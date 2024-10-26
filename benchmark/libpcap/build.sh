#!/bin/bash

if [ -z $WORKDIR ]; then
    WORKDIR=./workspace
fi
# | workspace
#   | src (required)
#     | libpcap (repo)
#     | tcpdump (repo)
#   | build
#   | lib (required)
#     | libpcap.a
#   | include (optional)
#     | pcap
#       | ...
#     | pcap-bpf.h
#     | pcap-namedb.h
#     | pcap.h
#   | corpus (optional)
#     | 02-sunrise-sunset-esp.pcap
#     | 08-sunrise-sunset-aes.pcap
#     | ...

mkdir -p $WORKDIR
# to absolute path
WORKDIR=`realpath $WORKDIR`
pushd $WORKDIR

SRCDIR=$WORKDIR/src
mkdir -p $SRCDIR && pushd $SRCDIR
# clone the project
git clone https://github.com/the-tcpdump-group/libpcap
# specify the version
pushd libpcap
git checkout 9145d31bcc40bc7b656a06304998f111a88b4591  # 1.11.0-pre

BUILDIR=$WORKDIR/build
mkdir -p $BUILDIR && pushd $BUILDIR
# build
FLAGS="-g -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer-no-link -fno-sanitize=undefined,address"
export CC=clang
export CXX=clang++
export CFLAGS="$CFLAGS $FLAGS"
export CXXFLAGS="$CXXFLAGS $FLAGS"
cmake -DBUILD_WITH_LIBNL=off -DENABLE_REMOTE=off -DDISABLE_RDMA=on $SRCDIR/libpcap
make -j 4

# install to a temporal directory
mkdir install
cmake --install . --prefix `realpath ./install`

# copy library
mkdir -p $WORKDIR/lib
cp install/lib/libpcap.a $WORKDIR/lib

# copy header files
mkdir -p $WORKDIR/include
cp -r install/include/* $WORKDIR/include
# $SRCDIR/libpcap
popd
# $SRCDIR
popd

# copy corpus
mkdir -p $WORKDIR/corpus
git clone https://github.com/the-tcpdump-group/tcpdump
cp ./tcpdump/tests/*.pcap $WORKDIR/corpus

# $WORKDIR
popd

popd
