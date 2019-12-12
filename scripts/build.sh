#!/bin/bash
set -e
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
pushd build
make -j 4
popd
