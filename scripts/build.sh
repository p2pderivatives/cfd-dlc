#!/bin/bash
cmake -S . -B build
pushd build
make -j 4
popd
