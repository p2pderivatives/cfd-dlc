#!/bin/bash
cmake -S . -B build
pushd build
make -j4
popd
