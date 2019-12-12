#!/bin/bash
cmake -S . -B build
pushd build
make
popd
