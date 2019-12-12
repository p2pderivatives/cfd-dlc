#!/bin/bash
set -e
mkdir build_coverage
cd build_coverage && cmake ../ -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON && make -j4 && ctest -C Debug -R cfddlc_test
make lcov_cfddlc
