#!/bin/bash
mkdir build_coverage
cd build_coverage && cmake ../ -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON && make -j4 && ctest -C Debug
make lcov_cfddlc
