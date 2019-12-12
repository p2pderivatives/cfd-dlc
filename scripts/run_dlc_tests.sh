#!/bin/bash
pushd build
ctest -C Release -R dlc_test
popd
