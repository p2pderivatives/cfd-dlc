#!/bin/bash
set -e
pushd build/Release
./cfddlc_test
popd
