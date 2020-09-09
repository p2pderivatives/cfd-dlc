#!/bin/bash
CFD_VERSION=v0.2.5
wget https://github.com/cryptogarageinc/cfd/releases/download/$CFD_VERSION/cfd-$CFD_VERSION-ubuntu1804-gcc-x86_64.zip
unzip -d / cfd-$CFD_VERSION-ubuntu1804-gcc-x86_64.zip
