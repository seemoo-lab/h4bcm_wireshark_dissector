#!/usr/bin/env bash

mkdir build
cd build || exit
cmake ..
make
make install
