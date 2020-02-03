# cfd-dlc
Library for creating and managing Discrete Logarithm Contracts (DLC)

## build

### full build
```
./scripts/build.sh
```

### quick build (use installed cfd)

use pkg-config.

- macos: `brew install pkg-config`

1. install cfd. (on initial or update only.)
```
git clone git@github.com:cryptogarageinc/cfd.git v0.0.10
cmake -S . -B build
cmake -DENABLE_SHARED=on -DENABLE_JS_WRAPPER=off -DENABLE_TESTS=off -DTARGET_RPATH=/usr/local/lib -DCMAKE_BUILD_TYPE=Release --build build
cmake --build build --parallel 4 --config Release
cd build && sudo make install -j 4
(or cmake --install build)

attention: support is shared library only.
```

update installed library, need cleanup installed file. script:
  `https://github.com/cryptogarageinc/cfd/blob/master/tools/cleanup_install_files.sh`

2. build cfd-dlc (on clean state)
```
./scripts/build.sh
```
