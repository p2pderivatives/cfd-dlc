FROM ubuntu:18.04

ENV WORKSPACE /tmp/workspace
WORKDIR ${WORKSPACE}

# install dependencies
RUN apt update && apt install -y \
  gpg \
  wget \
  build-essential \
  python \
  git \
  lcov \
  doxygen \
  graphviz \
  pkg-config \
  unzip \
  && rm -rf /var/lib/apt/lists/*

# install cmake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.15.2/cmake-3.15.2-Linux-x86_64.tar.gz && \
  tar -xvf cmake-3.15.2-Linux-x86_64.tar.gz && \
  cp cmake-3.15.2-Linux-x86_64/bin/* /usr/local/bin && cp -r cmake-3.15.2-Linux-x86_64/share/* /usr/local/share && \
  rm -rf cmake-3.15.2-Linux-x86_64/ cmake-3.15.2-Linux-x86_64.tar.gz

COPY "./scripts/install_cfd.sh" ./
RUN ./install_cfd.sh

# move mount directory
WORKDIR ${WORKSPACE}/cfd-dlc
