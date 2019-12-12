TESTS=test_dlc
noinst_PROGRAMS=test_dlc

# for common
if DEBUG
OPT = -g3 -O0
else
OPT = -O3
endif
CFLAGS= -Wall $(OPT)
CPPFLAGS= $(CFLAGS) -std=c++11
CXXFLAGS= $(CFLAGS) -std=c++11

dlc_all: dlc

dlc_clean: dlc_clean

PATH_CFDCORE= ../../cfd-core

if TARGET_WINDOWS
# Windows option
LIB_OPTS= $(PATH_CFDCORE)/test/googletest/googletest/lib/.libs/libgtest.a \
          $(PATH_CFDCORE)/test/googletest/googletest/lib/.libs/libgtest_main.a \
          $(PATH_CFDCORE)/test/googletest/googlemock/lib/.libs/libgmock.a \
          $(PATH_CFDCORE)/test/googletest/googlemock/lib/.libs/libgmock_main.a
LINK_OPTS= -fstack-protector -static -lstdc++ -lgcc -lwinpthread -lssp \
           -L$(PATH_CFDCORE)/src/hidapi_local/windows/.libs -lhidapi-0 \
           -L$(PATH_CFDCORE)/src/libwally/src/.libs -lwallycore-0 \
           -L$(PATH_CFDCORE)/src/univalue/.libs -lunivalue-0 \
           -L$(PATH_CFDCORE)/src/curl_local/lib/.libs -lcurl-4 \
           -L$(PATH_CFDCORE)/src/zlib_local -lz \
           -L$(PATH_CFDCORE)/src/.libs -lcfdcore-0 \
           -L../src/.libs -ldlc-0
test_dlc_CFLAGS_OPT= 
else
if TARGET_DARWIN
# mac option
LIB_OPTS= $(PATH_CFDCORE)/test/googletest/googletest/lib/.libs/libgtest.a \
          $(PATH_CFDCORE)/test/googletest/googletest/lib/.libs/libgtest_main.a \
          $(PATH_CFDCORE)/test/googletest/googlemock/lib/.libs/libgmock.a \
          $(PATH_CFDCORE)/test/googletest/googlemock/lib/.libs/libgmock_main.a
LINK_OPTS= -fstack-protector -static -lstdc++ -lgcc -lpthread \
           -L$(PATH_CFDCORE)/src/hidapi_local/mac/.libs -lhidapi \
           -L$(PATH_CFDCORE)/src/libwally/src/.libs -lwallycore \
           -L$(PATH_CFDCORE)/src/univalue/.libs -lunivalue \
           -L$(PATH_CFDCORE)/src/curl_local/lib/.libs -lcurl \
           -L$(PATH_CFDCORE)/src/zlib_local -lz \
           -L$(PATH_CFDCORE)/src/.libs -lcfdcore \
           -L../src/.libs -ldlc
test_dlc_CFLAGS_OPT=
else
# other(linux, etc.) option
LIB_OPTS= $(PATH_CFDCORE)/test/googletest/googletest/lib/.libs/libgtest.a \
          $(PATH_CFDCORE)/test/googletest/googletest/lib/.libs/libgtest_main.a \
          $(PATH_CFDCORE)/test/googletest/googlemock/lib/.libs/libgmock.a \
          $(PATH_CFDCORE)/test/googletest/googlemock/lib/.libs/libgmock_main.a
LINK_OPTS= -fstack-protector -static -lstdc++ -lgcc -lpthread \
           -L$(PATH_CFDCORE)/src/hidapi_local/linux/.libs -lhidapi-hidraw \
           -L$(PATH_CFDCORE)/src/hidapi_local/libusb/.libs -lhidapi-libusb \
           -L$(PATH_CFDCORE)/src/libwally/src/.libs -lwallycore \
           -L$(PATH_CFDCORE)/src/univalue/.libs -lunivalue \
           -L$(PATH_CFDCORE)/src/curl_local/lib/.libs -lcurl \
           -L$(PATH_CFDCORE)/src/zlib_local -lz \
           -L$(PATH_CFDCORE)/src/.libs -lcfdcore \
           -L../src/.libs -ldlc
test_dlc_CFLAGS_OPT=
endif
endif

# for test_dlc
test_dlc_LDFLAGS=$(LINK_OPTS)
#test_dlc_OBJECTS=$(wildcard src/*.o)
test_dlc_LDADD=$(LIB_OPTS)
#test_dlc_LIBADD=$(LIB_OPTS)
test_dlc_CFLAGS= -I../include -I../src \
    -I$(PATH_CFDCORE)/test/googletest/googlemock/include \
    -I$(PATH_CFDCORE)/test/googletest/googletest/include \
    -I$(PATH_CFDCORE)/src/include \
    -I$(PATH_CFDCORE)/include \
    -I$(PATH_CFDCORE)/src \
    -I$(PATH_CFDCORE)/src/univalue/include \
    $(test_dlc_CFLAGS_OPT)
test_dlc_CXXFLAGS= $(test_dlc_CFLAGS)
test_dlc_SOURCES= $(TEST_CFD_DLC_SOURCES) $(TEST_CFD_DLC_STATIC_SOURCES)
