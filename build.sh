#/bin/sh

if [ -z "$XSTL_PATH" ] ; then
        echo "Please specify XSTL_PATH"
else
    PWD=`pwd`
    ./autogen.sh && ./configure --prefix=${PWD}/out --enable-tests --enable-debug --enable-unicode --with-xstl=${XSTL_PATH} && make -j4 && make install
fi
