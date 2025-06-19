#!/bin/bash
# This file is meant to be included by the parent cppbuild.sh script
if [[ -z "$PLATFORM" ]]; then
    pushd ..
    bash cppbuild.sh "$@" modsecurity
    popd
    exit
fi

mkdir -p $PLATFORM
cd $PLATFORM
INSTALL_PATH=`pwd`

if [[ ! -d "ModSecurity" ]]; then
    git clone https://github.com/SpiderLabs/ModSecurity
    cd ModSecurity
    git checkout v3.0.8
    git submodule init
    git submodule update
else
    cd ModSecurity
fi

# Function to detect PCRE configuration
detect_pcre_config() {
    PCRE_CONFIG=""
    if command -v pcre-config >/dev/null 2>&1; then
        PCRE_PREFIX=$(pcre-config --prefix 2>/dev/null)
        if [ -n "$PCRE_PREFIX" ]; then
            PCRE_CONFIG="--with-pcre=$PCRE_PREFIX"
        fi
    elif command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libpcre 2>/dev/null; then
        PCRE_PREFIX=$(pkg-config --variable=prefix libpcre 2>/dev/null)
        if [ -n "$PCRE_PREFIX" ]; then
            PCRE_CONFIG="--with-pcre=$PCRE_PREFIX"
        fi
    fi
    echo "$PCRE_CONFIG"
}

case $PLATFORM in
    linux-x86_64)
        sh build.sh
        ./configure --prefix=$INSTALL_PATH
        make -j $MAKEJ
        make install-strip
        ;;
    macosx-x86_64)
        sh build.sh
        sedinplace 's/\\\$rpath/@rpath/g' configure
        PCRE_CONFIG=$(detect_pcre_config)
        ./configure --prefix=$INSTALL_PATH $PCRE_CONFIG
        make -j $MAKEJ
        make install-strip
        ;;
    macosx-arm64)
        sh build.sh
        sedinplace 's/\\\$rpath/@rpath/g' configure
        PCRE_CONFIG=$(detect_pcre_config)
        ./configure --prefix=$INSTALL_PATH $PCRE_CONFIG
        make -j $MAKEJ
        make install-strip
        ;;
    *)
        echo "Error: Platform \"$PLATFORM\" is not supported"
        ;;
esac

cd ../..
