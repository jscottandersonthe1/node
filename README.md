### node runtime targeted to an embedded ppc MPC8378E (e300c4 core) running on a Linux 2.6.21 kernel

### To build:

Build environment:

    // Cross development tools built using example configuration for e300c3 core.
    // Used Linux headers for 2.6.32 (oldest permitted by crosstool)
    * powerpc-e300c3-linux-gnu-gcc (crosstool-NG 1.21.0) 4.8.3
    * Python 2.7.5
    * GNU Make 3.82
      Built for x86_64-redhat-linux-gnu

Build steps:
    export TOOL_PREFIX=/home/the1/x-tools/powerpc-e300c3-linux-gnu/bin/powerpc-e300c3-linux-gnu
    export LINK=$TOOL_PREFIX-g++
    export CXX=$TOOL_PREFIX-g++
    export AR=$TOOL_PREFIX-ar
    export RANLIB=$TOOL_PREFIX-ranlib
    export CC=$TOOL_PREFIX-gcc
    export LD=$TOOL_PREFIX-ld

    ./configure --without-snapshot --dest-cpu=ppc
    make -j4
    make install DESTDIR=<path/to/root>
    // Note: default action installs to ${DESTDIR}/usr/local

Refer to upstream for further information concerning node.

The deps/v8ppc directory has received a merge overlay of the files required for
working with this 32-bit core which has a HW FPU.  The source for the v8-related
files is the g4compat branch from repo https://github.com/andrewlow/v8ppc.git with
one modification to recognize the ppc603 core.
