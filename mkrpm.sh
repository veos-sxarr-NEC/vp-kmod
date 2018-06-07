#!/bin/sh
set -e

./autogen.sh
./configure --prefix=/opt/nec/ve/veos --with-release-id=`date +%Y%m%d%H%M`
make rpm
