#!/bin/sh
set -e

mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
autoreconf -i --force
./configure --prefix=/opt/nec/ve/veos
make dist
cp vp-kmod-*.tar.gz $HOME/rpmbuild/SOURCES
rpmbuild -ba vp-kmod.spec --noclean
