#!/bin/sh

useradd -M quagga
mkdir /var/log/quagga && chown quagga:quagga /var/log/quagga
mkdir /var/run/quagga && chown quagga:quagga /var/run/quagga
apt-get update && apt-get install -qy git autoconf libtool gawk make telnet libreadline6-dev
git clone git://git.sv.gnu.org/quagga.git quagga && \
(cd quagga && ./bootstrap.sh && \
./configure --disable-doc --localstatedir=/var/run/quagga && make && make install)
ldconfig
