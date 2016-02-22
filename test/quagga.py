# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from base import *

class Quagga(Container):
    def __init__(self, name, host_dir, guest_dir='/root/config', image='goldp/quagga'):
        super(Quagga, self).__init__(name, image, host_dir, guest_dir)

    @classmethod
    def build_image(cls, force=False, tag='goldp/quagga', checkout='HEAD', nocache=False):
        cls.dockerfile = '''
FROM ubuntu:latest
WORKDIR /root
RUN useradd -M quagga
RUN mkdir /var/log/quagga && chown quagga:quagga /var/log/quagga
RUN mkdir /var/run/quagga && chown quagga:quagga /var/run/quagga
RUN apt-get update && apt-get install -qy git autoconf libtool gawk make telnet libreadline6-dev
RUN git clone git://git.sv.gnu.org/quagga.git quagga && \
(cd quagga && git checkout {0} && ./bootstrap.sh && \
./configure --disable-doc --localstatedir=/var/run/quagga && make && make install)
RUN ldconfig
'''.format(checkout)
        super(Quagga, cls).build_image(force, tag, nocache)
