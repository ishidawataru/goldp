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
import os
import tarfile
import yaml

class GoLDP(Container):
    def __init__(self, name, router_id, host_dir, guest_dir='/root/config', image='goldp/goldp'):
        self.router_id = router_id
        self.ospf_routes = ['{0}/32'.format(router_id)]
        self.ldp_interfaces = []
        super(GoLDP, self).__init__(name, image, host_dir, guest_dir)

    @classmethod
    def build_image(cls, force=False, tag='goldp/goldp', from_image='golang:1.7', checkout='HEAD', nocache=False):
        cls.dockerfile = '''
FROM {0}
WORKDIR /root
RUN apt-get update && apt-get install -qy quagga telnet vim tcpdump
RUN sed -i -e 's/zebra=no/zebra=yes/g' -e 's/ospfd=no/ospfd=yes/g' /etc/quagga/daemons
RUN go get -v github.com/ishidawataru/goldp/goldpd
RUN go get -v github.com/ishidawataru/goldp/goldpctl
ADD goldp $GOPATH/src/github.com/ishidawataru/goldp
RUN go get -v github.com/ishidawataru/goldp/goldpd
RUN go get -v github.com/ishidawataru/goldp/goldpctl
RUN go install github.com/ishidawataru/goldp/goldpd
RUN go install github.com/ishidawataru/goldp/goldpctl
'''.format(from_image)
        with tarfile.open('/tmp/goldp.tgz', 'w:gz') as tar:
            pwd = os.getcwd()
            idx = pwd.rindex('goldp')
            tar.add('{0}goldp'.format(pwd[:idx]), arcname='goldp', exclude=lambda s: '.git' in s )
            with open('/tmp/Dockerfile', 'w') as f:
                f.write(cls.dockerfile)
            tar.add('/tmp/Dockerfile', arcname='Dockerfile')

        with open('/tmp/goldp.tgz', 'r') as f:
            super(GoLDP, cls).build_image(force, tag, nocache=nocache,
                                          custom_context=True, encoding='gzip',
                                          fileobj=f)


    def write_zebra_config(self):
        filename = '{0}/zebra.conf'.format(self.host_dir)
        with open(filename, 'w') as f:
            config = '''hostname {0}
password zebra
debug zebra events
debug zebra fpm
debug zebra kernel
debug zebra packet
debug zebra rib
router-id {1}
interface lo
ip address {1}/32
log file /tmp/zebra.log
'''.format(self.name, self.router_id)
            f.write(config)


    def write_ospfd_config(self):
        with open('{0}/ospfd.conf'.format(self.host_dir), 'w') as f:
            config = '''hostname {0}
password zebra
router ospf
{1}
debug ospf zebra
log file /tmp/ospfd.log
'''.format(self.name, '\n'.join('network {0} area 0.0.0.0'.format(nw) for nw in self.ospf_routes))
            f.write(config)

    def write_goldpd_config(self):
        with open('{0}/ldpd.conf'.format(self.host_dir), 'w') as f:
            config = {'interfaces': [{'name': name} for name in self.ldp_interfaces]}
            f.write(yaml.dump(config))

    def start(self):
        self.write_zebra_config()
        self.write_ospfd_config()
        self.write_goldpd_config()

        startup = '''#!/bin/bash
cp {0}/zebra.conf /etc/quagga
chown quagga:quagga /etc/quagga/zebra.conf
cp {0}/ospfd.conf /etc/quagga
chown quagga:quagga /etc/quagga/ospfd.conf
service quagga start
goldpd --enable-zebra -f {0}/ldpd.conf -l debug > {0}/goldpd.log 2>&1
'''.format(self.guest_dir)
        filename = '{0}/start.sh'.format(self.host_dir)
        with open(filename, 'w') as f:
            f.write(startup)
        os.chmod(filename, 0777)
        i = dckr.exec_create(container=self.name, cmd='{0}/start.sh'.format(self.guest_dir), tty=True)
        dckr.exec_start(i['Id'], detach=True, tty=True, socket=True)
