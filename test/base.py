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

from settings import dckr
import io
import os
import shutil
import yaml
from pyroute2 import IPRoute
from itertools import chain, count
from nsenter import Namespace
from threading import Thread

flatten = lambda l: chain.from_iterable(l)

def ctn_exists(name):
    return '/{0}'.format(name) in list(flatten(n['Names'] for n in dckr.containers(all=True)))


def img_exists(name):
    return name in [ctn['RepoTags'][0].split(':')[0] for ctn in dckr.images()]


class docker_netns(object):
    def __init__(self, name):
        pid = int(dckr.inspect_container(name)['State']['Pid'])
        if pid == 0:
            raise Exception('no container named {0}'.format(name))
        self.pid = pid

    def __enter__(self):
        pid = self.pid
        if not os.path.exists('/var/run/netns'):
            os.mkdir('/var/run/netns')
        os.symlink('/proc/{0}/ns/net'.format(pid), '/var/run/netns/{0}'.format(pid))
        return str(pid)

    def __exit__(self, type, value, traceback):
        pid = self.pid
        os.unlink('/var/run/netns/{0}'.format(pid))


def connect_ctn_to_br(ctn, brname):
    with docker_netns(ctn.name) as pid:
        ip = IPRoute()
        br = ip.link_lookup(ifname=brname)
        if len(br) == 0:
            ip.link_create(ifname=brname, kind='bridge')
            br = ip.link_lookup(ifname=brname)
        br = br[0]
        ip.link('set', index=br, state='up')

        ifname = ctn.next_ifname()

        ifs = ip.link_lookup(ifname=ctn.name+ifname)
        if len(ifs) > 0:
           ip.link_remove(ifs[0])

        ip.link_create(ifname=ctn.name+ifname, kind='veth', peer=pid)
        host = ip.link_lookup(ifname=ctn.name+ifname)[0]
        ip.link('set', index=host, master=br)
        ip.link('set', index=host, state='up')
        guest = ip.link_lookup(ifname=pid)[0]
        ip.link('set', index=guest, net_ns_fd=pid)
        with Namespace(pid, 'net'):
            ip = IPRoute()
            ip.link('set', index=guest, ifname=ifname)
            ip.link('set', index=guest, state='up')
        return ifname


class Container(object):
    def __init__(self, name, image, host_dir, guest_dir):
        self.name = name
        self.image = image
        self.host_dir = host_dir
        self.guest_dir = guest_dir
        self.config_name = None
        if os.path.exists(host_dir):
            shutil.rmtree(host_dir)
        os.makedirs(host_dir)
        os.chmod(host_dir, 0777)
        self.counter = count()
        self.counter.next()

    @classmethod
    def build_image(cls, force, tag, **kwargs):
        if 'fileobj' not in kwargs:
            kwargs['fileobj'] = io.BytesIO(cls.dockerfile.encode('utf-8'))

        if force or not img_exists(tag):
            print 'build {0}...'.format(tag)
            for line in dckr.build(rm=True, decode=True, tag=tag, **kwargs):
                if 'stream' in line:
                    print line['stream'].strip()


    def next_ifname(self):
        ifname = 'eth{0}'.format(self.counter.next())
        print self.name, ifname
        return ifname


    def run(self, rm=True):

        if rm and ctn_exists(self.name):
            print 'remove container:', self.name
            dckr.remove_container(self.name, force=True)

        config = dckr.create_host_config(binds=['{0}:{1}'.format(os.path.abspath(self.host_dir), self.guest_dir)],
                                         privileged=True)
        ctn = dckr.create_container(image=self.image, command='bash', detach=True, name=self.name,
                                    stdin_open=True, volumes=[self.guest_dir], host_config=config)
        dckr.start(container=self.name)
        self.ctn_id = ctn['Id']
        return ctn

    def local(self, cmd, stream=False):
        i = dckr.exec_create(container=self.name, cmd=cmd)
        return dckr.exec_start(i['Id'], tty=True, stream=stream, socket=True)
