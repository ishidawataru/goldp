#!/usr/bin/env python
#
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

from goldp import GoLDP
from base import *
from argparse import ArgumentParser
from itertools import combinations

def run(args):

    ctns = []
    for idx, name in enumerate(['g1', 'g2', 'g3', 'g4']):
        config_dir = '{0}/{1}'.format(args.dir, name)
        g = GoLDP(name, '10.10.10.{0}'.format(idx+10), config_dir)
        g.run()
        ctns.append(g)

    for idx, (i, j) in enumerate(combinations(ctns, 2)):
        for jdx, ctn in enumerate([i, j]):
            ifname = connect_ctn_to_br(ctn, 'br{0}'.format(idx))
            nw = '10.{0}.0.{1}/30'.format(idx, jdx+1)
            ctn.local('ip addr add {0} dev {1}'.format(nw, ifname))
            ctn.ospf_routes.append(nw)
            ctn.ldp_interfaces.append(ifname)

    for ctn in ctns:
        print 'start', ctn.name
        ctn.start()


def build(args):
    GoLDP.build_image(args.force, nocache=args.no_cache, from_image=args.from_image)

if __name__ == '__main__':
    parser = ArgumentParser(description='GoLDP test tool')
    parser.add_argument('-d', '--dir', default='/tmp/goldp')
    s = parser.add_subparsers()

    parser_run = s.add_parser('run', help='run')
    parser_run.set_defaults(func=run)

    parser_build = s.add_parser('build', help='prepare env')
    parser_build.add_argument('-f', '--force', action='store_true', help='build even if the container already exists')
    parser_build.add_argument('-n', '--no-cache', action='store_true')
    parser_build.add_argument('-i', '--from-image', default='golang:1.6')
    parser_build.set_defaults(func=build)

    args = parser.parse_args()
    args.func(args)
