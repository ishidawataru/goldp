// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"

	"github.com/apex/log"
	"github.com/ishidawataru/goldp/packet"
)

type hello struct {
	from    *net.UDPAddr
	ifindex int
	id      ldp.LDPIdentifier
	msg     ldp.MessageInterface
}

type helloServer struct {
	p       *ipv4.PacketConn
	helloCh chan *hello
}

func (s *helloServer) serve() error {
	for {
		buf := make([]byte, 128)
		_, cm, from, err := s.p.ReadFrom(buf)
		if err != nil {
			return err
		}
		hdr, err := ldp.ParseHeader(buf)
		if err != nil {
			log.Warnf("%s", err)
			continue
		}
		buf = buf[ldp.HEADER_SIZE : int(hdr.Length)+ldp.HEADER_SIZE-6]
		for len(buf) > 0 {
			msg, rest, err := ldp.ParseMessage(buf)
			if err != nil {
				log.Warnf("%s", err)
				break
			}
			s.helloCh <- &hello{
				from:    from.(*net.UDPAddr),
				ifindex: cm.IfIndex,
				id:      hdr.LDPIdentifier,
				msg:     msg,
			}
			buf = rest
		}
	}
}

func (s *helloServer) stop() error {
	if s.p != nil {
		return s.p.Close()
	}
	close(s.helloCh)
	return nil
}

func newHelloServer(ch chan *hello) (*helloServer, error) {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("224.0.0.2:%d", ldp.UDP_PORT))
	if err != nil {
		return nil, err
	}
	s := &helloServer{
		helloCh: ch,
		p:       ipv4.NewPacketConn(conn),
	}
	if err := s.p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return nil, err
	}
	return s, nil
}
