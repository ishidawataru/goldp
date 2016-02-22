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
	"github.com/ishidawataru/goldp/api"
	"github.com/ishidawataru/goldp/config"
	"github.com/ishidawataru/goldp/packet"
)

type LDPServer struct {
	config     *config.Config
	ReqCh      chan *api.Request
	helloCh    chan *hello
	connCh     chan *net.TCPConn
	sessions   map[string]*LDPSession
	interfaces map[int]*Interface
	p          *ipv4.PacketConn
}

type hello struct {
	from    *net.UDPAddr
	ifindex int
	id      ldp.LDPIdentifier
	msg     ldp.MessageInterface
}

func (server *LDPServer) HandleReq(req *api.Request) error {
	res := &api.Response{}
	defer func() {
		if req.ResCh != nil {
			req.ResCh <- res
		}
	}()

	switch req.Type {
	case api.SET_GLOBAL:
		global := req.Data.(config.Global)
		if global.RouterId != "" && net.ParseIP(global.RouterId).To4() == nil {
			res.Error = fmt.Errorf("invalid router id")
			return nil
		}
		server.config.Global = global

		if global.RouterId != "" {
			for _, i := range server.interfaces {
				if i.helloing {
					ch := make(chan struct{})
					i.endCh <- ch
					<-ch
					log.Debugf("end %s helloing", i.i.Name)
				}
				i.RouterId = global.RouterId
				i.HoldTime = global.HoldTime
				if err := i.Hello(); err != nil {
					return err
				}
				log.Debugf("start %s helloing", i.i.Name)
			}
			go func() {
				dst, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", global.RouterId, ldp.TCP_PORT))
				if err != nil {
					log.Fatalf("%s", err)
				}
				ln, err := net.ListenTCP("tcp4", dst)
				if err != nil {
					log.Fatalf("%s", err)
				}
				for {
					conn, err := ln.AcceptTCP()
					if err != nil {
						log.Fatalf("%s", err)
					}
					server.connCh <- conn
				}
			}()
		}

	case api.ADD_INTF:
		d := req.Data.(config.Interface)
		name := d.Name
		if intf, err := net.InterfaceByName(name); err != nil {
			return err
		} else {
			if _, y := server.interfaces[intf.Index]; y {
				res.Error = fmt.Errorf("interface %s is already configured", name)
				return nil
			}

			i := &Interface{
				i:        intf,
				p:        server.p,
				endCh:    make(chan chan struct{}),
				RouterId: server.config.Global.RouterId,
				HoldTime: server.config.Global.HoldTime,
			}
			server.interfaces[intf.Index] = i

			if i.RouterId != "" {
				if err := i.Hello(); err != nil {
					return err
				}
				log.Debugf("start %s helloing", intf.Name)
			}
		}
	}
	return nil
}

func (server *LDPServer) Serve() {

	conn, err := net.ListenPacket("udp4", fmt.Sprintf("224.0.0.2:%d", ldp.UDP_PORT))
	if err != nil {
		log.Fatalf("%s", err)
	}
	server.p = ipv4.NewPacketConn(conn)
	if err := server.p.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		log.Fatalf("%s", err)
	}
	go func() {
		for {
			buf := make([]byte, 128)
			_, cm, from, err := server.p.ReadFrom(buf)
			if err != nil {
				log.Fatalf("%s", err)
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
				server.helloCh <- &hello{
					from:    from.(*net.UDPAddr),
					ifindex: cm.IfIndex,
					id:      hdr.LDPIdentifier,
					msg:     msg,
				}
				buf = rest
			}
		}
	}()

	for {
		select {
		case req := <-server.ReqCh:
			if err := server.HandleReq(req); err != nil {
				log.Fatalf("%s", err)
			}
		case h := <-server.helloCh:
			id, _ := ldp.NewLDPIdentifier(fmt.Sprintf("%s:0", server.config.Global.RouterId))
			if h.id.Equal(id) {
				continue
			}
			if _, y := server.sessions[h.from.IP.String()]; !y {
				s, err := NewLDPSession(h, server.config.Global.RouterId, server.ReqCh)
				if err != nil {
					log.Fatalf("%s", err)
				}
				server.sessions[h.from.IP.String()] = s
			}
		case c := <-server.connCh:
			from := c.RemoteAddr().(*net.TCPAddr).IP.String()
			// If LSR1 cannot find a matching Hello adjacency, it sends a
			// Session Rejected/No Hello Error Notification message and
			// closes the TCP connection.
			if s, y := server.sessions[from]; !y {
				log.Warnf("not configured neighbor %s", from)
				c.Close()
				continue
			} else if s.Active() {
				log.Warnf("incoming connection but this session is active %s", from)
				continue
			}
			server.sessions[from].ConnCh <- c
		}
	}
}

func NewLDPServer() *LDPServer {
	return &LDPServer{
		config:     &config.Config{},
		ReqCh:      make(chan *api.Request, 8),
		helloCh:    make(chan *hello),
		connCh:     make(chan *net.TCPConn),
		sessions:   make(map[string]*LDPSession),
		interfaces: make(map[int]*Interface),
	}
}
