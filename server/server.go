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
	config      config.Config
	ReqCh       chan *api.Request
	helloCh     chan *hello
	connCh      chan *net.TCPConn
	sessions    map[string]*LDPSession
	interfaces  map[int]*Interface
	p           *ipv4.PacketConn
	monitorReqs []*api.Request
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
			close(req.ResCh)
		}
	}()

	getIntf := func(d config.Interface) (*net.Interface, error) {
		if d.Name != "" {
			return net.InterfaceByName(d.Name)
		}
		if d.Index > 0 {
			return net.InterfaceByIndex(d.Index)
		}
		return nil, fmt.Errorf("specify interface name or index")
	}

	switch req.Type {
	case api.GET_GLOBAL:
		res.Data = server.config.Global
		return nil
	case api.SET_GLOBAL:
		// TODO: allow only once
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
	case api.GET_INTFS:
		res.Data = server.config.Interfaces
		return nil
	case api.GET_INTF:
		intf, err := getIntf(req.Data.(config.Interface))
		if err != nil {
			res.Error = err
			return nil
		}
		for _, c := range server.config.Interfaces {
			if c.Index == intf.Index {
				res.Data = c
				break
			}
		}
		if res.Data == nil {
			res.Error = fmt.Errorf("not found interface %s(idx %d)", intf.Name, intf.Index)
		}
	case api.ADD_INTF:
		d := req.Data.(config.Interface)
		intf, err := getIntf(d)
		if err != nil {
			res.Error = err
			return nil
		}
		if _, y := server.interfaces[intf.Index]; y {
			res.Error = fmt.Errorf("interface %s is already configured", intf.Name)
			return nil
		}

		d.Name = intf.Name
		d.Index = intf.Index
		server.config.Interfaces = append(server.config.Interfaces, d)

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
	case api.DEL_INTF:
		d := req.Data.(config.Interface)
		intf, err := getIntf(d)
		if err != nil {
			res.Error = err
			return nil
		}
		if i, y := server.interfaces[intf.Index]; !y {
			res.Error = fmt.Errorf("not found interface %s", intf.Name)
			return nil
		} else {
			i.Stop()
		}
	case api.ADD_ADDRESS:
		d := req.Data.(config.Interface)
		intf, err := getIntf(d)
		if err != nil {
			res.Error = err
			return nil
		}
		for idx, c := range server.config.Interfaces {
			if c.Index == intf.Index {
				server.config.Interfaces[idx].Addresses = append(c.Addresses, d.Addresses...)
				break
			}
		}
		// TODO: handle duplicates
		// TODO: broadcast the change
		server.Notify(req)
	case api.MON_ADDRESS:
		server.monitorReqs = append(server.monitorReqs, req)
	}

	log.Infof("cur config: %v", server.config)

	return nil
}

func (server *LDPServer) Notify(news *api.Request) {
	remainReqs := make([]*api.Request, 0, len(server.monitorReqs))
	for _, req := range server.monitorReqs {
		do := false
		switch {
		case req.Type == api.MON_ADDRESS && (news.Type == api.ADD_ADDRESS || news.Type == api.DEL_ADDRESS):
			do = true
		}
		if do {
			select {
			case <-req.EndCh:
			case req.MonCh <- news:
				remainReqs = append(remainReqs, req)
			default:
				remainReqs = append(remainReqs, req)
			}
		}
	}
	server.monitorReqs = remainReqs
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
				s, err := NewLDPSession(h, server.config, server.ReqCh)
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
			select {
			case server.sessions[from].ConnCh <- c:
			default:
				c.Close()
				log.Warnf("closed incoming connection from %s to avoid blocking", from)
			}
		}
	}
}

func NewLDPServer() *LDPServer {
	return &LDPServer{
		config:      config.Config{},
		ReqCh:       make(chan *api.Request, 8),
		helloCh:     make(chan *hello),
		connCh:      make(chan *net.TCPConn),
		sessions:    make(map[string]*LDPSession),
		interfaces:  make(map[int]*Interface),
		monitorReqs: make([]*api.Request, 0),
	}
}
