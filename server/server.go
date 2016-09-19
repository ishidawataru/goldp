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
	"sync"

	"golang.org/x/net/ipv4"

	"github.com/apex/log"
	"github.com/ishidawataru/goldp/config"
	"github.com/ishidawataru/goldp/packet"
)

type LDPServer struct {
	config     config.Config
	helloCh    chan *hello
	connCh     chan *net.TCPConn
	sessions   map[string]*LDPSession
	interfaces map[int]*Interface
	p          *ipv4.PacketConn
	m          sync.RWMutex
}

type hello struct {
	from    *net.UDPAddr
	ifindex int
	id      ldp.LDPIdentifier
	msg     ldp.MessageInterface
}

func getIntf(d config.Interface) (*net.Interface, error) {
	if d.Name != "" {
		return net.InterfaceByName(d.Name)
	}
	if d.Index > 0 {
		return net.InterfaceByIndex(d.Index)
	}
	return nil, fmt.Errorf("specify interface name or index")
}

func (server *LDPServer) GetConfig() (config.Config, error) {
	server.m.RLock()
	defer server.m.RUnlock()
	return server.config, nil
}

func (server *LDPServer) StartServer(g config.Global) error {
	server.m.Lock()
	defer server.m.Unlock()
	if server.config.Global.RouterId != "" {
		return fmt.Errorf("server is already started")
	}

	if g.RouterId != "" && net.ParseIP(g.RouterId).To4() == nil {
		return fmt.Errorf("invalid router id")
	}
	server.config.Global = g

	for _, i := range server.interfaces {
		if i.helloing {
			log.Debugf("end %s helloing", i.i.Name)
			i.stop()
		}
		i.RouterId = g.RouterId
		i.HoldTime = g.HoldTime
		if err := i.hello(); err != nil {
			return err
		}
		log.Debugf("start %s helloing", i.i.Name)
	}
	go func() {
		dst, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", g.RouterId, ldp.TCP_PORT))
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
	return nil
}

func (server *LDPServer) StopServer() error {
	return fmt.Errorf("not implemented yet")
}

func (server *LDPServer) AddInterface(d config.Interface) error {
	server.m.Lock()
	defer server.m.Unlock()
	intf, err := getIntf(d)
	if err != nil {
		return err
	}
	if _, y := server.interfaces[intf.Index]; y {
		return fmt.Errorf("interface %s is already configured", intf.Name)
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

	if server.config.Global.RouterId != "" {
		if err := i.hello(); err != nil {
			return err
		}
		log.Debugf("start %s helloing", intf.Name)
	} else {
		log.Debugf("delayed helloing, server is not started")
	}

	return nil
}

func (server *LDPServer) DeleteInterface(d config.Interface) error {
	server.m.Lock()
	defer server.m.Unlock()

	intf, err := getIntf(d)
	if err != nil {
		return err
	}
	if i, y := server.interfaces[intf.Index]; !y {
		return fmt.Errorf("not found interface %s", intf.Name)
	} else {
		i.stop()
		delete(server.interfaces, intf.Index)
		intfs := make([]config.Interface, 0, len(server.config.Interfaces))
		for _, c := range server.config.Interfaces {
			if c.Name == i.i.Name {
				continue
			}
			intfs = append(intfs, c)
		}
		server.config.Interfaces = intfs
	}
	return nil
}

func (server *LDPServer) ListInterface() ([]config.Interface, error) {
	server.m.RLock()
	defer server.m.RUnlock()

	return server.config.Interfaces, nil
}

func (server *LDPServer) GetInterface(d config.Interface) (*Interface, error) {
	server.m.RLock()
	defer server.m.RUnlock()

	i, err := getIntf(d)
	if err != nil {
		return nil, err
	}
	intf, ok := server.interfaces[i.Index]
	if ok {
		return intf, nil
	}
	return nil, fmt.Errorf("not found interface %s", i.Name)
}

func (server *LDPServer) AddInterfaceAddress(d config.Interface) error {
	server.m.Lock()
	defer server.m.Unlock()

	intf, err := getIntf(d)
	if err != nil {
		return err
	}
	for idx, c := range server.config.Interfaces {
		if c.Index == intf.Index {
			server.config.Interfaces[idx].Addresses = append(c.Addresses, d.Addresses...)
			break
		}
	}
	// TODO: handle duplicates
	// TODO: broadcast the change
	//	server.Notify(req)
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
		case h := <-server.helloCh:
			id, _ := ldp.NewLDPIdentifier(fmt.Sprintf("%s:0", server.config.Global.RouterId))
			if h.id.Equal(id) {
				continue
			}
			server.m.Lock()
			if _, y := server.sessions[h.from.IP.String()]; !y {
				s, err := newLDPSession(h, server.config)
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
			server.m.Lock()
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
		server.m.Unlock()
	}
}

func NewLDPServer() *LDPServer {
	return &LDPServer{
		config:     config.Config{},
		helloCh:    make(chan *hello),
		connCh:     make(chan *net.TCPConn),
		sessions:   make(map[string]*LDPSession),
		interfaces: make(map[int]*Interface),
	}
}
