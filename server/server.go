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

	"github.com/apex/log"
	"github.com/ishidawataru/goldp/config"
	"github.com/ishidawataru/goldp/packet"
	"gopkg.in/tomb.v2"
)

type mapping struct {
	local  int
	remote map[string]int //key: LDP ID, value: label
}

type Server struct {
	t             tomb.Tomb
	m             sync.RWMutex
	config        config.Config
	helloCh       chan *hello
	helloServer   *helloServer
	monitorServer *monitorServer
	connCh        chan *net.TCPConn
	sessions      map[string]*LDPSession //key : LDP ID
	interfaces    map[int]*Interface
	tcpLn         *net.TCPListener
	nexthops      map[string]ldp.LDPIdentifier // key: nexthop, value: LDP ID
	fromToLDPID   map[string]string            // key: src IP,  value: LDP ID
	table         map[string]*mapping          // key: prefix,  value: mapping
}

func (server *Server) GetConfig() (config.Config, error) {
	if server == nil {
		return config.Config{}, fmt.Errorf("server is not started")
	}
	server.m.RLock()
	defer server.m.RUnlock()
	return server.config, nil
}

func (server *Server) AddInterface(d config.Interface) error {
	if server == nil {
		return fmt.Errorf("server is not started")
	}
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

	i, err := newInterface(server, intf)
	if err != nil {
		return err
	}
	server.interfaces[intf.Index] = i
	return i.addAddress(d.Addresses...)
}

func (server *Server) DeleteInterface(d config.Interface) error {
	if server == nil {
		return fmt.Errorf("server is not started")
	}
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
		for k, s := range server.sessions {
			if intf.Index == s.ifindex {
				// TODO consider session with multiple interface associated
				s.stop()
				delete(server.sessions, k)
			}
		}
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

func (server *Server) ListInterface() ([]config.Interface, error) {
	if server == nil {
		return nil, fmt.Errorf("server is not started")
	}
	server.m.RLock()
	defer server.m.RUnlock()

	return server.config.Interfaces, nil
}

func (server *Server) GetInterface(d config.Interface) (config.Interface, error) {
	c := config.Interface{}
	if server == nil {
		return c, fmt.Errorf("server is not started")
	}
	server.m.RLock()
	defer server.m.RUnlock()

	i, err := getIntf(d)
	if err != nil {
		return c, err
	}
	intf, ok := server.interfaces[i.Index]
	if ok {
		return intf.ToConfig(), nil
	}
	return c, fmt.Errorf("not found interface %s", i.Name)
}

func (server *Server) AddInterfaceAddress(d config.Interface) error {
	if server == nil {
		return fmt.Errorf("server is not started")
	}
	server.m.Lock()
	defer server.m.Unlock()

	intf, err := getIntf(d)
	if err != nil {
		return err
	}
	i, ok := server.interfaces[intf.Index]
	if !ok {
		return fmt.Errorf("not found interface %s", intf.Name)
	}
	return i.addAddress(d.Addresses...)
}

func (server *Server) DeleteInterfaceAddress(d config.Interface) error {
	if server == nil {
		return fmt.Errorf("server is not started")
	}
	server.m.Lock()
	defer server.m.Unlock()

	intf, err := getIntf(d)
	if err != nil {
		return err
	}
	i, ok := server.interfaces[intf.Index]
	if !ok {
		return fmt.Errorf("not found interface %s", intf.Name)
	}
	return i.delAddress(d.Addresses...)
}

func (server *Server) addSession(h *hello) error {
	server.m.Lock()
	defer server.m.Unlock()
	if _, y := server.sessions[h.id.String()]; !y {
		log.Debugf("add session %#v", h)
		s, err := newLDPSession(h, server)
		if err != nil {
			return err
		}
		server.sessions[h.id.String()] = s
		server.monitorServer.emit(EVENT_SESSION_ADD, s.ToConfig())
	}
	return nil
}

func (server *Server) deleteSession(h *hello) error {
	server.m.Lock()
	defer server.m.Unlock()
	if s, y := server.sessions[h.id.String()]; y {
		log.Debugf("delete session %#v", h)
		s.stop()
		delete(server.sessions, h.id.String())
		delete(server.fromToLDPID, h.from.IP.String())
		server.monitorServer.emit(EVENT_SESSION_DEL, s.ToConfig())
	}
	return nil
}

func (server *Server) ListSession() ([]config.Session, error) {
	if server == nil {
		return nil, fmt.Errorf("server is not started")
	}
	server.m.RLock()
	defer server.m.RUnlock()

	list := make([]config.Session, 0, len(server.sessions))
	for _, s := range server.sessions {
		list = append(list, s.ToConfig())
	}
	return list, nil
}

func (server *Server) addNexthop(id ldp.LDPIdentifier, nexthop ...string) error {
	server.m.Lock()
	defer server.m.Unlock()
	for _, n := range nexthop {
		server.nexthops[n] = id
	}
	return nil
}

func (server *Server) delNexthop(id ldp.LDPIdentifier, nexthop ...string) error {
	server.m.Lock()
	defer server.m.Unlock()
	for _, n := range nexthop {
		delete(server.nexthops, n)
	}
	return nil
}

func (server *Server) AddLocalLabelMapping(label int, fec ...string) error {
	server.m.Lock()
	defer server.m.Unlock()
	for _, prefix := range fec {
		m, ok := server.table[prefix]
		if !ok {
			m = &mapping{
				remote: make(map[string]int),
			}
		}
		m.local = label
		server.table[prefix] = m
	}
	return nil
}

func (server *Server) DeleteLocalLabelMapping(fec ...string) error {
	server.m.Lock()
	defer server.m.Unlock()
	for _, prefix := range fec {
		m, ok := server.table[prefix]
		if !ok {
			continue
		}
		m.local = 0
	}
	return nil
}

func (server *Server) GetLocalLabelMapping(fec string) (int, error) {
	server.m.Lock()
	defer server.m.Unlock()
	m, ok := server.table[fec]
	if !ok || m.local == 0 {
		return 0, fmt.Errorf("FEC: %s doesn't exist", fec)
	}
	return m.local, nil
}

func (server *Server) addRemoteLabelMapping(id ldp.LDPIdentifier, label int, fec ...string) error {
	server.m.Lock()
	defer server.m.Unlock()
	for _, prefix := range fec {
		m, ok := server.table[prefix]
		if !ok {
			m = &mapping{
				remote: make(map[string]int),
			}
		}
		m.remote[id.String()] = label
		server.table[prefix] = m
	}
	return nil
}

func (server *Server) GetRemoteLabelMapping(fec, nexthop string) (int, error) {
	server.m.Lock()
	defer server.m.Unlock()
	id, ok := server.nexthops[nexthop]
	if !ok {
		return 0, fmt.Errorf("couldn't find a LDP sesssion with nexthop %s", nexthop)
	}
	m, ok := server.table[fec]
	if !ok || m.remote[id.String()] == 0 {
		// TODO send request on demand
		return 0, fmt.Errorf("FEC: %s doesn't exist", fec)
	}
	return m.remote[id.String()], nil
}

func (server *Server) requestMapping(id ldp.LDPIdentifier, fec ...string) error {
	server.m.Lock()
	s := server.sessions[id.String()]
	if s == nil {
		return fmt.Errorf("no session with ID %s", id)
	}
	res := make(map[int][]string)
	for _, prefix := range fec {
		m, ok := server.table[prefix]
		if !ok || m.local == 0 {
			log.Warnf("no label mapped for %s", prefix)
			// TODO: assign new label
			continue
		}
		res[m.local] = append(res[m.local], prefix)
	}
	server.m.Unlock()
	for label, r := range res {
		if err := s.sendMapping(label, r...); err != nil {
			return err
		}
	}
	return nil
}

func (server *Server) MonitorSession() (*Watcher, error) {
	if server == nil {
		return nil, fmt.Errorf("server is not started")
	}
	return server.monitorServer.monitor(EVENT_SESSION)
}

func (server *Server) loop() error {
	if server == nil {
		return fmt.Errorf("server is not started")
	}
	for {
		select {
		case <-server.t.Dying():
			log.Info("server dying")
			close(server.connCh)
			return nil
		case h, ok := <-server.helloCh:
			if !ok {
				continue
			}
			id, _ := ldp.NewLDPIdentifier(fmt.Sprintf("%s:0", server.config.Global.RouterId))
			if h.id.Equal(id) {
				continue
			}
			server.m.RLock()
			server.fromToLDPID[h.from.IP.String()] = h.id.String()
			if i, y := server.interfaces[h.ifindex]; y {
				server.m.RUnlock()
				i.recv(h)
			} else {
				log.Warnf("suspicious hello: %#v", h)
				server.m.RUnlock()
			}
		case c := <-server.connCh:
			from := c.RemoteAddr().(*net.TCPAddr).IP.String()
			// If LSR1 cannot find a matching Hello adjacency, it sends a
			// Session Rejected/No Hello Error Notification message and
			// closes the TCP connection.
			server.m.RLock()
			id := server.fromToLDPID[from]
			if s, y := server.sessions[id]; !y {
				log.Warnf("not configured neighbor %s", from)
				c.Close()
				server.m.RUnlock()
				continue
			} else if s.Active() {
				log.Warnf("incoming connection but this session is active %s", from)
				server.m.RUnlock()
				continue
			}
			select {
			case server.sessions[id].ConnCh <- c:
			default:
				c.Close()
				log.Warnf("closed incoming connection from %s to avoid blocking", from)
			}
			server.m.RUnlock()
		}
	}
	return nil
}

func (server *Server) StartServer(g config.Global) (*Server, error) {
	if server == nil {
		server = New()
	}
	server.m.Lock()
	defer server.m.Unlock()

	if server.config.Global.RouterId != "" {
		return server, fmt.Errorf("server is already started")
	}

	if g.RouterId != "" && net.ParseIP(g.RouterId).To4() == nil {
		return server, fmt.Errorf("invalid router id")
	}

	dst, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", g.RouterId, ldp.TCP_PORT))
	if err != nil {
		return server, err
	}
	ln, err := net.ListenTCP("tcp4", dst)
	if err != nil {
		return server, err
	}
	server.tcpLn = ln

	server.config.Global = g
	server.helloServer = newHelloServer(server.helloCh)
	server.t.Go(server.helloServer.serve)

	server.t.Go(func() error {
		for {
			conn, err := ln.AcceptTCP()
			if err != nil {
				log.Errorf("%s", err)
				return nil
			}
			select {
			case <-server.t.Dying():
				return nil
			case server.connCh <- conn:
			}
		}
	})

	server.t.Go(server.loop)
	return server, nil
}

func (server *Server) Stop() error {
	if server == nil {
		return fmt.Errorf("server is not started")
	}
	server.m.Lock()
	defer server.m.Unlock()
	for _, i := range server.interfaces {
		i.stop()
	}
	for _, s := range server.sessions {
		s.stop()
	}
	if server.helloServer != nil {
		err := server.helloServer.stop()
		if err != nil {
			return err
		}
	}
	if server.tcpLn != nil {
		server.tcpLn.Close()
	}
	server.t.Kill(nil)
	server.t.Wait()
	return nil
}

func New() *Server {
	return &Server{
		helloCh:       make(chan *hello),
		connCh:        make(chan *net.TCPConn),
		sessions:      make(map[string]*LDPSession),
		interfaces:    make(map[int]*Interface),
		monitorServer: newMonitorServer(),
		nexthops:      make(map[string]ldp.LDPIdentifier),
		fromToLDPID:   make(map[string]string),
	}
}
