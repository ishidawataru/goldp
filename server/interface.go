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
	"time"

	"golang.org/x/net/ipv4"

	"github.com/apex/log"
	"github.com/ishidawataru/goldp/config"
	"github.com/ishidawataru/goldp/packet"
	"gopkg.in/tomb.v2"
)

type Interface struct {
	t           tomb.Tomb
	s           *Server
	i           *net.Interface
	p           *ipv4.PacketConn
	routerId    string
	holdTime    int
	recvedHello *hello
	ch          chan *hello
	addresses   []string
}

func (i *Interface) addAddress(address ...string) error {
	// duplication check
	for _, a := range i.addresses {
		for _, b := range address {
			if a == b {
				return fmt.Errorf("%s duplicated", a)
			}
		}
	}
	i.addresses = append(i.addresses, address...)
	return nil
}

func (i *Interface) delAddress(address ...string) error {
	// existance check
	for _, b := range address {
		found := false
		for _, a := range i.addresses {
			if a == b {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s doesn't exist", b)
		}
	}
	n := make([]string, 0, len(i.addresses))
	for _, a := range i.addresses {
		found := false
		for _, b := range address {
			if a == b {
				found = true
				break
			}
		}
		if !found {
			n = append(n, a)
		}
	}
	i.addresses = n
	return nil
}

func (i *Interface) ToConfig() config.Interface {
	return config.Interface{
		Name:      i.i.Name,
		Index:     i.i.Index,
		Addresses: i.addresses,
	}
}

func (i *Interface) recv(h *hello) error {
	select {
	case i.ch <- h:
	default:
		return fmt.Errorf("failed to send hello to internal goroutine")
	}
	return nil
}

func (i *Interface) hello() error {
	dst, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("224.0.0.2:%d", ldp.UDP_PORT))
	if err := i.p.JoinGroup(i.i, dst); err != nil {
		return err
	}
	src, _ := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", i.routerId, ldp.UDP_PORT))
	if err := i.p.ExcludeSourceSpecificGroup(i.i, dst, src); err != nil {
		return err
	}

	id, err := ldp.NewLDPIdentifier(fmt.Sprintf("%s:0", i.routerId))
	if err != nil {
		log.Fatalf("%s", err)
	}

	i.t.Go(func() error {
		for {
			t := time.NewTimer(time.Second * time.Duration(i.holdTime))
			select {
			case <-t.C:
				if i.recvedHello != nil {
					if err := i.s.deleteSession(i.recvedHello); err != nil {
						log.Fatalf("%s", err)
					}
					i.recvedHello = nil
				}
			case h := <-i.ch:
				if i.recvedHello == nil {
					i.recvedHello = h
					err := i.s.addSession(h)
					if err != nil {
						log.Fatalf("%s", err)
					}
				}
			case <-i.t.Dying():
				log.Debug("returning recv hello goroutine")
				return nil
			}
		}
	})

	i.t.Go(func() error {
		t := time.NewTicker(time.Second)
		for {
			select {
			case <-t.C:
			case <-i.t.Dying():
				if err := i.p.LeaveGroup(i.i, dst); err != nil {
					log.Errorf("%s", err)
				}
				return nil
			}
			tlv := ldp.NewCommonHelloParamTLV(uint16(i.holdTime), false, true)
			msg := ldp.NewHelloMessage(200, tlv, nil)
			pdu := ldp.NewPDU(id, msg)
			buf, err := pdu.Serialize()
			if err != nil {
				log.Fatalf("%s", err)
			}
			cm := &ipv4.ControlMessage{
				// An LSR MUST advertise the same transport address in all Hellos that
				// advertise the same label space.  This requirement ensures that two
				// LSRs linked by multiple Hello adjacencies using the same label spaces
				// play the same connection establishment role for each adjacency.
				Src:     net.ParseIP(i.routerId),
				IfIndex: i.i.Index,
			}
			if _, err := i.p.WriteTo(buf, cm, dst); err != nil {
				log.Fatalf("%s", err)
			}
		}
	})
	return nil
}

func (i *Interface) stop() {
	i.t.Kill(nil)
	i.t.Wait()
}

func newInterface(s *Server, i *net.Interface) (*Interface, error) {
	intf := &Interface{
		s:        s,
		i:        i,
		p:        s.helloServer.p,
		routerId: s.config.Global.RouterId,
		holdTime: s.config.Global.HoldTime,
		ch:       make(chan *hello),
	}
	return intf, intf.hello()
}
