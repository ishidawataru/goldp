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
	"github.com/ishidawataru/goldp/packet"
)

type Interface struct {
	i        *net.Interface
	p        *ipv4.PacketConn
	endCh    chan chan struct{}
	routerId string
	holdTime int
	helloing bool
}

func (i *Interface) hello() error {
	if i.helloing {
		return fmt.Errorf("already sending hellos")
	}
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

	go func() {
		i.helloing = true
		t := time.NewTicker(time.Second)
		for {
			select {
			case <-t.C:
			case ch := <-i.endCh:
				if err := i.p.LeaveGroup(i.i, dst); err != nil {
					log.Errorf("%s", err)
				}
				i.helloing = false
				close(ch)
				return
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
	}()
	return nil
}

func (i *Interface) stop() {
	ch := make(chan struct{})
	i.endCh <- ch
	<-ch
}
